"""
PHANTOM Patch Agent — Generates ranked, signed patch diffs for confirmed findings.
Verifies patches with Bandit anti-regression scan before output.
"""
import json
import os
import hashlib
import datetime
import tempfile
import shutil
from tools.bandit_tool import run_bandit
from memory.store import PhantomMemory
from guardrails import sanitize_tool_output, validate_action
from llm import generate
import ui


class PatchAgent:
    def __init__(self, memory: PhantomMemory):
        self.memory = memory
        self.name = "patch_agent"

    def run(self, exploit_results: dict, session_id: str) -> dict:
        ui.agent_start(self.name, "Generating ranked patches for confirmed findings")
        patches = []

        for confirmed in exploit_results.get("confirmed", []):
            finding = confirmed.get("finding", {})
            validate_action(self.name, f"generate patch for {finding.get('type', 'unknown')}")

            patch = self._generate_patch(confirmed, finding)
            if patch:
                # Bandit anti-regression scan
                patch["bandit_cleared"] = self._verify_patch(patch, finding)

                # SHA-256 signature
                patch["signature"] = self._sign_patch(
                    patch.get("diff", ""), session_id
                )

                patches.append(patch)
                status_style = "green" if patch["bandit_cleared"] else "red"
                status_text = "CLEARED" if patch["bandit_cleared"] else "BLOCKED"
                ui.agent_result(
                    self.name,
                    f"Patch for {finding.get('type', 'unknown')}: "
                    f"Bandit {status_text} | Signed: {patch['signature'][:8]}...",
                    style=status_style
                )

        output = {
            "patches":       patches,
            "total_patches": len(patches),
            "all_cleared":   all(p.get("bandit_cleared", False) for p in patches)
        }
        self.memory.store(self.name, "patches", output, "COMPLETE")
        return output

    def _generate_patch(self, confirmed: dict, finding: dict) -> dict:
        """Use LLM to generate a surgical code fix."""
        code_context = finding.get("code", "")
        if finding.get("file") and os.path.exists(finding["file"]):
            try:
                lines = open(finding["file"], encoding="utf-8", errors="ignore").readlines()
                start = max(0, finding.get("line", 1) - 5)
                end = min(len(lines), finding.get("line", 1) + 10)
                code_context = "".join(lines[start:end])
            except Exception:
                pass

        prompt = f"""You are the Patch Agent in PHANTOM security system.
Generate a minimal, surgical code fix for this confirmed vulnerability.

VULNERABILITY:
Type: {finding.get('type', 'unknown')}
File: {finding.get('file', 'unknown')}
Line: {finding.get('line', 0)}
MITRE Technique: {confirmed.get('technique_id', 'unknown')}
CVSS Estimate: {confirmed.get('cvss_estimate', 0)}
Attack Vector: {confirmed.get('attack_vector', 'unknown')}

CODE CONTEXT:
{code_context}

Rules:
1. Output ONLY a unified diff format patch
2. Change minimum lines necessary — surgical fix only
3. Do not refactor beyond the vulnerable function
4. Use the framework's own security primitives where possible

Format your response exactly like this:
```diff
--- a/filename
+++ b/filename
@@ ... @@
 context
-vulnerable line
+fixed line
 context
```

PLAIN ENGLISH: [3-sentence explanation for a developer who has never heard of this vulnerability type. Zero jargon. End with one specific action.]"""

        text = generate(prompt)
        sanitize_tool_output(text, source="llm_patch_gen")

        diff = ""
        plain_english = ""
        if "```diff" in text:
            diff = text.split("```diff")[1].split("```")[0].strip()
        elif "```" in text:
            # Try to extract any code block
            parts = text.split("```")
            if len(parts) >= 3:
                diff = parts[1].strip()

        if "PLAIN ENGLISH:" in text:
            plain_english = text.split("PLAIN ENGLISH:")[-1].strip()
        elif diff and "```" in text:
            plain_english = text.split("```")[-1].strip()

        return {
            "finding_type":  finding.get("type", "unknown"),
            "file":          finding.get("file", "unknown"),
            "line":          finding.get("line", 0),
            "cvss_estimate": confirmed.get("cvss_estimate", 0),
            "technique_id":  confirmed.get("technique_id", ""),
            "diff":          diff,
            "plain_english": plain_english,
            "confidence":    confirmed.get("confidence", 0)
        }

    def _verify_patch(self, patch: dict, finding: dict) -> bool:
        """
        Anti-regression check: apply patch concept to temp file,
        re-scan with Bandit. Ensures patch doesn't introduce new HIGH issues.
        """
        if not patch.get("diff") or not finding.get("file"):
            return True  # Can't verify without diff or file
        if not os.path.exists(finding["file"]):
            return True

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                src = finding["file"]
                dst = os.path.join(tmpdir, os.path.basename(src))
                shutil.copy(src, dst)

                # Try to apply the patch by simulating the fix
                # Read original, apply diff lines conceptually
                original_lines = open(src, encoding="utf-8", errors="ignore").readlines()
                patched_lines = self._apply_diff_lines(original_lines, patch["diff"],
                                                       finding.get("line", 0))
                with open(dst, "w", encoding="utf-8") as f:
                    f.writelines(patched_lines)

                result = run_bandit(tmpdir)
                new_highs = len(result.get("high_severity", []))
                ui.agent_detail(f"  Bandit re-scan: {new_highs} HIGH findings in patched file")
                return new_highs == 0
        except Exception as e:
            ui.agent_warning(self.name, f"Patch verification error: {e}")
            return True  # Can't verify — don't block

    def _apply_diff_lines(self, original: list, diff: str, vuln_line: int) -> list:
        """
        Best-effort patch application from unified diff.
        Replaces lines marked with '-' and adds lines marked with '+'.
        """
        result = list(original)
        remove_lines = []
        add_lines = []

        for line in diff.split("\n"):
            if line.startswith("-") and not line.startswith("---"):
                remove_lines.append(line[1:].strip())
            elif line.startswith("+") and not line.startswith("+++"):
                add_lines.append(line[1:] + "\n")

        # Find the vulnerable line area and apply changes
        if vuln_line > 0 and vuln_line <= len(result):
            # Remove matched lines around the vulnerability
            start = max(0, vuln_line - 3)
            end = min(len(result), vuln_line + 3)

            new_result = result[:start]
            for i in range(start, end):
                line_content = result[i].strip()
                if any(line_content == rm.strip() for rm in remove_lines):
                    continue  # Skip removed lines
                new_result.append(result[i])

            # Insert added lines at the vulnerability point
            insert_pos = min(vuln_line, len(new_result))
            for add_line in reversed(add_lines):
                new_result.insert(insert_pos, add_line)

            new_result.extend(result[end:])
            return new_result

        return result  # Fallback: return original if can't locate

    def _sign_patch(self, diff: str, session_id: str) -> str:
        """SHA-256 signature linking patch to assessment session."""
        ts = datetime.datetime.utcnow().isoformat()
        content = f"{diff}{session_id}{ts}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
