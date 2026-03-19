import subprocess
import json
import sys
import os

def run_semgrep(target_path: str, rules: str = "p/python") -> dict:
    """Run semgrep if available, else return empty findings."""
    semgrep_cmd = os.path.join(os.path.dirname(sys.executable), "semgrep")
    if os.name == "nt":
        semgrep_cmd += ".exe"
    try:
        result = subprocess.run(
            [semgrep_cmd, "--config", rules, "--json", target_path],
            capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace"
        )
        try:
            raw = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"findings": [], "error": result.stderr, "total": 0}
        findings = []
        for r in raw.get("results", []):
            findings.append({
                "file":     r["path"],
                "line":     r["start"]["line"],
                "rule_id":  r["check_id"],
                "severity": r["extra"].get("severity", "INFO"),
                "message":  r["extra"].get("message", ""),
                "code":     r["extra"].get("lines", "")
            })
        return {"findings": findings, "total": len(findings)}
    except FileNotFoundError:
        print("[EXPLOIT ENGINE] semgrep not installed — skipping semgrep scan")
        return {"findings": [], "total": 0, "note": "semgrep not installed"}
    except Exception as e:
        print(f"[EXPLOIT ENGINE] semgrep error: {e}")
        return {"findings": [], "total": 0, "error": str(e)}
