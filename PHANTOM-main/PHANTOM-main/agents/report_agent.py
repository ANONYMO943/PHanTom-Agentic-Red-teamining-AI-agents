"""
PHANTOM Report Agent — Generates 3-layer structured report.
Layer 1: Executive Summary (for managers)
Layer 2: Technical Findings (for developers)
Layer 3: Audit Trail (for ISO auditors) — SHA-256 hash-chained
"""
import json
import os
import datetime
import hashlib
from memory.store import PhantomMemory
from guardrails import sanitize_tool_output
from llm import generate
import ui


class ReportAgent:
    def __init__(self, memory: PhantomMemory):
        self.memory = memory
        self.name = "report_agent"

    def run(self, all_results: dict, session_id: str) -> dict:
        ui.agent_start(self.name, "Generating structured assessment report")

        # Layer 1 — Executive summary via LLM
        ui.agent_detail("Layer 1: Executive summary (non-technical)...")
        exec_summary = self._generate_executive_summary(all_results)

        # Layer 2 — Technical findings
        ui.agent_detail("Layer 2: Technical findings with patches...")
        tech_findings = self._format_technical_findings(all_results)

        # Layer 3 — Hash-chained audit trail
        ui.agent_detail("Layer 3: SHA-256 chained audit trail...")
        audit_trail = self._build_audit_trail(session_id, all_results)

        report = {
            "session_id":         session_id,
            "timestamp":          datetime.datetime.utcnow().isoformat(),
            "target":             all_results.get("recon", {}).get("target", "unknown"),
            "duration_seconds":   all_results.get("duration", 0),
            "executive_summary":  exec_summary,
            "technical_findings": tech_findings,
            "audit_trail":        audit_trail,
            "stats": {
                "confirmed_findings":   len(all_results.get("exploit", {}).get("confirmed", [])),
                "unconfirmed_findings": len(all_results.get("exploit", {}).get("unconfirmed", [])),
                "patches_generated":    len(all_results.get("patches", {}).get("patches", [])),
                "patches_cleared":      sum(
                    1 for p in all_results.get("patches", {}).get("patches", [])
                    if p.get("bandit_cleared")
                )
            }
        }

        self.memory.store(self.name, "final_report", report, "COMPLETE")
        ui.agent_result(
            self.name,
            f"Report complete: {report['stats']['confirmed_findings']} confirmed, "
            f"{report['stats']['patches_generated']} patches, "
            f"{len(audit_trail)} audit entries"
        )
        return report

    def _generate_executive_summary(self, results: dict) -> str:
        """Generate non-technical executive summary via LLM."""
        confirmed = results.get("exploit", {}).get("confirmed", [])
        patches = results.get("patches", {}).get("patches", [])
        highest_cvss = max((c.get("cvss_estimate", 0) for c in confirmed), default=0)
        severity = ("CRITICAL" if highest_cvss >= 9 else
                    "HIGH" if highest_cvss >= 7 else
                    "MEDIUM" if highest_cvss >= 4 else "LOW")

        # Collect finding types for richer summary
        finding_types = [c.get("finding", {}).get("type", "unknown") for c in confirmed]

        prompt = f"""Write a 4-sentence executive summary for a security assessment report.

Assessment Results:
- Confirmed vulnerabilities: {len(confirmed)}
- Types found: {', '.join(finding_types) if finding_types else 'None'}
- Highest CVSS score: {highest_cvss} ({severity})
- Patches generated: {len(patches)}
- Patches cleared by static analysis: {sum(1 for p in patches if p.get('bandit_cleared'))}
- Top finding detail: {confirmed[0].get('reasoning', 'see technical section')[:200] if confirmed else 'No confirmed vulnerabilities'}

Rules:
- Write for a non-technical manager or CISO
- No jargon — no CVE IDs, no technique names
- Be direct about risk level and business impact
- End with exactly one clear, specific action item
- Maximum 4 sentences"""

        text = generate(prompt)
        sanitize_tool_output(text, source="llm_exec_summary")
        return text.strip()

    def _format_technical_findings(self, results: dict) -> list:
        """Format all findings with patches for developer consumption."""
        findings = []

        for i, confirmed in enumerate(results.get("exploit", {}).get("confirmed", []), 1):
            finding = confirmed.get("finding", {})

            # Match patch by file path
            patch = next(
                (p for p in results.get("patches", {}).get("patches", [])
                 if p.get("file") == finding.get("file")),
                None
            )

            findings.append({
                "id":            f"FINDING-{i:03d}",
                "type":          finding.get("type", "unknown"),
                "file":          finding.get("file", "unknown"),
                "line":          finding.get("line", 0),
                "cvss":          confirmed.get("cvss_estimate", 0),
                "technique_id":  confirmed.get("technique_id", ""),
                "confidence":    confirmed.get("confidence", 0),
                "reasoning":     confirmed.get("reasoning", ""),
                "attack_vector": confirmed.get("attack_vector", ""),
                "patch":         patch,
                "status":        "CONFIRMED"
            })

        for i, unconfirmed in enumerate(
                results.get("exploit", {}).get("unconfirmed", []), 1):
            finding = unconfirmed.get("finding", {})
            findings.append({
                "id":         f"UNCONFIRMED-{i:03d}",
                "type":       finding.get("type", "unknown"),
                "file":       finding.get("file", "unknown"),
                "line":       finding.get("line", 0),
                "reasoning":  unconfirmed.get("reasoning", ""),
                "confidence": unconfirmed.get("confidence", 0),
                "status":     "UNCONFIRMED",
                "attempts":   len(unconfirmed.get("attempts", [])),
                "blocker":    unconfirmed.get("pivot_suggestion",
                              unconfirmed.get("pivot_applied", "Confidence below threshold"))
            })

        return findings

    def _build_audit_trail(self, session_id: str, results: dict) -> list:
        """
        Build SHA-256 hash-chained audit trail.
        Each entry's hash includes the previous hash — tamper-evident chain.
        """
        trail = []
        prev_hash = "genesis"

        events = [
            ("SESSION_START",     "orchestrator",   {
                "target": results.get("recon", {}).get("target", "unknown")
            }),
            ("RECON_COMPLETE",    "recon",          {
                "ports": len(results.get("recon", {})
                             .get("network_surface", {})
                             .get("open_ports", [])),
                "scanner": results.get("recon", {})
                               .get("network_surface", {})
                               .get("scanner", "unknown")
            }),
            ("THREAT_MODEL",      "threat_model",   {
                "attack_paths": results.get("threat_model", {})
                                    .get("total_attack_paths", 0),
                "highest_technique": results.get("threat_model", {})
                                        .get("highest_risk", {})
                                        .get("technique_id", "none")
            }),
            ("EXPLOIT_COMPLETE",  "exploit_engine", {
                "confirmed": len(results.get("exploit", {}).get("confirmed", [])),
                "unconfirmed": len(results.get("exploit", {}).get("unconfirmed", []))
            }),
            ("PATCHES_GENERATED", "patch_agent",    {
                "count": len(results.get("patches", {}).get("patches", [])),
                "all_cleared": results.get("patches", {}).get("all_cleared", False)
            }),
            ("REPORT_GENERATED",  "report_agent",   {
                "session": session_id
            }),
        ]

        for event_type, agent, data in events:
            ts = datetime.datetime.utcnow().isoformat()
            content = f"{event_type}{agent}{json.dumps(data, sort_keys=True)}{prev_hash}{ts}"
            entry_hash = hashlib.sha256(content.encode()).hexdigest()[:12]

            trail.append({
                "timestamp": ts,
                "event":     event_type,
                "agent":     agent,
                "data":      data,
                "hash":      entry_hash,
                "prev_hash": prev_hash
            })
            prev_hash = entry_hash

        return trail
