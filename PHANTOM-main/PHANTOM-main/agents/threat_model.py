"""
PHANTOM Threat Model Agent — Maps attack surface to MITRE ATT&CK,
STRIDE categories, and CVSS context.
"""
from tools.mitre_tool import map_to_attack, KILL_CHAIN
from tools.nvd_tool import search_cves_by_keyword
from memory.store import PhantomMemory
from guardrails import sanitize_tool_output
import ui


class ThreatModelAgent:
    def __init__(self, memory: PhantomMemory):
        self.memory = memory
        self.name = "threat_model"

    def run(self, attack_surface: dict) -> dict:
        ui.agent_start(self.name, "Classifying attack surface via MITRE ATT&CK + STRIDE")

        findings = []

        # Map open ports to ATT&CK techniques
        for port_info in attack_surface.get("network_surface", {}).get("open_ports", []):
            service = port_info.get("service", "unknown")
            attack_mapping = map_to_attack(service)

            finding = {
                "source":         "network",
                "service":        service,
                "port":           port_info["port"],
                "version":        port_info.get("version", ""),
                "attack_tactic":  attack_mapping["tactic"],
                "technique_id":   attack_mapping["technique_id"],
                "technique_name": attack_mapping["technique_name"],
                "stride":         attack_mapping["stride"],
                "kill_chain_pos": attack_mapping.get("kill_chain_pos",
                                                     self._kill_chain_depth(attack_mapping["tactic"])),
                "priority":       self._calc_priority(port_info, attack_mapping)
            }

            # Check NVD for known CVEs
            if port_info.get("product") or service != "unknown":
                keyword = f"{port_info.get('product', service)} {port_info.get('version', '')}".strip()
                known_cves = search_cves_by_keyword(keyword)
                sanitize_tool_output(str(known_cves), source="nvd_api")
                finding["known_cves"] = known_cves[:3]

            findings.append(finding)
            ui.agent_result(
                self.name,
                f"{service}:{port_info['port']} -> {attack_mapping['technique_id']} "
                f"({attack_mapping['tactic']})",
                style="cyan"
            )

        # Map code surface issues
        code_surface = attack_surface.get("code_surface", {})
        if code_surface.get("has_debug"):
            debug_mapping = map_to_attack("debug_enabled")
            findings.append({
                "source":         "code",
                "type":           "DEBUG_ENABLED",
                "service":        "flask",
                "port":           0,
                "attack_tactic":  debug_mapping["tactic"],
                "technique_id":   debug_mapping["technique_id"],
                "technique_name": debug_mapping["technique_name"],
                "stride":         debug_mapping["stride"],
                "priority":       2,
                "kill_chain_pos": debug_mapping.get("kill_chain_pos", 2)
            })
            ui.agent_warning(self.name, "DEBUG mode -> T1082 (System Information Discovery)")

        for issue in code_surface.get("config_issues", []):
            if "secret" in issue.get("issue", "").lower():
                secret_mapping = map_to_attack("hardcoded_secret")
                findings.append({
                    "source":         "code",
                    "type":           "HARDCODED_SECRET",
                    "service":        "config",
                    "port":           0,
                    "file":           issue.get("file", ""),
                    "attack_tactic":  secret_mapping["tactic"],
                    "technique_id":   secret_mapping["technique_id"],
                    "technique_name": secret_mapping["technique_name"],
                    "stride":         secret_mapping["stride"],
                    "priority":       2,
                    "kill_chain_pos": secret_mapping.get("kill_chain_pos", 8)
                })
                ui.agent_warning(self.name,
                                 f"Hardcoded secret -> {secret_mapping['technique_id']} "
                                 f"({secret_mapping['tactic']})")

        # Sort by priority
        findings.sort(key=lambda x: x.get("priority", 99))

        threat_model = {
            "findings":           findings,
            "highest_risk":       findings[0] if findings else None,
            "total_attack_paths": len(findings)
        }

        self.memory.store(self.name, "threat_model", threat_model, "COMPLETE")
        ui.agent_result(self.name,
                        f"Identified {len(findings)} attack paths, "
                        f"highest priority: {findings[0]['technique_id'] if findings else 'none'}")
        return threat_model

    def _kill_chain_depth(self, tactic: str) -> int:
        try:
            return KILL_CHAIN.index(tactic) + 1
        except ValueError:
            return 7

    def _calc_priority(self, port_info: dict, attack_mapping: dict) -> int:
        score = 5
        if port_info.get("port") in [80, 443, 8080, 8443, 5000, 3000]:
            score -= 2
        if port_info.get("port") in [5432, 3306, 27017, 6379]:
            score -= 1
        depth = attack_mapping.get("kill_chain_pos",
                                   self._kill_chain_depth(attack_mapping["tactic"]))
        if depth <= 4:
            score -= 1
        return max(1, score)
