"""
PHANTOM Recon Agent — Surface mapping.
Phase 1: Passive (Shodan) → Phase 2: Active (nmap) → Phase 3: Codebase scan.
"""
import os
import re
import glob as glib
from tools.nmap_tool import run_nmap
from tools.shodan_tool import query_shodan
from memory.store import PhantomMemory
from guardrails import sanitize_tool_output, validate_action
import ui


class ReconAgent:
    def __init__(self, memory: PhantomMemory):
        self.memory = memory
        self.name = "recon"

    def run(self, target: str, target_path: str = None) -> dict:
        ui.agent_start(self.name, f"Starting surface mapping on {target}")
        validate_action(self.name, f"scan target {target}")

        # Phase 1 — Passive (Shodan)
        ui.agent_detail("Phase 1: Passive intelligence (Shodan)...")
        shodan_data = query_shodan(target)
        if shodan_data.get("error"):
            ui.agent_warning(self.name, f"Shodan: {shodan_data['error']}")
        else:
            ports = shodan_data.get("open_ports", [])
            org = shodan_data.get("org", "unknown")
            ui.agent_result(self.name, f"Shodan: {org} — {len(ports)} known ports")

        # Phase 2 — Active (nmap)
        ui.agent_detail("Phase 2: Active scanning (nmap)...")
        nmap_data = run_nmap(target)
        sanitize_tool_output(str(nmap_data), source="nmap")
        open_ports = nmap_data.get("open_ports", [])
        scanner = nmap_data.get("scanner", "nmap")
        ui.agent_result(self.name,
                        f"Scanner ({scanner}): {len(open_ports)} open ports found")
        for p in open_ports:
            ver = f" {p['version']}" if p.get("version") else ""
            ui.agent_detail(f"  :{p['port']} -> {p['service']}{ver}")

        # Phase 3 — Codebase scan
        code_surface = {}
        if target_path and os.path.exists(target_path):
            ui.agent_detail("Phase 3: Codebase surface scan...")
            code_surface = self._scan_codebase(target_path)
            ui.agent_result(
                self.name,
                f"Codebase: {code_surface.get('file_count', 0)} files, "
                f"{len(code_surface.get('entry_points', []))} routes"
            )
            if code_surface.get("has_debug"):
                ui.agent_warning(self.name, "DEBUG mode is ENABLED")
            if code_surface.get("has_dotenv"):
                ui.agent_warning(self.name, ".env file found in repository root")

        # Build attack surface model
        attack_surface = {
            "target":          target,
            "target_path":     target_path,
            "network_surface": nmap_data,
            "passive_intel":   shodan_data,
            "code_surface":    code_surface,
        }

        self.memory.store(self.name, "attack_surface", attack_surface, "COMPLETE")
        ui.guardrail_ok("Recon output sanitized")
        return attack_surface

    def _scan_codebase(self, path: str) -> dict:
        """Scan codebase structure — no exploit tools, just mapping."""
        py_files = glib.glob(f"{path}/**/*.py", recursive=True)
        if not py_files:
            py_files = glib.glob(f"{path}/*.py")

        has_requirements = os.path.exists(os.path.join(path, "requirements.txt"))
        has_env = os.path.exists(os.path.join(path, ".env"))
        has_debug = False
        entry_points = []
        config_issues = []

        for fpath in py_files:
            try:
                content = open(fpath, encoding="utf-8", errors="ignore").read()
                if re.search(r"debug\s*=\s*True", content, re.IGNORECASE):
                    has_debug = True
                    config_issues.append({"file": fpath, "issue": "DEBUG mode enabled"})
                if "@app.route" in content:
                    routes = re.findall(r'@app\.route\(["\']([^"\']+)["\']', content)
                    for r in routes:
                        entry_points.append({"route": r, "file": fpath})
                if re.search(r'secret_key\s*=\s*["\'][^"\']+["\']', content, re.IGNORECASE):
                    config_issues.append({"file": fpath, "issue": "Hardcoded secret key"})
            except Exception:
                pass

        deps = []
        if has_requirements:
            try:
                deps = [line.strip() for line in
                        open(os.path.join(path, "requirements.txt")).readlines()
                        if line.strip() and not line.startswith("#")]
            except Exception:
                pass

        return {
            "python_files":  py_files,
            "entry_points":  entry_points,
            "dependencies":  deps,
            "has_debug":     has_debug,
            "has_dotenv":    has_env,
            "config_issues": config_issues,
            "file_count":    len(py_files)
        }
