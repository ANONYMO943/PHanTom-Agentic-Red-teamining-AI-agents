import subprocess
import json
import sys
import os

def run_bandit(target_path: str) -> dict:
    """Run bandit Python security linter. Falls back gracefully if not installed."""
    bandit_cmd = os.path.join(os.path.dirname(sys.executable), "bandit")
    if os.name == "nt":
        bandit_cmd += ".exe"
    try:
        result = subprocess.run(
            [bandit_cmd, "-r", target_path, "-f", "json", "-q"],
            capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace"
        )
        try:
            raw = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"findings": [], "high_severity": [], "error": result.stderr, "total": 0}
        findings = []
        for issue in raw.get("results", []):
            findings.append({
                "file":       issue["filename"],
                "line":       issue["line_number"],
                "test_id":    issue["test_id"],
                "test_name":  issue["test_name"],
                "severity":   issue["issue_severity"],
                "confidence": issue["issue_confidence"],
                "code":       issue["code"]
            })
        return {
            "findings":      findings,
            "high_severity": [f for f in findings if f["severity"] == "HIGH"],
            "total":         len(findings)
        }
    except FileNotFoundError:
        print("[EXPLOIT ENGINE] bandit not installed — using basic code scanner fallback")
        return _basic_code_scan(target_path)
    except Exception as e:
        print(f"[EXPLOIT ENGINE] bandit error: {e}")
        return {"findings": [], "high_severity": [], "total": 0}


def _basic_code_scan(target_path: str) -> dict:
    """Fallback code scanner when bandit is unavailable."""
    import os, glob as glib
    PATTERNS = [
        ("render_template_string", "JINJA2_SSTI", "HIGH",        "Potential SSTI via render_template_string"),
        ("debug=True",             "FLASK_DEBUG",  "HIGH",        "Flask debug mode enabled"),
        ("secret_key",             "HARDCODED_SECRET", "HIGH",    "Hardcoded secret key"),
        ("execute(",               "SQL_INJECTION", "MEDIUM",     "Possible SQL injection"),
        ("eval(",                  "CODE_INJECTION","HIGH",       "Use of eval()"),
        ("os.system(",             "OS_COMMAND",    "HIGH",       "Use of os.system()"),
        ("subprocess.call(",       "OS_COMMAND",    "MEDIUM",     "Use of subprocess"),
        ("pickle.loads(",          "PICKLE",        "HIGH",       "Unsafe pickle deserialization"),
    ]
    findings = []
    py_files = glib.glob(f"{target_path}/**/*.py", recursive=True) + \
               glib.glob(f"{target_path}/*.py")
    for fpath in py_files:
        try:
            lines = open(fpath, encoding="utf-8", errors="ignore").readlines()
            for i, line in enumerate(lines, 1):
                for pattern, test_name, severity, message in PATTERNS:
                    if pattern.lower() in line.lower():
                        findings.append({
                            "file":       fpath,
                            "line":       i,
                            "test_id":    test_name,
                            "test_name":  message,
                            "severity":   severity,
                            "confidence": "MEDIUM",
                            "code":       line.strip()
                        })
        except Exception:
            pass
    return {
        "findings":      findings,
        "high_severity": [f for f in findings if f["severity"] == "HIGH"],
        "total":         len(findings)
    }
