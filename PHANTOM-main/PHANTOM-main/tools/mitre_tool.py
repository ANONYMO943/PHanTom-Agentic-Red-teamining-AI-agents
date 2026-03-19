"""
MITRE ATT&CK mapping tool — maps services and vulnerability patterns
to ATT&CK Techniques, Tactics, and STRIDE threat categories.

Uses a curated subset of the MITRE ATT&CK Enterprise matrix (STIX format).
Full dataset: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
"""

# ── ATT&CK Technique Map ───────────────────────────────────────────────
# service_or_pattern → (tactic, technique_id, technique_name)
# Curated from MITRE ATT&CK Enterprise v14

TECHNIQUE_MAP = {
    # ── Initial Access ──
    "postgresql":           ("Initial Access",       "T1190",      "Exploit Public-Facing Application"),
    "mysql":                ("Initial Access",       "T1190",      "Exploit Public-Facing Application"),
    "mongodb":              ("Initial Access",       "T1190",      "Exploit Public-Facing Application"),
    "redis":                ("Initial Access",       "T1190",      "Exploit Public-Facing Application"),
    "http":                 ("Initial Access",       "T1190",      "Exploit Public-Facing Application"),
    "https":                ("Initial Access",       "T1190",      "Exploit Public-Facing Application"),
    "http-alt":             ("Initial Access",       "T1190",      "Exploit Public-Facing Application"),
    "https-alt":            ("Initial Access",       "T1190",      "Exploit Public-Facing Application"),
    "phishing":             ("Initial Access",       "T1566",      "Phishing"),
    "default_credentials":  ("Initial Access",       "T1078",      "Valid Accounts"),
    "exposed_api":          ("Initial Access",       "T1190",      "Exploit Public-Facing Application"),

    # ── Execution ──
    "ssti":                 ("Execution",            "T1059.006",  "Command and Scripting Interpreter: Python"),
    "sqli":                 ("Execution",            "T1059",      "Command and Scripting Interpreter"),
    "sql_injection":        ("Execution",            "T1059",      "Command and Scripting Interpreter"),
    "rce":                  ("Execution",            "T1203",      "Exploitation for Client Execution"),
    "command_injection":    ("Execution",            "T1059",      "Command and Scripting Interpreter"),
    "os_command":           ("Execution",            "T1059",      "Command and Scripting Interpreter"),
    "code_injection":       ("Execution",            "T1059.006",  "Command and Scripting Interpreter: Python"),
    "eval":                 ("Execution",            "T1059.006",  "Command and Scripting Interpreter: Python"),
    "deserialization":      ("Execution",            "T1059",      "Command and Scripting Interpreter"),
    "pickle":               ("Execution",            "T1059.006",  "Command and Scripting Interpreter: Python"),
    "template_injection":   ("Execution",            "T1059.006",  "Command and Scripting Interpreter: Python"),
    "jinja2":               ("Execution",            "T1059.006",  "Command and Scripting Interpreter: Python"),
    "render_template":      ("Execution",            "T1059.006",  "Command and Scripting Interpreter: Python"),

    # ── Persistence ──
    "backdoor":             ("Persistence",          "T1505.003",  "Server Software Component: Web Shell"),
    "web_shell":            ("Persistence",          "T1505.003",  "Server Software Component: Web Shell"),
    "cron_job":             ("Persistence",          "T1053.003",  "Scheduled Task/Job: Cron"),

    # ── Privilege Escalation ──
    "sudo":                 ("Privilege Escalation", "T1548.003",  "Abuse Elevation Control: Sudo"),
    "suid":                 ("Privilege Escalation", "T1548.001",  "Abuse Elevation Control: Setuid"),

    # ── Defense Evasion ──
    "obfuscation":          ("Defense Evasion",      "T1027",      "Obfuscated Files or Information"),

    # ── Credential Access ──
    "hardcoded_secret":     ("Credential Access",    "T1552.001",  "Unsecured Credentials: In Files"),
    "hardcoded_password":   ("Credential Access",    "T1552.001",  "Unsecured Credentials: In Files"),
    "exposed_credentials":  ("Credential Access",    "T1552.001",  "Unsecured Credentials: In Files"),
    "weak_password":        ("Credential Access",    "T1110",      "Brute Force"),
    "jwt_weak":             ("Credential Access",    "T1528",      "Steal Application Access Token"),
    "session_fixation":     ("Credential Access",    "T1539",      "Steal Web Session Cookie"),

    # ── Discovery ──
    "debug_enabled":        ("Discovery",            "T1082",      "System Information Discovery"),
    "directory_listing":    ("Discovery",            "T1083",      "File and Directory Discovery"),
    "info_disclosure":      ("Discovery",            "T1082",      "System Information Discovery"),
    "banner_grab":          ("Reconnaissance",       "T1592.002",  "Gather Victim Host Info: Software"),
    "version_disclosure":   ("Reconnaissance",       "T1592.002",  "Gather Victim Host Info: Software"),

    # ── Lateral Movement ──
    "ssh":                  ("Lateral Movement",     "T1021.004",  "Remote Services: SSH"),
    "rdp":                  ("Lateral Movement",     "T1021.001",  "Remote Services: RDP"),
    "smb":                  ("Lateral Movement",     "T1021.002",  "Remote Services: SMB"),
    "ftp":                  ("Lateral Movement",     "T1021",      "Remote Services"),

    # ── Collection ──
    "path_traversal":       ("Collection",           "T1005",      "Data from Local System"),
    "lfi":                  ("Collection",           "T1005",      "Data from Local System"),
    "file_read":            ("Collection",           "T1005",      "Data from Local System"),

    # ── Impact ──
    "xss":                  ("Impact",               "T1189",      "Drive-by Compromise"),
    "csrf":                 ("Impact",               "T1185",      "Browser Session Hijacking"),
    "dos":                  ("Impact",               "T1499",      "Endpoint Denial of Service"),
    "xxe":                  ("Execution",            "T1059",      "Command and Scripting Interpreter"),
    "ssrf":                 ("Initial Access",       "T1190",      "Exploit Public-Facing Application"),

    # ── Misconfiguration ──
    "cors_misconfigured":   ("Initial Access",       "T1190",      "Exploit Public-Facing Application"),
    "open_redirect":        ("Initial Access",       "T1566.002",  "Phishing: Spearphishing Link"),
    "missing_headers":      ("Discovery",            "T1082",      "System Information Discovery"),
    "flask_debug":          ("Discovery",            "T1082",      "System Information Discovery"),
}


# ── STRIDE Classification ──────────────────────────────────────────────

STRIDE_MAP = {
    "T1190":     ["Tampering", "Elevation of Privilege"],
    "T1059":     ["Tampering", "Elevation of Privilege"],
    "T1059.006": ["Tampering", "Information Disclosure"],
    "T1203":     ["Tampering", "Elevation of Privilege"],
    "T1078":     ["Spoofing", "Elevation of Privilege"],
    "T1566":     ["Spoofing"],
    "T1552.001": ["Information Disclosure"],
    "T1552":     ["Information Disclosure"],
    "T1110":     ["Spoofing", "Elevation of Privilege"],
    "T1528":     ["Spoofing", "Information Disclosure"],
    "T1539":     ["Spoofing", "Elevation of Privilege"],
    "T1082":     ["Information Disclosure"],
    "T1083":     ["Information Disclosure"],
    "T1005":     ["Information Disclosure"],
    "T1592.002": ["Information Disclosure"],
    "T1021":     ["Lateral Movement", "Elevation of Privilege"],
    "T1021.004": ["Lateral Movement", "Elevation of Privilege"],
    "T1021.001": ["Lateral Movement", "Elevation of Privilege"],
    "T1021.002": ["Lateral Movement", "Elevation of Privilege"],
    "T1505.003": ["Tampering", "Elevation of Privilege"],
    "T1053.003": ["Persistence", "Elevation of Privilege"],
    "T1548.003": ["Elevation of Privilege"],
    "T1548.001": ["Elevation of Privilege"],
    "T1027":     ["Tampering"],
    "T1189":     ["Tampering", "Information Disclosure"],
    "T1185":     ["Spoofing", "Tampering"],
    "T1499":     ["Denial of Service"],
    "T1566.002": ["Spoofing"],
    "T1592":     ["Information Disclosure"],
}


# ── Kill Chain ──────────────────────────────────────────────────────────

KILL_CHAIN = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]


def map_to_attack(service_or_vuln: str) -> dict:
    """Map a service name or vulnerability type to MITRE ATT&CK technique."""
    key = service_or_vuln.lower().strip()

    # Direct match
    if key in TECHNIQUE_MAP:
        tactic, tid, tname = TECHNIQUE_MAP[key]
        return {
            "tactic":         tactic,
            "technique_id":   tid,
            "technique_name": tname,
            "stride":         STRIDE_MAP.get(tid, ["Unknown"]),
            "kill_chain_pos": _kill_chain_position(tactic),
            "matched_on":     key,
            "match_type":     "exact"
        }

    # Fuzzy match
    for pattern, (tactic, tid, tname) in TECHNIQUE_MAP.items():
        if pattern in key or key in pattern:
            return {
                "tactic":         tactic,
                "technique_id":   tid,
                "technique_name": tname,
                "stride":         STRIDE_MAP.get(tid, ["Unknown"]),
                "kill_chain_pos": _kill_chain_position(tactic),
                "matched_on":     pattern,
                "match_type":     "fuzzy"
            }

    return {
        "tactic":         "Unknown",
        "technique_id":   "T0000",
        "technique_name": "Unclassified",
        "stride":         ["Unknown"],
        "kill_chain_pos": 7,
        "matched_on":     key,
        "match_type":     "none"
    }


def _kill_chain_position(tactic: str) -> int:
    try:
        return KILL_CHAIN.index(tactic) + 1
    except ValueError:
        return 7


def get_technique_details(technique_id: str) -> dict:
    """Look up full details for a technique ID."""
    for pattern, (tactic, tid, tname) in TECHNIQUE_MAP.items():
        if tid == technique_id:
            return {
                "technique_id":   tid,
                "technique_name": tname,
                "tactic":         tactic,
                "stride":         STRIDE_MAP.get(tid, ["Unknown"]),
                "kill_chain_pos": _kill_chain_position(tactic),
            }
    return {"technique_id": technique_id, "technique_name": "Unknown"}
