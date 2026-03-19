# PHANTOM — Autonomous Pentesting AI

> **⚠️ DISCLAIMER**: This tool is for **authorized security testing only**.
> Never run PHANTOM against systems you do not own or have explicit written
> permission to test. Unauthorized use is illegal and unethical.

---

## What Is PHANTOM?

PHANTOM is a multi-agent AI system for automated security assessment built on
top of **Claude AI** (Anthropic). It implements a **ReAct
(Reasoning + Acting)** orchestration loop that autonomously plans, executes,
reflects on, and replans security assessment tasks across five specialized
agents — all without hardcoded decision trees.

---

## Architecture

```
                        ┌──────────────────────────┐
                        │   PhantomOrchestrator    │
                        │  (ReAct loop — Claude)   │
                        └────────────┬─────────────┘
                 Plan → Act → Observe │ Reflect → Replan
          ┌──────────┬───────────┬───┴────────┬───────────┐
          ▼          ▼           ▼            ▼           ▼
     ReconAgent  ThreatModel  ExploitEngine PatchAgent ReportAgent
     (nmap +     (MITRE       (Semgrep +    (Claude +  (Claude +
      Shodan)     ATT&CK +     Bandit +      Bandit     audit
                  NVD CVEs)    Claude        verify)    trail)
                               self-correct)
                        │
                        ▼
                 PhantomMemory (ChromaDB)
                 — persists findings, failed attempts,
                   confirmed exploits across the session
```

### The 5 Agents

| Agent | Role |
|-------|------|
| **ReconAgent** | nmap port/service scan + optional Shodan passive intel + codebase surface mapping |
| **ThreatModelAgent** | Maps open ports & code issues to MITRE ATT&CK tactics/techniques + pulls NVD CVEs + STRIDE threat categories |
| **ExploitEngine** | Runs Semgrep + Bandit static analysis; uses Claude to assess exploitability; self-corrects via pivot when confidence < 70% |
| **PatchAgent** | Generates minimal unified-diff patches via Claude; re-runs Bandit to verify the patch doesn't introduce new issues; signs each patch with SHA-256 |
| **ReportAgent** | Produces executive summary (non-technical), structured technical findings list, and a chained-hash audit trail |

---

## Quick Start

```bash
# 1. Clone / download the project
git clone <repo-url>
cd phantom

# 2. Create and activate a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys
copy .env.example .env      # Windows
# cp .env.example .env      # macOS/Linux
# Then open .env and fill in your keys:
#   ANTHROPIC_API_KEY=sk-ant-...
#   SHODAN_API_KEY=...        (optional)
#   NVD_API_KEY=...           (optional, increases NVD rate limits)

# 5. Run an assessment
python main.py <target_ip> [codebase_path]

# Example — scan localhost and analyse the bundled demo app:
python main.py 127.0.0.1 ./target_app
```

The full JSON report is saved automatically as
`phantom_report_<session_id>.json`.

---

## Demo Target App

`target_app/app.py` is an **intentionally vulnerable** Flask application
containing:

- **SSTI** (Server-Side Template Injection) in `/render`
- **SQL Injection** pattern in `/user`
- **Hardcoded secret key**
- **Debug mode enabled**

Run it with:

```bash
cd target_app
pip install flask==2.3.0
python app.py          # starts on http://127.0.0.1:5000
```

Then in another terminal:

```bash
cd ..
python main.py 127.0.0.1 ./target_app
```

---

## Project Structure

```
phantom/
├── main.py                  # Entry point & report printer
├── orchestrator.py          # ReAct loop — Claude plans every step
├── requirements.txt         # Python dependencies
├── .env.example             # API key template
├── .gitignore
│
├── memory/
│   ├── __init__.py
│   └── store.py             # ChromaDB-backed session memory
│
├── tools/
│   ├── __init__.py
│   ├── nmap_tool.py         # python-nmap wrapper
│   ├── semgrep_tool.py      # Semgrep subprocess wrapper
│   ├── bandit_tool.py       # Bandit subprocess wrapper
│   ├── nvd_tool.py          # NIST NVD REST API v2 client
│   ├── mitre_tool.py        # ATT&CK + STRIDE mapping tables
│   └── shodan_tool.py       # Shodan API wrapper
│
├── agents/
│   ├── __init__.py
│   ├── recon.py             # ReconAgent
│   ├── threat_model.py      # ThreatModelAgent
│   ├── exploit_engine.py    # ExploitEngine (self-correcting)
│   ├── patch_agent.py       # PatchAgent (verified + signed)
│   └── report_agent.py      # ReportAgent (audit trail)
│
└── target_app/
    ├── app.py               # Intentionally vulnerable demo app
    └── requirements.txt
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `anthropic` | Claude AI API — drives orchestration, exploit assessment, patch generation, report writing |
| `chromadb` | Vector database for session memory (stores findings, failures, pivots) |
| `python-nmap` | nmap port scanner Python bindings |
| `semgrep` | Pattern-based static analysis (SAST) |
| `bandit` | Python-specific security linter (AST-based) |
| `requests` | NVD CVE API HTTP client |
| `python-dotenv` | `.env` file loader |
| `shodan` | Shodan passive recon API client |
| `rich` | Optional — enhanced terminal output |
| `flask` | Demo target app only |

---

## Requirements

- Python 3.10+
- nmap installed on the host OS (`apt install nmap` / `brew install nmap`)
- Valid `ANTHROPIC_API_KEY` (required)
- `SHODAN_API_KEY` (optional — passive recon is skipped without it)
- `NVD_API_KEY` (optional — adds higher NVD rate limits)

---

## ⚠️ Legal Disclaimer

PHANTOM is a research and educational tool. Only use it against systems you
own or have **explicit, written authorization** to test. The authors accept no
liability for misuse. Penetration testing without authorization is a criminal
offence in most jurisdictions.
