"""
PHANTOM FastAPI Bridge
Drop this file into the root of your PHANTOM project (alongside main.py).
Run: uvicorn api:app --reload --port 8000
"""

import uuid
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="PHANTOM API", version="1.0.0")

# Allow all origins so the frontend HTML file can call this locally
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store: session_id -> session data
sessions: dict = {}
executor = ThreadPoolExecutor(max_workers=2)


# ─── Request / Response Models ───────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    codebase_path: Optional[str] = None


# ─── Background scan runner ───────────────────────────────────────────────────

def _run_scan(session_id: str, target: str, codebase_path: Optional[str]):
    """Runs in a thread pool — PhantomOrchestrator is fully synchronous."""
    try:
        sessions[session_id]["status"] = "running"
        sessions[session_id]["log"].append("🔍 Orchestrator starting ReAct loop...")

        from orchestrator import PhantomOrchestrator
        import ui
        from io import StringIO
        from rich.console import Console

        orchestrator = PhantomOrchestrator()

        # Capture Rich console output into session log
        capture_buffer = StringIO()
        original_console = ui.console
        ui.console = Console(file=capture_buffer, force_terminal=False, width=120)

        # Also capture plain print calls
        import builtins
        original_print = builtins.print

        def capturing_print(*args, **kwargs):
            msg = " ".join(str(a) for a in args)
            sessions[session_id]["log"].append(msg)
            original_print(*args, **kwargs)

        builtins.print = capturing_print
        try:
            report = orchestrator.run(target, codebase_path)
            # Flush captured Rich output into log
            captured = capture_buffer.getvalue()
            if captured:
                for line in captured.splitlines():
                    if line.strip():
                        sessions[session_id]["log"].append(line)
        finally:
            builtins.print = original_print
            ui.console = original_console

        sessions[session_id]["status"] = "done"
        sessions[session_id]["report"] = report
        sessions[session_id]["log"].append("✅ Assessment complete.")

    except Exception as e:
        import traceback
        sessions[session_id]["status"] = "error"
        sessions[session_id]["error"] = str(e)
        sessions[session_id]["log"].append(f"❌ Error: {e}")
        sessions[session_id]["log"].append(traceback.format_exc())


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "PHANTOM API is running. POST /api/scan to start."}


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    """Start a new PHANTOM scan. Returns a session_id to poll."""
    session_id = f"phantom-{uuid.uuid4().hex[:8]}"
    sessions[session_id] = {
        "session_id":   session_id,
        "status":       "queued",
        "target":       req.target,
        "codebase_path": req.codebase_path,
        "log":          [f"📡 Scan queued for {req.target}"],
        "report":       None,
        "error":        None,
    }
    loop = asyncio.get_event_loop()
    loop.run_in_executor(executor, _run_scan, session_id, req.target, req.codebase_path)
    return {"session_id": session_id, "status": "queued"}


@app.get("/api/status/{session_id}")
def get_status(session_id: str):
    """Poll this to get live status + log lines. Returns report when done."""
    if session_id not in sessions:
        return {"error": "Session not found", "session_id": session_id}
    session = sessions[session_id]
    return {
        "session_id": session_id,
        "status":     session["status"],          # queued | running | done | error
        "target":     session["target"],
        "log":        session["log"],             # list of string log lines
        "error":      session.get("error"),
        "report":     session.get("report"),      # full report when status == "done"
    }


@app.get("/api/sessions")
def list_sessions():
    """List all session IDs and their statuses."""
    return [
        {"session_id": sid, "status": s["status"], "target": s["target"]}
        for sid, s in sessions.items()
    ]


@app.delete("/api/session/{session_id}")
def delete_session(session_id: str):
    if session_id in sessions:
        del sessions[session_id]
        return {"deleted": True}
    return {"error": "Not found"}
