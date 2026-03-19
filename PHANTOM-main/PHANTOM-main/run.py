"""
PHANTOM — One-command demo launcher.
Checks dependencies, starts target app, runs full assessment.
Usage: python run.py
"""
import sys
import os
import subprocess
import time
import socket

BASE = os.path.dirname(os.path.abspath(__file__))


def check_dependencies():
    """Verify critical packages are installed."""
    missing = []
    required = {
        "google.genai":    "google-genai",
        "chromadb":        "chromadb",
        "dotenv":          "python-dotenv",
        "requests":        "requests",
        "flask":           "flask",
        "rich":            "rich",
        "pydantic":        "pydantic",
    }
    for module, package in required.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)

    if missing:
        print(f"[SETUP] Installing missing: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
        print("[SETUP] Done. Re-launching...\n")
        os.execv(sys.executable, [sys.executable] + sys.argv)


def check_env():
    """Verify API key is set."""
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE, ".env"))
    key = os.getenv("GEMINI_API_KEY")
    if not key or key.strip() == "":
        print("\n[ERROR] GEMINI_API_KEY is not set in your .env file.")
        print(f"  Edit: {os.path.join(BASE, '.env')}")
        print("  Add:  GEMINI_API_KEY=your_key_here\n")
        sys.exit(1)
    print("[SETUP] API key loaded")


def start_target_app():
    """Launch the vulnerable Flask app for demo."""
    app_path = os.path.join(BASE, "target_app", "app.py")
    print("[SETUP] Starting target Flask app on port 5000...")
    try:
        proc = subprocess.Popen(
            [sys.executable, app_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        # Wait and verify it started
        for _ in range(10):
            time.sleep(0.5)
            s = socket.socket()
            s.settimeout(0.5)
            result = s.connect_ex(("127.0.0.1", 5000))
            s.close()
            if result == 0:
                print("[SETUP] Target app running at http://127.0.0.1:5000")
                return proc
        print("[SETUP] Target app may not be running — continuing anyway")
        return proc
    except Exception as e:
        print(f"[SETUP] Could not start target app: {e}")
        return None


def main():
    print("\n" + "=" * 60)
    print("  PHANTOM — AI Pentesting System — Demo Launcher")
    print("=" * 60 + "\n")

    check_dependencies()
    check_env()
    proc = start_target_app()

    print("\n[SETUP] Launching PHANTOM assessment...\n")
    try:
        sys.path.insert(0, BASE)
        import ui
        from orchestrator import PhantomOrchestrator
        import json

        target_path = os.path.join(BASE, "target_app")
        orchestrator = PhantomOrchestrator()
        report = orchestrator.run("127.0.0.1", target_path)

        # Print Rich report
        ui.print_report(report)

        # Save JSON
        out = os.path.join(BASE, f"phantom_report_{report['session_id']}.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        ui.console.print(f"\n[bold green]Full report saved:[/] {out}\n")

    except Exception as e:
        import traceback
        print(f"\n[ERROR] PHANTOM failed: {e}")
        traceback.print_exc()
    finally:
        if proc:
            proc.terminate()
            print("[SETUP] Target app stopped.")


if __name__ == "__main__":
    main()
