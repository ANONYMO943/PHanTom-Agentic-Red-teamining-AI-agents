"""
PHANTOM — Entry point for security assessment.
Usage: python main.py <target_ip> [codebase_path]
"""
import json
import sys
import os
from dotenv import load_dotenv
from orchestrator import PhantomOrchestrator
import ui

load_dotenv()


def main():
    if len(sys.argv) < 2:
        ui.console.print("[bold red]Usage:[/] python main.py <target_ip> [codebase_path]")
        ui.console.print("[dim]Example: python main.py 127.0.0.1 ./target_app[/]")
        sys.exit(1)

    target = sys.argv[1]
    target_path = sys.argv[2] if len(sys.argv) > 2 else None

    # Normalize path
    if target_path:
        target_path = os.path.abspath(target_path)

    orchestrator = PhantomOrchestrator()
    report = orchestrator.run(target, target_path)

    # Print Rich report
    ui.print_report(report)

    # Save full JSON report
    output_file = f"phantom_report_{report['session_id']}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    ui.console.print(f"\n[bold green]Full report saved:[/] {output_file}")


if __name__ == "__main__":
    main()
