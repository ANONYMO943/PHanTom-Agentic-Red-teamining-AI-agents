"""
PHANTOM Rich Terminal UI — beautiful live output for demo and production.
All agents call these functions instead of raw print().
"""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax
from rich import box
import datetime
import sys
import io

# Force UTF-8 output on Windows to avoid cp1252 encoding errors
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

console = Console(force_terminal=True)


# ── Banner & Session ────────────────────────────────────────────────────

def print_banner(session_id: str, target: str, codebase: str = None):
    """Print the PHANTOM startup banner with session info."""
    title = Text()
    title.append("  P H A N T O M\n", style="bold bright_magenta")
    title.append("  Pentesting Heuristic Agent with Multi-Tool Network\n", style="dim white")
    title.append("  Autonomous  ·  Explainable  ·  Always On", style="italic cyan")

    console.print()
    console.print(Panel(title, border_style="bright_magenta", box=box.DOUBLE_EDGE,
                        padding=(1, 2)))

    info = Table(show_header=False, box=None, padding=(0, 2))
    info.add_column(style="bold cyan", width=12)
    info.add_column()
    info.add_row("Session", f"[bold]{session_id}[/]")
    info.add_row("Target", target)
    if codebase:
        info.add_row("Codebase", codebase)
    info.add_row("Started", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    console.print(Panel(info, title="[bold white]Session Info[/]",
                        border_style="blue", box=box.ROUNDED))
    console.print()


# ── Orchestrator ────────────────────────────────────────────────────────

def orchestrator_cycle(cycle: int, reasoning: str):
    """Show orchestrator planning step."""
    console.print(
        f"\n[bold white on blue] CYCLE {cycle} [/] "
        f"[bold bright_cyan]Planning next action...[/]"
    )
    console.print(f"  [dim italic]> {reasoning[:120]}[/]")


def orchestrator_done(reason: str):
    """Show orchestrator completion."""
    console.print(
        f"\n[bold white on green] COMPLETE [/] "
        f"[bold green]{reason}[/]"
    )


# ── Agent Status ────────────────────────────────────────────────────────

def agent_start(agent_name: str, description: str):
    """Agent beginning work."""
    label = agent_name.upper().replace("_", " ")
    console.print(f"\n  [bold yellow]▶ [{label}][/] {description}")


def agent_result(agent_name: str, message: str, style: str = "green"):
    """Agent success result."""
    label = agent_name.upper().replace("_", " ")
    console.print(f"    [bold {style}]✓[/] [dim][{label}][/] {message}")


def agent_warning(agent_name: str, message: str):
    """Agent warning."""
    label = agent_name.upper().replace("_", " ")
    console.print(f"    [bold yellow]⚠[/] [dim][{label}][/] {message}")


def agent_error(agent_name: str, message: str):
    """Agent error."""
    label = agent_name.upper().replace("_", " ")
    console.print(f"    [bold red]✗[/] [dim][{label}][/] {message}")


def agent_detail(message: str):
    """Indented detail line under an agent."""
    console.print(f"      [dim]{message}[/]")


# ── Findings ────────────────────────────────────────────────────────────

def finding_confirmed(finding_type: str, confidence: float, cvss: float = 0):
    """Show a confirmed finding."""
    sev_color = "red" if cvss >= 9 else "yellow" if cvss >= 7 else "blue"
    console.print(
        f"    [bold {sev_color}]█ CONFIRMED[/] {finding_type} "
        f"[dim](confidence: {confidence:.0%}, CVSS: {cvss:.1f})[/]"
    )


def finding_unconfirmed(finding_type: str, confidence: float):
    """Show an unconfirmed finding."""
    console.print(
        f"    [bold yellow]░ UNCONFIRMED[/] {finding_type} "
        f"[dim](confidence: {confidence:.0%})[/]"
    )


def pivot_notice(finding_type: str, reason: str):
    """Show exploit engine pivoting."""
    console.print(
        f"    [bold cyan]↻ PIVOT[/] {finding_type}: "
        f"[dim]{reason[:80]}[/]"
    )


def human_gate(finding_type: str, confidence: float, decision: str):
    """Show human-in-the-loop gate activation."""
    if decision == "proceed":
        console.print(
            f"    [bold green]⊘ GATE[/] {finding_type}: confidence {confidence:.0%} — "
            f"[green]auto-proceeding[/]"
        )
    elif decision == "abort":
        console.print(
            f"    [bold red]⊘ GATE[/] {finding_type}: confidence {confidence:.0%} — "
            f"[red]abandoned (below threshold)[/]"
        )
    else:
        console.print(
            f"    [bold yellow]⊘ GATE[/] {finding_type}: confidence {confidence:.0%} — "
            f"[yellow]paused for human review[/]"
        )


def guardrail_ok(check_name: str):
    """Show a guardrail check passed."""
    console.print(f"    [dim green]🛡 {check_name}: passed[/]")


def guardrail_block(check_name: str, reason: str):
    """Show a guardrail violation."""
    console.print(f"    [bold red]🛡 {check_name}: BLOCKED — {reason}[/]")


# ── Report ──────────────────────────────────────────────────────────────

def print_report(report: dict):
    """Print the full assessment report with Rich formatting."""
    console.print()
    console.print(Panel(
        "[bold bright_magenta]P H A N T O M   A S S E S S M E N T   R E P O R T[/]",
        border_style="bright_magenta", box=box.DOUBLE_EDGE
    ))

    # Session info
    console.print(f"  [bold]Session:[/]  {report.get('session_id', 'N/A')}")
    console.print(f"  [bold]Duration:[/] {report.get('duration_seconds', 0):.1f}s")
    console.print()

    # Executive Summary
    summary = report.get("executive_summary", "Not generated")
    sev = "red" if "CRITICAL" in summary.upper() else "yellow" if "HIGH" in summary.upper() else "blue"
    console.print(Panel(
        summary,
        title="[bold]Executive Summary[/]",
        border_style=sev,
        box=box.ROUNDED,
        padding=(1, 2)
    ))

    # Stats table
    stats = report.get("stats", {})
    stats_table = Table(title="Assessment Statistics", box=box.SIMPLE_HEAVY,
                        title_style="bold white")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="bold white", justify="center")
    stats_table.add_row("Confirmed Findings",
                        f"[bold red]{stats.get('confirmed_findings', 0)}[/]")
    stats_table.add_row("Unconfirmed Findings",
                        f"[yellow]{stats.get('unconfirmed_findings', 0)}[/]")
    stats_table.add_row("Patches Generated",
                        str(stats.get("patches_generated", 0)))
    stats_table.add_row("Patches Cleared (Bandit)",
                        f"[green]{stats.get('patches_cleared', 0)}[/]")
    console.print(stats_table)
    console.print()

    # Technical findings — confirmed
    for f in report.get("technical_findings", []):
        if f["status"] == "CONFIRMED":
            cvss = f.get("cvss", 0)
            sc = "red" if cvss >= 9 else "yellow" if cvss >= 7 else "blue"

            lines = []
            lines.append(f"[bold]Type:[/]          {f['type']}")
            lines.append(f"[bold]File:[/]          {f.get('file', '?')}:{f.get('line', 0)}")
            lines.append(f"[bold]CVSS:[/]          [{sc}]{cvss:.1f}[/{sc}]")
            lines.append(f"[bold]Technique:[/]     {f.get('technique_id', 'N/A')}")
            lines.append(f"[bold]Confidence:[/]    {f.get('confidence', 0):.0%}")
            lines.append(f"[bold]Attack Vector:[/] {f.get('attack_vector', 'N/A')}")
            lines.append(f"[bold]Reasoning:[/]     {f.get('reasoning', 'N/A')[:200]}")

            if f.get("patch"):
                p = f["patch"]
                cleared = "[green]✓ CLEARED[/]" if p.get("bandit_cleared") else "[red]✗ BLOCKED[/]"
                lines.append(f"")
                lines.append(f"[bold]Patch Status:[/] {cleared}")
                lines.append(f"[bold]Signature:[/]    {p.get('signature', 'N/A')}")
                if p.get("plain_english"):
                    lines.append(f"[bold]Fix:[/]          {p['plain_english'][:200]}")
                if p.get("diff"):
                    lines.append(f"")
                    lines.append(f"[bold]Diff:[/]")
                    lines.append(f"[green]{p['diff'][:400]}[/]")

            console.print(Panel(
                "\n".join(lines),
                title=f"[bold {sc}]{f['id']} — CRITICAL[/]" if cvss >= 9
                      else f"[bold {sc}]{f['id']} — HIGH[/]" if cvss >= 7
                      else f"[bold {sc}]{f['id']} — MEDIUM[/]",
                border_style=sc,
                box=box.ROUNDED
            ))

    # Unconfirmed findings
    for f in report.get("technical_findings", []):
        if f["status"] == "UNCONFIRMED":
            console.print(Panel(
                f"[bold]Type:[/]       {f['type']}\n"
                f"[bold]File:[/]       {f.get('file', '?')}\n"
                f"[bold]Confidence:[/] {f.get('confidence', 0):.0%}\n"
                f"[bold]Reasoning:[/]  {f.get('reasoning', 'N/A')[:200]}",
                title=f"[yellow]{f['id']} — UNCONFIRMED[/]",
                border_style="yellow",
                box=box.ROUNDED
            ))

    # Thought trace
    trace = report.get("thought_trace", [])
    if trace:
        trace_table = Table(title="Agent Reasoning Trace", box=box.SIMPLE,
                            title_style="bold white")
        trace_table.add_column("Cycle", style="bold white", width=6, justify="center")
        trace_table.add_column("Agent", style="cyan", width=18)
        trace_table.add_column("Reasoning", style="dim")
        for step in trace:
            trace_table.add_row(
                str(step["cycle"]),
                step["agent"].upper().replace("_", " "),
                step["thought"][:90] + ("..." if len(step.get("thought", "")) > 90 else "")
            )
        console.print(trace_table)
        console.print()

    # Audit trail
    audit = report.get("audit_trail", [])
    if audit:
        audit_table = Table(title="Audit Trail — SHA-256 Hash Chained",
                            box=box.MINIMAL, title_style="bold white")
        audit_table.add_column("Event", style="cyan", width=22)
        audit_table.add_column("Agent", style="bold", width=16)
        audit_table.add_column("Hash", style="dim green", width=14)
        audit_table.add_column("Prev", style="dim", width=14)
        for entry in audit:
            audit_table.add_row(
                entry["event"],
                entry["agent"],
                entry["hash"],
                entry["prev_hash"]
            )
        console.print(audit_table)
