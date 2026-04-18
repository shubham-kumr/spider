"""
SPIDER - Terminal UI Display Components
All Rich-based terminal UI components for SPIDER CLI output.
Follows the design system defined in FRONTEND_GUIDELINES.md.
"""

from __future__ import annotations

import sys
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from spider.config import SPIDER_NO_RICH

# legacy_windows=False forces Rich to use ANSI sequences instead of the
# legacy Win32 console API, bypassing cp1252 encoding errors on Windows.
_console = Console(force_terminal=True, legacy_windows=False, highlight=False)


# ── Color System ──────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "bold orange1",
    "medium":   "bold yellow",
    "low":      "bold cyan",
    "info":     "white",
    "success":  "bold green",
    "warning":  "bold yellow",
    "error":    "bold red",
}

AGENT_COLORS = {
    "orchestrator":  "bold magenta",
    "recon":         "bold blue",
    "enumeration":   "bold cyan",
    "exploitation":  "bold red",
    "post_exploit":  "bold orange1",
    "reporting":     "bold green",
    "system":        "dim white",
    "preflight":     "bold white",
}

SEVERITY_BADGE = {
    "critical": "[bold white on red] CRITICAL [/bold white on red]",
    "high":     "[bold white on dark_orange] HIGH [/bold white on dark_orange]",
    "medium":   "[bold black on yellow] MEDIUM [/bold black on yellow]",
    "low":      "[bold white on blue] LOW [/bold white on blue]",
    "info":     "[bold white on grey50] INFO [/bold white on grey50]",
}


# ── Component 1: Startup Banner ───────────────────────────────────────────────

def render_banner(target_ip: str = "", version: str = "1.0.0") -> None:
    """Display the SPIDER ASCII art startup banner."""
    if SPIDER_NO_RICH:
        print(f"SPIDER v{version} | Target: {target_ip}")
        return

    # Beautiful ASCII Art from README
    banner_text = Text()
    banner_text.append("  ███████╗██████╗ ██╗██████╗ ███████╗██████╗\n", style="bold red")
    banner_text.append("  ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗\n", style="bold red")
    banner_text.append("  ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝\n", style="bold red")
    banner_text.append("  ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗\n", style="bold red")
    banner_text.append("  ███████║██║     ██║██████╔╝███████╗██║  ██║\n", style="bold red")
    banner_text.append("  ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝\n", style="bold red")
    banner_text.append(
        "\n  System for Pentesting, Initial Discovery, Exploitation & Reconnaissance\n",
        style="dim white",
    )
    if target_ip:
        banner_text.append(f"  Version {version}  |  Target: {target_ip}\n", style="dim white")
    else:
        banner_text.append(f"  Version {version}\n", style="dim white")

    try:
        _console.print(Panel(banner_text, border_style="bright_black", padding=(0, 1)))
    except Exception:
        # Absolute fallback for any encoding issue
        print(f"\n  [ SPIDER v{version} ] Target: {target_ip}")
        print("  System for Pentesting, Initial Discovery, Exploitation & Reconnaissance\n")


# ── Component 2: Pre-Flight Check Panel ──────────────────────────────────────

def render_preflight(checks: list[dict]) -> None:
    """
    Display pre-flight check results table.
    
    checks = [{"name": "nmap", "status": True, "note": "7.94"}, ...]
    """
    if SPIDER_NO_RICH:
        for c in checks:
            icon = "PASS" if c["status"] else "FAIL"
            print(f"  [{icon}] {c['name']}: {c.get('note','')}")
        return

    table = Table(
        title="[bold white]Pre-Flight Checks[/bold white]",
        border_style="bright_black",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Check", style="white", min_width=24)
    table.add_column("Status", justify="center", min_width=12)
    table.add_column("Note", style="dim white", min_width=24)

    for check in checks:
        status_icon = (
            "[bold green]✓ PASS[/bold green]"
            if check["status"]
            else "[bold red]✗ FAIL[/bold red]"
        )
        table.add_row(check["name"], status_icon, check.get("note", ""))

    _console.print(table)


# ── Component 3: Orchestrator Decision Panel ─────────────────────────────────

def render_orchestrator_decision(round_num: int, next_agent: str, reason: str) -> None:
    """Display orchestrator's LLM decision."""
    if SPIDER_NO_RICH:
        print(f"[ORCHESTRATOR] Round {round_num} → {next_agent.upper()}: {reason}")
        return

    content = (
        f"[dim white]Round {round_num}[/dim white]\n"
        f"[bold magenta]>> Next Agent:[/bold magenta] [bold white]{next_agent.upper()}[/bold white]\n"
        f"[dim white]Reasoning:[/dim white] [white]{reason}[/white]"
    )
    _console.print(Panel(
        content,
        title="[bold magenta]ORCHESTRATOR[/bold magenta]",
        border_style="magenta",
        padding=(0, 1),
    ))


# ── Component 4: Open Ports Table ────────────────────────────────────────────

def render_ports_table(ports: list[dict]) -> Table:
    """
    Build and return a Rich Table of nmap results.
    ports = [{"port": 21, "service": "ftp", "version": "...", "banner": "..."}, ...]
    """
    table = Table(
        title=f"[bold blue]Recon Results — {len(ports)} Open Ports[/bold blue]",
        border_style="blue",
        show_header=True,
        header_style="bold white on dark_blue",
    )
    table.add_column("Port", style="bold cyan", justify="right", min_width=6)
    table.add_column("Proto", style="dim white", min_width=5)
    table.add_column("Service", style="white", min_width=12)
    table.add_column("Version", style="white", min_width=25)
    table.add_column("Banner", style="dim white", min_width=30)

    for p in ports:
        table.add_row(
            str(p.get("port", "")),
            p.get("protocol", "tcp"),
            p.get("service", "—"),
            (p.get("version") or p.get("product") or "—")[:40],
            (p.get("banner") or "—")[:50],
        )
    return table


# ── Component 5: Findings Table ───────────────────────────────────────────────

def render_findings_table(findings: list[dict]) -> Table:
    """
    Build and return a Rich Table of enumeration findings.
    """
    table = Table(
        title=f"[bold cyan]Findings — {len(findings)} Issues Identified[/bold cyan]",
        border_style="cyan",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Severity", justify="center", min_width=14)
    table.add_column("Service:Port", style="cyan", min_width=14)
    table.add_column("Finding", style="white", min_width=35)
    table.add_column("CVE", style="bold red", min_width=16)
    table.add_column("CVSS", justify="right", min_width=6)

    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        badge = SEVERITY_BADGE.get(sev, sev.upper())
        port = f.get("port")
        svc_port = f"{f.get('service', '?')}:{port}" if port else f.get("service", "?")
        cvss = f.get("cvss_score")
        table.add_row(
            badge,
            svc_port,
            str(f.get("title", ""))[:50],
            f.get("cve_id") or "—",
            f"{cvss:.1f}" if cvss else "—",
        )
    return table


# ── Component 6: Exploitation Status Panel ───────────────────────────────────

def render_exploit_status(
    module: str,
    target: str,
    port: int,
    success: bool,
    session_id: Optional[int] = None,
    error: Optional[str] = None,
) -> None:
    """Display exploit execution result."""
    if SPIDER_NO_RICH:
        if success:
            print(f"[EXPLOIT SUCCESS] {module} → {target}:{port} — Session {session_id}")
        else:
            print(f"[EXPLOIT FAILED] {module} → {target}:{port} — {error}")
        return

    if success:
        content = (
            f"[dim white]Module:[/dim white] [bold cyan]{module}[/bold cyan]\n"
            f"[dim white]Target:[/dim white] [white]{target}:{port}[/white]\n"
            f"[bold green]>> EXPLOIT SUCCESS — Session ID: {session_id}[/bold green]"
        )
        border = "green"
        title = "[bold green]EXPLOITATION — SUCCESS[/bold green]"
    else:
        content = (
            f"[dim white]Module:[/dim white] [bold cyan]{module}[/bold cyan]\n"
            f"[dim white]Target:[/dim white] [white]{target}:{port}[/white]\n"
            f"[bold red]>> EXPLOIT FAILED: {error}[/bold red]"
        )
        border = "red"
        title = "[bold red]EXPLOITATION — FAILED[/bold red]"

    _console.print(Panel(content, title=title, border_style=border, padding=(0, 1)))


# ── Component 7: Progress Spinner ────────────────────────────────────────────

def get_progress_spinner() -> Progress:
    """Return a Rich Progress spinner context manager for long-running tasks."""
    return Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn("[white]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
    )


# ── Component 8: Error Panel ──────────────────────────────────────────────────

def render_error(title: str, message: str, fix: Optional[str] = None) -> None:
    """Display a styled error panel with optional fix suggestion."""
    if SPIDER_NO_RICH:
        print(f"[ERROR] {title}: {message}")
        if fix:
            print(f"  Fix: {fix}")
        return

    content = f"[bold red]{message}[/bold red]"
    if fix:
        content += f"\n\n[dim white]Fix:[/dim white] [yellow]{fix}[/yellow]"

    _console.print(Panel(
        content,
        title=f"[bold red]ERROR: {title}[/bold red]",
        border_style="red",
        padding=(0, 1),
    ))


# ── Component 9: Success Banner ──────────────────────────────────────────────

def render_success_banner(message: str, detail: Optional[str] = None) -> None:
    """Display a success banner panel."""
    if SPIDER_NO_RICH:
        print(f"[SUCCESS] {message}")
        if detail:
            print(f"  {detail}")
        return

    content = f"[bold green]{message}[/bold green]"
    if detail:
        content += f"\n[dim white]{detail}[/dim white]"
    _console.print(Panel(content, border_style="green", padding=(0, 1)))


# ── Component 10: Status Table ───────────────────────────────────────────────

def render_status_table(runs: list[dict]) -> None:
    """Display all SPIDER runs status table."""
    if SPIDER_NO_RICH:
        for r in runs:
            print(f"  {r['target']} | {r['phase']} | {r['findings']} findings | {r['timestamp']}")
        return

    if not runs:
        _console.print("[dim white]No runs found in database.[/dim white]")
        return

    table = Table(
        title="[bold white]SPIDER Run Status[/bold white]",
        border_style="bright_black",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Target IP", style="cyan", min_width=16)
    table.add_column("Status", style="white", min_width=10)
    table.add_column("Last Phase", style="white", min_width=14)
    table.add_column("Ports", justify="right", style="blue", min_width=6)
    table.add_column("Findings", justify="right", style="yellow", min_width=10)
    table.add_column("Sessions", justify="right", style="green", min_width=10)
    table.add_column("Last Run", style="dim white", min_width=18)

    for r in runs:
        status_color = {
            "complete": "bold green",
            "running": "bold yellow",
            "failed": "bold red",
        }.get(r.get("status", ""), "white")
        table.add_row(
            r["target"],
            f"[{status_color}]{r.get('status','?')}[/{status_color}]",
            r["phase"],
            str(r.get("ports", 0)),
            str(r["findings"]),
            str(r["sessions"]),
            r["timestamp"],
        )
    _console.print(table)


# ── Log action ────────────────────────────────────────────────────────────────

def log_action(agent: str, message: str, level: str = "info") -> None:
    """
    Print a timestamped agent action log line to the terminal.
    Also writes to the log file if configured.
    
    Format: HH:MM:SS [AGENT] message
    """
    timestamp = datetime.now().strftime("%H:%M:%S")
    agent_color = AGENT_COLORS.get(agent.lower(), "white")
    level_color = {
        "info":    "white",
        "warning": "bold yellow",
        "error":   "bold red",
        "success": "bold green",
    }.get(level, "white")

    if SPIDER_NO_RICH:
        print(f"{timestamp} [{agent.upper()}] {message}")
    else:
        _console.print(
            f"[dim white]{timestamp}[/dim white] "
            f"[{agent_color}][{agent.upper()}][/{agent_color}] "
            f"[{level_color}]{message}[/{level_color}]"
        )
