# Frontend (CLI) Design Guidelines
# SPIDR — System for Penetration Testing, Intelligence, Discovery & Reconnaissance

**Version**: 1.0  
**Last Updated**: 2026-04-17  
**Note**: SPIDR is a CLI tool. "Frontend" means the terminal UI built with the Rich library. This document defines every visual decision for the terminal interface.

---

## 1. Design Principles

1. **Information density**: Every line on screen must carry meaning. No decorative clutter.
2. **Threat-first color coding**: Critical = red, High = orange, Medium = yellow, Low = cyan, Info = white. Never deviate.
3. **Real-time transparency**: Users must see what each agent is doing as it happens — no black-box silences.
4. **Fail loudly**: Errors must be immediately visible with actionable remediation steps.
5. **Minimal interaction**: The tool is autonomous. User input should be required only at startup.

---

## 2. Color System (Rich Color Names)

### Severity Colors

```python
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
```

### Agent Colors (for agent identity in log stream)

```python
AGENT_COLORS = {
    "orchestrator":  "bold magenta",
    "recon":         "bold blue",
    "enumeration":   "bold cyan",
    "exploitation":  "bold red",
    "post_exploit":  "bold orange1",
    "reporting":     "bold green",
    "system":        "dim white",
}
```

### UI Structure Colors

```python
UI_COLORS = {
    "panel_border":   "bright_black",   # Subtle borders
    "panel_title":    "bold white",
    "table_header":   "bold white on dark_blue",
    "table_row_alt":  "on grey7",       # Alternating row shading
    "dim_text":       "dim white",
    "highlight":      "bold white on dark_red",
    "link":           "underline cyan",
}
```

---

## 3. Typography (Rich Markup)

### Text Hierarchy

```python
# Page/run title — used once per run
title_style = "bold white on dark_blue"

# Section headers (agent names, phase names)
section_style = "bold white"

# Body text (agent reasoning, descriptions)
body_style = "white"

# Muted / secondary text (timestamps, IDs)
muted_style = "dim white"

# Inline code / commands
code_style = "bold cyan on grey11"

# CVE IDs and vulnerability names
vuln_style = "bold red"

# Success messages
success_style = "bold green"

# Warning messages  
warning_style = "bold yellow"

# Error messages
error_style = "bold red"
```

### Usage Rules
- Never use more than 3 style layers simultaneously (e.g., `bold red on dark_blue` is max)
- CVE IDs always rendered with `vuln_style`
- Shell commands always rendered with `code_style`
- Timestamps always rendered with `muted_style`

---

## 4. Component Library (Rich Components)

### Component 1: Startup Banner

```python
from rich import print
from rich.panel import Panel
from rich.text import Text

def render_banner(target_ip: str, version: str = "1.0.0"):
    banner_text = Text()
    banner_text.append("  ███████╗██████╗ ██╗██████╗ ██████╗ \n", style="bold red")
    banner_text.append("  ██╔════╝██╔══██╗██║██╔══██╗██╔══██╗\n", style="bold red")
    banner_text.append("  ███████╗██████╔╝██║██║  ██║██████╔╝\n", style="bold red")
    banner_text.append("  ╚════██║██╔═══╝ ██║██║  ██║██╔══██╗\n", style="bold red")
    banner_text.append("  ███████║██║     ██║██████╔╝██║  ██║\n", style="bold red")
    banner_text.append("  ╚══════╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝\n", style="bold red")
    banner_text.append(f"\n  System for Penetration Testing, Intelligence, Discovery & Reconnaissance\n", style="dim white")
    banner_text.append(f"  Version {version}  |  Target: {target_ip}\n", style="dim white")
    
    print(Panel(banner_text, border_style="bright_black", padding=(0, 1)))
```

---

### Component 2: Pre-Flight Check Panel

```python
from rich.table import Table
from rich.console import Console

def render_preflight(checks: list[dict]) -> None:
    """
    checks = [
      {"name": "nmap", "status": True, "note": "7.94"},
      {"name": "Together AI API", "status": False, "note": "Key missing"},
      ...
    ]
    """
    console = Console()
    table = Table(
        title="[bold white]Pre-Flight Checks[/bold white]",
        border_style="bright_black",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Check", style="white", min_width=20)
    table.add_column("Status", justify="center", min_width=10)
    table.add_column("Note", style="dim white", min_width=20)

    for check in checks:
        status_icon = "[bold green]✓ PASS[/bold green]" if check["status"] else "[bold red]✗ FAIL[/bold red]"
        table.add_row(check["name"], status_icon, check["note"])
    
    console.print(table)
```

---

### Component 3: Orchestrator Decision Panel

```python
from rich.panel import Panel

def render_orchestrator_decision(round_num: int, next_agent: str, reason: str) -> None:
    content = (
        f"[dim white]Round {round_num}[/dim white]\n"
        f"[bold magenta]>> Next Agent:[/bold magenta] [bold white]{next_agent.upper()}[/bold white]\n"
        f"[dim white]Reasoning:[/dim white] [white]{reason}[/white]"
    )
    print(Panel(
        content,
        title="[bold magenta]ORCHESTRATOR[/bold magenta]",
        border_style="magenta",
        padding=(0, 1)
    ))
```

---

### Component 4: Open Ports Table (Recon Agent)

```python
from rich.table import Table

def render_ports_table(ports: list[dict]) -> Table:
    """
    ports = [
      {"port": 21, "service": "ftp", "version": "vsftpd 2.3.4", "banner": "..."},
      ...
    ]
    """
    table = Table(
        title="[bold blue]Recon Results — Open Ports[/bold blue]",
        border_style="blue",
        show_header=True,
        header_style="bold white on dark_blue",
    )
    table.add_column("Port", style="bold cyan", justify="right", min_width=6)
    table.add_column("Service", style="white", min_width=10)
    table.add_column("Version", style="white", min_width=20)
    table.add_column("Banner", style="dim white", min_width=30)

    for port in ports:
        table.add_row(
            str(port["port"]),
            port["service"],
            port["version"] or "—",
            (port["banner"] or "—")[:50]
        )
    return table
```

---

### Component 5: Findings Table (Enumeration / Post-Exploit Agents)

```python
from rich.table import Table

SEVERITY_BADGE = {
    "critical": "[bold white on red] CRITICAL [/bold white on red]",
    "high":     "[bold white on dark_orange] HIGH [/bold white on dark_orange]",
    "medium":   "[bold black on yellow] MEDIUM [/bold black on yellow]",
    "low":      "[bold white on blue] LOW [/bold white on blue]",
    "info":     "[bold white on grey50] INFO [/bold white on grey50]",
}

def render_findings_table(findings: list[dict]) -> Table:
    """
    findings = [
      {"id": 1, "service": "ftp", "port": 21, "finding": "VSFTPD 2.3.4 backdoor", 
       "severity": "critical", "cve": "CVE-2011-2523"},
      ...
    ]
    """
    table = Table(
        title="[bold cyan]Enumeration Findings[/bold cyan]",
        border_style="cyan",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Severity", justify="center", min_width=12)
    table.add_column("Service:Port", style="cyan", min_width=15)
    table.add_column("Finding", style="white", min_width=35)
    table.add_column("CVE", style="bold red", min_width=15)

    for f in findings:
        badge = SEVERITY_BADGE.get(f["severity"].lower(), f["severity"])
        table.add_row(
            badge,
            f"{f['service']}:{f['port']}",
            f["finding"],
            f.get("cve") or "—"
        )
    return table
```

---

### Component 6: Exploitation Status Panel

```python
from rich.panel import Panel

def render_exploit_status(module: str, target: str, port: int, success: bool, session_id: int = None, error: str = None) -> None:
    if success:
        content = (
            f"[dim white]Module:[/dim white] [bold cyan]{module}[/bold cyan]\n"
            f"[dim white]Target:[/dim white] [white]{target}:{port}[/white]\n"
            f"[bold green]>> EXPLOIT SUCCESS — Session ID: {session_id}[/bold green]"
        )
        border = "green"
        title = "[bold green]EXPLOITATION AGENT — SUCCESS[/bold green]"
    else:
        content = (
            f"[dim white]Module:[/dim white] [bold cyan]{module}[/bold cyan]\n"
            f"[dim white]Target:[/dim white] [white]{target}:{port}[/white]\n"
            f"[bold red]>> EXPLOIT FAILED: {error}[/bold red]"
        )
        border = "red"
        title = "[bold red]EXPLOITATION AGENT — FAILED[/bold red]"
    
    print(Panel(content, title=title, border_style=border, padding=(0, 1)))
```

---

### Component 7: Progress Spinner (Long-Running Tasks)

```python
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

def get_progress_spinner(task_name: str):
    """Use as context manager during nmap, linpeas, etc."""
    return Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn("[white]{task.description}"),
        TimeElapsedColumn(),
    )

# Usage:
# with get_progress_spinner("nmap scan") as progress:
#     task = progress.add_task("Running nmap on 192.168.56.101...", total=None)
#     result = run_nmap(target)
#     progress.remove_task(task)
```

---

### Component 8: Error Panel

```python
from rich.panel import Panel

def render_error(title: str, message: str, fix: str = None) -> None:
    content = f"[bold red]{message}[/bold red]"
    if fix:
        content += f"\n\n[dim white]Fix:[/dim white] [yellow]{fix}[/yellow]"
    
    print(Panel(
        content,
        title=f"[bold red]ERROR: {title}[/bold red]",
        border_style="red",
        padding=(0, 1)
    ))

# Example:
# render_error("Tool Not Found", "nmap not found in PATH", fix="sudo apt install nmap")
```

---

### Component 9: Success Banner

```python
from rich.panel import Panel

def render_success_banner(message: str, detail: str = None) -> None:
    content = f"[bold green]{message}[/bold green]"
    if detail:
        content += f"\n[dim white]{detail}[/dim white]"
    print(Panel(content, border_style="green", padding=(0, 1)))
```

---

### Component 10: Status Table (spidr status)

```python
from rich.table import Table

def render_status_table(runs: list[dict]) -> Table:
    """
    runs = [
      {"target": "192.168.56.101", "phase": "post_exploit", 
       "findings": 7, "sessions": 1, "timestamp": "2026-04-17 14:32"}
    ]
    """
    table = Table(
        title="[bold white]SPIDR Run Status[/bold white]",
        border_style="bright_black",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Target IP", style="cyan", min_width=16)
    table.add_column("Last Phase", style="white", min_width=14)
    table.add_column("Findings", justify="right", style="yellow", min_width=10)
    table.add_column("Sessions", justify="right", style="green", min_width=10)
    table.add_column("Last Run", style="dim white", min_width=18)

    for run in runs:
        table.add_row(
            run["target"],
            run["phase"],
            str(run["findings"]),
            str(run["sessions"]),
            run["timestamp"]
        )
    return table
```

---

## 5. Log Stream Format

Every agent action is printed as a single log line to the terminal (in addition to file logging):

```python
from datetime import datetime
from rich import print

def log_action(agent: str, message: str, level: str = "info") -> None:
    timestamp = datetime.now().strftime("%H:%M:%S")
    agent_color = AGENT_COLORS.get(agent, "white")
    level_color = {"info": "white", "warning": "yellow", "error": "red", "success": "green"}.get(level, "white")
    
    print(
        f"[dim white]{timestamp}[/dim white] "
        f"[{agent_color}][{agent.upper()}][/{agent_color}] "
        f"[{level_color}]{message}[/{level_color}]"
    )

# Output: 14:32:01 [RECON] Running nmap -sV -sC on 192.168.56.101...
```

---

## 6. Report HTML/CSS Design System

The pentest report rendered by the Reporting Agent follows these visual rules.

### Color Palette (Report)

```css
:root {
    --color-bg: #0d1117;           /* Dark background */
    --color-surface: #161b22;       /* Card background */
    --color-border: #30363d;        /* Subtle borders */
    --color-text: #c9d1d9;          /* Body text */
    --color-heading: #f0f6fc;       /* Headings */
    --color-critical: #f85149;      /* Critical severity */
    --color-high: #e3973e;          /* High severity */
    --color-medium: #d29922;        /* Medium severity */
    --color-low: #388bfd;           /* Low severity */
    --color-info: #8b949e;          /* Info/muted */
    --color-success: #3fb950;       /* Success states */
    --color-accent: #58a6ff;        /* Links, highlights */
    --color-code-bg: #1c2128;       /* Code block background */
}
```

### Typography (Report)

```css
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
    font-size: 14px;
    line-height: 1.6;
    color: var(--color-text);
    background: var(--color-bg);
}

h1 { font-size: 28px; font-weight: 700; color: var(--color-heading); }
h2 { font-size: 20px; font-weight: 600; color: var(--color-heading); border-bottom: 1px solid var(--color-border); padding-bottom: 8px; }
h3 { font-size: 16px; font-weight: 600; color: var(--color-heading); }

code {
    font-family: "Fira Code", "Consolas", monospace;
    font-size: 12px;
    background: var(--color-code-bg);
    padding: 2px 6px;
    border-radius: 4px;
}
```

### Severity Badge CSS

```css
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.badge-critical { background: var(--color-critical); color: #fff; }
.badge-high     { background: var(--color-high); color: #fff; }
.badge-medium   { background: var(--color-medium); color: #000; }
.badge-low      { background: var(--color-low); color: #fff; }
.badge-info     { background: var(--color-info); color: #fff; }
```

### Finding Card Structure

Each vulnerability in the report renders as a card:

```html
<div class="finding-card" id="finding-001">
    <div class="finding-header">
        <span class="badge badge-critical">CRITICAL</span>
        <h3>VSFTPD 2.3.4 Backdoor (CVE-2011-2523)</h3>
        <span class="cvss-score">CVSS 10.0</span>
    </div>
    <div class="finding-body">
        <div class="finding-meta">
            <span>Service: FTP | Port: 21 | ATT&CK: T1190</span>
        </div>
        <h4>Description</h4>
        <p>...</p>
        <h4>Evidence</h4>
        <code>...</code>
        <h4>Recommendation</h4>
        <p>...</p>
    </div>
</div>
```

---

## 7. Accessibility (CLI)

- All critical information conveyed by text, not color alone (icons used alongside color: ✓ / ✗ / ⚠)
- `SPIDR_NO_RICH=true` env var disables all Rich formatting for screen readers and log file output
- Error messages always include the specific action that failed and how to fix it

---

## 8. State Indicator Patterns

### Running Agent Indicator
```
[14:32:01] [RECON] Running nmap -sV -sC on 192.168.56.101...  ⠸ (0:00:12)
```

### Agent Complete Indicator
```
[14:34:22] [RECON] ✓ Complete — 23 ports found in 2m 21s
```

### Skipped Phase Indicator
```
[14:34:23] [SYSTEM] ⚠ Skipping exploitation — msfrpcd not available
```

### Pipeline Complete Indicator
```
╔══════════════════════════════════════════════════╗
║  ✓ SPIDR run complete — 192.168.56.101           ║
║  Findings: 7  |  Sessions: 1  |  Root: YES       ║
║  Report: ./reports/2026-04-17_192.168.56.101.pdf ║
╚══════════════════════════════════════════════════╝
```
