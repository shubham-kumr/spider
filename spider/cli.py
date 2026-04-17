"""
SPIDER — CLI Entry Point
Click-based CLI with run, status, report, preflight, and clean commands.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import click

from spider import __version__
from spider.config import SPIDER_DB_PATH, REPORT_DIR, SPIDER_VERSION
from spider.ui.display import (
    render_banner,
    render_preflight,
    render_status_table,
    render_error,
    render_success_banner,
    log_action,
)


# ── Pre-flight check helpers ──────────────────────────────────────────────────

def _check_tools() -> list[dict]:
    """Check that all required CLI tools are in PATH."""
    tools = [
        {"tool": "nmap",       "install": "sudo apt install nmap"},
        {"tool": "gobuster",   "install": "sudo apt install gobuster"},
        {"tool": "nikto",      "install": "sudo apt install nikto"},
        {"tool": "enum4linux", "install": "sudo apt install enum4linux"},
    ]
    results = []
    for t in tools:
        path = shutil.which(t["tool"])
        if path:
            # Try to get version
            import subprocess
            try:
                ver_out = subprocess.run(
                    [t["tool"], "--version"],
                    capture_output=True, text=True, timeout=5
                )
                note = (ver_out.stdout or ver_out.stderr or "").splitlines()[0][:40] if path else "not found"
            except Exception:
                note = "found"
            results.append({"name": t["tool"], "status": True, "note": note})
        else:
            results.append({
                "name": t["tool"],
                "status": False,
                "note": f"Install: {t['install']}",
            })
    return results


def _check_api_key() -> dict:
    from spider.config import TOGETHER_API_KEY
    if TOGETHER_API_KEY and len(TOGETHER_API_KEY) > 10:
        return {"name": "Together AI API key", "status": True, "note": f"...{TOGETHER_API_KEY[-6:]}"}
    return {"name": "Together AI API key", "status": False, "note": "Set TOGETHER_API_KEY in .env"}


def _check_msfrpcd() -> dict:
    from spider.tools.msf_tool import check_msfrpcd
    from spider.config import MSF_RPC_HOST, MSF_RPC_PORT
    ok = check_msfrpcd()
    if ok:
        return {"name": "msfrpcd", "status": True, "note": f"{MSF_RPC_HOST}:{MSF_RPC_PORT}"}
    return {
        "name": "msfrpcd",
        "status": False,
        "note": f"Start with: msfrpcd -P <pass> -S -a 127.0.0.1",
    }


def _check_target(target_ip: str) -> dict:
    from spider.tools.nmap_tool import check_host_up
    try:
        ok = check_host_up(target_ip)
        return {
            "name": f"Target {target_ip} reachable",
            "status": ok,
            "note": "ping OK" if ok else "Target unreachable",
        }
    except Exception as e:
        return {"name": f"Target {target_ip}", "status": False, "note": str(e)}


def _run_preflight_checks(target_ip: str = None) -> tuple[list[dict], bool]:
    """Run all pre-flight checks. Returns (checks, all_passed)."""
    checks = _check_tools()
    checks.append(_check_api_key())
    if target_ip:
        checks.append(_check_target(target_ip))
    msf_check = _check_msfrpcd()
    checks.append(msf_check)
    all_critical_pass = all(
        c["status"] for c in checks
        if c["name"] not in ("msfrpcd",)  # msfrpcd optional
    )
    return checks, all_critical_pass


# ── CLI commands ──────────────────────────────────────────────────────────────

@click.group()
@click.version_option(version=SPIDER_VERSION, prog_name="spider")
def main():
    """
    SPIDER — System for Penetration Testing, Intelligence, Discovery, Exploit & Recon

    An AI-driven multi-agent offensive security framework for controlled lab environments.

    \b
    ETHICAL USE ONLY — Only run against systems you own or have explicit written permission to test.
    """
    pass


@main.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target IP address (e.g. 192.168.56.101)",
)
@click.option(
    "--start-from",
    default="recon",
    type=click.Choice(["recon", "enumerate", "exploit", "post_exploit", "report"]),
    help="Resume pipeline from a specific phase",
    show_default=True,
)
@click.option(
    "--skip-preflight",
    is_flag=True,
    default=False,
    help="Skip pre-flight checks (not recommended)",
)
def run(target: str, start_from: str, skip_preflight: bool):
    """
    Run the full SPIDER pipeline against a target.

    \b
    Examples:
      spider run --target 192.168.56.101
      spider run --target 192.168.56.101 --start-from enumerate
    """
    render_banner(target_ip=target, version=SPIDER_VERSION)

    # ── Pre-flight checks ─────────────────────────────────────────
    if not skip_preflight:
        log_action("system", "Running pre-flight checks...", "info")
        checks, all_pass = _run_preflight_checks(target)
        render_preflight(checks)

        # API key is critical
        api_check = next((c for c in checks if "API key" in c["name"]), None)
        if api_check and not api_check["status"]:
            render_error(
                "API Key Missing",
                "TOGETHER_API_KEY not found in .env",
                fix="Copy .env.example to .env and fill in your Together AI key",
            )
            sys.exit(1)

        # Target must be reachable
        target_check = next((c for c in checks if "reachable" in c["name"]), None)
        if target_check and not target_check["status"]:
            render_error(
                "Target Unreachable",
                f"Cannot reach {target}",
                fix="Ensure VirtualBox host-only or NAT adapter is configured",
            )
            sys.exit(1)

        # Check if msfrpcd is available
        msf_check = next((c for c in checks if c["name"] == "msfrpcd"), None)
        msfrpcd_available = msf_check["status"] if msf_check else False

        if not msfrpcd_available:
            log_action("system", "msfrpcd not available — exploitation phase will be skipped", "warning")
    else:
        msfrpcd_available = False
        log_action("system", "Pre-flight checks skipped", "warning")

    # ── Initialize database and run state ────────────────────────
    from spider.state.store import StateStore
    from spider.agents.orchestrator import build_graph, build_initial_state

    store = StateStore(db_path=SPIDER_DB_PATH)

    # Handle resume from phase
    existing_ports = []
    existing_findings = []

    if start_from != "recon":
        prior_run = store.get_run_by_ip(target)
        if prior_run:
            log_action("system", f"Resuming from {start_from} using prior run ID {prior_run.id}", "info")
            existing_ports = store.get_open_ports(prior_run.id)
            existing_findings = store.get_findings(prior_run.id)
        else:
            log_action("system", f"No prior run found for {target} — starting from recon", "warning")
            start_from = "recon"

    run_id = store.create_run(target)
    log_action("system", f"Run ID: {run_id} | Target: {target}", "info")

    # ── Build and invoke the LangGraph pipeline ───────────────────
    graph = build_graph()
    initial_state = build_initial_state(
        run_id=run_id,
        target_ip=target,
        msfrpcd_available=msfrpcd_available,
        start_from=start_from,
        existing_ports=existing_ports,
        existing_findings=existing_findings,
    )

    try:
        final_state = graph.invoke(initial_state)
        if final_state.get("report_path"):
            log_action("system", f"Done! Report: {final_state['report_path']}", "success")
        if final_state.get("error_log"):
            log_action("system", f"Errors during run: {len(final_state['error_log'])}", "warning")
            for err in final_state["error_log"]:
                click.echo(f"  ! {err}")
    except KeyboardInterrupt:
        log_action("system", "Interrupted by user — saving state...", "warning")
        store.fail_run(run_id)
        render_success_banner(
            "Run interrupted",
            detail=f"Resume with: spider run --target {target} --start-from <phase>",
        )
        sys.exit(0)
    except Exception as e:
        render_error("Pipeline Error", str(e), fix="Check logs/ for details")
        store.fail_run(run_id)
        sys.exit(1)


@main.command()
def status():
    """Show status of all SPIDER runs."""
    render_banner()
    from spider.state.store import StateStore
    store = StateStore(db_path=SPIDER_DB_PATH)
    runs = store.get_all_runs()
    render_status_table(runs)


@main.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target IP address for which to regenerate the report",
)
def report(target: str):
    """Regenerate the pentest report for a target from stored findings."""
    render_banner(target_ip=target)

    from spider.state.store import StateStore
    from spider.agents.reporting import reporting_agent
    from spider.agents.orchestrator import build_initial_state

    store = StateStore(db_path=SPIDER_DB_PATH)
    prior_run = store.get_run_by_ip(target)

    if not prior_run:
        render_error(
            "No Data Found",
            f"No prior run found for {target}",
            fix=f"Run: spider run --target {target}",
        )
        sys.exit(1)

    run_id = prior_run.id
    log_action("reporting", f"Regenerating report for {target} (Run ID: {run_id})", "info")

    existing_ports = store.get_open_ports(run_id)
    existing_findings = store.get_findings(run_id)
    privesc_vectors = store.get_privesc_vectors(run_id)

    state = build_initial_state(
        run_id=run_id,
        target_ip=target,
        existing_ports=existing_ports,
        existing_findings=existing_findings,
    )
    state["privesc_vectors"] = privesc_vectors

    final_state = reporting_agent(state)

    if final_state.get("report_path"):
        render_success_banner("Report regenerated!", detail=f"Path: {final_state['report_path']}")
    else:
        render_error("Report Failed", "Report generation encountered errors")
        sys.exit(1)


@main.command()
@click.option(
    "--target", "-t",
    default=None,
    help="Target IP to test reachability (optional)",
)
def preflight(target: str):
    """Run pre-flight checks only (no scanning)."""
    render_banner()
    log_action("system", "Running pre-flight checks...", "info")
    checks, all_pass = _run_preflight_checks(target)
    render_preflight(checks)

    if all_pass:
        render_success_banner("All critical checks passed — ready to run SPIDER!")
    else:
        render_error("Pre-flight Failed", "One or more critical checks failed — fix before running")
        sys.exit(1)


@main.command()
@click.option(
    "--target", "-t",
    default=None,
    help="Clear data for a specific target IP only",
)
@click.confirmation_option(prompt="This will delete all stored run data. Continue?")
def clean(target: str):
    """Clear SPIDER state database (all runs or specific target)."""
    from spider.state.store import StateStore
    store = StateStore(db_path=SPIDER_DB_PATH)

    if target:
        run = store.get_run_by_ip(target)
        if run:
            store.clear_run_data(run.id)
            log_action("system", f"Cleared data for {target}", "success")
        else:
            log_action("system", f"No data found for {target}", "warning")
    else:
        # Delete the entire DB file
        db_path = Path(SPIDER_DB_PATH)
        if db_path.exists():
            db_path.unlink()
            log_action("system", f"Cleared database: {SPIDER_DB_PATH}", "success")
        else:
            log_action("system", "Database not found — nothing to clean", "warning")


if __name__ == "__main__":
    main()
