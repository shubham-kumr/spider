"""
SPIDER — Recon Agent
Wraps nmap for port scanning and service/version detection.
Stores results in SQLite and updates LangGraph state.
"""

from __future__ import annotations

from spider.agents.orchestrator import SpiderState
from spider.state.store import StateStore
from spider.tools.nmap_tool import run_nmap, ToolNotFoundError, TargetUnreachableError
from spider.ui.display import log_action, render_ports_table
from spider.config import SPIDER_DB_PATH


def recon_agent(state: SpiderState) -> SpiderState:
    """
    Recon Agent node for LangGraph.
    
    Performs:
    1. nmap -sV -sC scan
    2. Parse results to structured dicts
    3. Store in open_ports table
    4. Print Rich ports table
    5. Return updated state
    """
    store = StateStore(db_path=SPIDER_DB_PATH)
    store.update_phase(state["run_id"], "recon")

    log_action("recon", f"Starting nmap scan against {state['target_ip']}...", "info")

    try:
        from spider.ui.display import get_progress_spinner
        from rich.console import Console
        console = Console()

        with get_progress_spinner() as progress:
            task = progress.add_task(f"[bold blue]nmap -sV -sC {state['target_ip']}...", total=None)
            ports = run_nmap(state["target_ip"])
            progress.remove_task(task)

    except ToolNotFoundError as e:
        error = f"[RECON] {e}"
        log_action("recon", str(e), "error")
        return {
            **state,
            "error_log": state["error_log"] + [error],
            "attack_chain": state["attack_chain"] + ["Recon: FAILED — nmap not found"],
        }

    except TargetUnreachableError as e:
        error = f"[RECON] Target unreachable: {e}"
        log_action("recon", str(e), "error")
        return {
            **state,
            "open_ports": [],
            "error_log": state["error_log"] + [error],
            "attack_chain": state["attack_chain"] + [f"Recon: FAILED — {e}"],
        }

    except Exception as e:
        error = f"[RECON] Unexpected error: {e}"
        log_action("recon", str(e), "error")
        return {
            **state,
            "open_ports": [],
            "error_log": state["error_log"] + [error],
            "attack_chain": state["attack_chain"] + [f"Recon: FAILED — {e}"],
        }

    if not ports:
        log_action("recon", "No open ports found on target", "warning")
        return {
            **state,
            "open_ports": [],
            "attack_chain": state["attack_chain"] + ["Recon: 0 ports found"],
        }

    # Store in SQLite
    try:
        store.add_open_ports(state["run_id"], ports)
    except Exception as e:
        log_action("recon", f"DB store error: {e}", "warning")

    # Render Rich table
    try:
        from rich.console import Console
        console = Console()
        table = render_ports_table(ports)
        console.print(table)
    except Exception:
        pass

    log_action("recon", f"✓ Complete — {len(ports)} open ports found", "success")

    return {
        **state,
        "open_ports": ports,
        "attack_chain": state["attack_chain"] + [f"Recon: {len(ports)} open ports found"],
    }
