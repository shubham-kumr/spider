"""
SPIDER — Orchestrator Agent
LangGraph StateGraph that drives the full pentest pipeline.
Calls Qwen LLM to decide next agent at each step.
"""

from __future__ import annotations

from typing import TypedDict, Optional

from langgraph.graph import StateGraph, END

from spider.llm.client import call_qwen_json
from spider.llm.prompts import ORCHESTRATOR_SYSTEM_PROMPT, ORCHESTRATOR_USER_PROMPT


# ── LangGraph State Definition ────────────────────────────────────────────────

class SpiderState(TypedDict):
    run_id: int
    target_ip: str
    open_ports: list           # Populated by Recon Agent
    findings: list             # Populated by Enumeration Agent
    sessions: list             # Populated by Exploitation Agent
    privesc_vectors: list      # Populated by Post-Exploit Agent
    credentials: list          # Populated by Post-Exploit Agent
    msfrpcd_available: bool    # Set during pre-flight
    next_agent: str            # Set by Orchestrator
    orchestrator_round: int    # Tracks orchestrator loop count
    orchestrator_reasoning: str  # LLM reasoning text
    report_path: Optional[str]   # Set by Reporting Agent on success
    error_log: list            # Accumulated errors across agents
    attack_chain: list         # Ordered log of completed phases


# ── Rule-based fallback (used when LLM fails) ────────────────────────────────

def _rule_based_decision(state: SpiderState) -> dict:
    """
    Deterministic next-agent decision when LLM is unavailable.
    Mirrors the rule set in APP_FLOW.md Decision Points.
    """
    if not state["open_ports"]:
        return {"next": "recon", "reason": "No port data — must scan first (rule-based fallback)"}

    if not state["findings"]:
        # Check if we already tried enumerating
        has_enumerated = any("Enum:" in chain for chain in state.get("attack_chain", []))
        if not has_enumerated:
            return {"next": "enumerate", "reason": "Ports found but no findings — enumerate services (rule-based fallback)"}

    # Check for critical/high findings
    critical_findings = [
        f for f in state["findings"]
        if f.get("severity") in ("critical", "high") and f.get("cve_id")
    ]

    if critical_findings and state["msfrpcd_available"] and not state["sessions"]:
        return {"next": "exploit", "reason": "Critical CVEs found and msfrpcd available — attempting exploitation (rule-based fallback)"}

    if state["sessions"] and not state["privesc_vectors"]:
        return {"next": "post_exploit", "reason": "Active session exists — escalating privileges (rule-based fallback)"}

    return {"next": "report", "reason": "All phases complete or exhausted — generating report (rule-based fallback)"}


# ── Orchestrator Node ─────────────────────────────────────────────────────────

def orchestrator_node(state: SpiderState) -> SpiderState:
    """
    Main orchestrator decision node.
    Calls Qwen LLM to analyze current state and decide next agent.
    Falls back to rule-based decisions on LLM failure.
    """
    from spider.ui.display import log_action, render_orchestrator_decision

    round_num = state.get("orchestrator_round", 0) + 1

    # ── Safety: max rounds guard ─────────────────────────────────
    if round_num > 10:
        log_action("orchestrator", "Max orchestrator rounds (10) reached — forcing report", "warning")
        return {
            **state,
            "orchestrator_round": round_num,
            "next_agent": "report",
            "orchestrator_reasoning": "Max rounds guard triggered",
        }

    # ── Build state summary for LLM ──────────────────────────────
    port_count = len(state["open_ports"])
    port_summary = ", ".join(
        f"{p.get('service','?')}:{p.get('port','?')}"
        for p in state["open_ports"][:5]
    ) if state["open_ports"] else "none"
    if len(state["open_ports"]) > 5:
        port_summary += f" +{port_count - 5} more"

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in state["findings"]:
        s = f.get("severity", "info")
        if s in sev_counts:
            sev_counts[s] += 1

    user_prompt = ORCHESTRATOR_USER_PROMPT.format(
        target_ip=state["target_ip"],
        port_count=port_count,
        port_summary=port_summary,
        finding_count=len(state["findings"]),
        critical_count=sev_counts["critical"],
        high_count=sev_counts["high"],
        session_count=len(state["sessions"]),
        privesc_count=len(state["privesc_vectors"]),
        msfrpcd_available=state["msfrpcd_available"],
    )

    # ── Call LLM (with rule-based fallback) ─────────────────────
    try:
        result = call_qwen_json(ORCHESTRATOR_SYSTEM_PROMPT, user_prompt)
        next_agent = result.get("next", "report")
        reason = result.get("reason", "LLM decision")
    except Exception as exc:
        error_msg = f"LLM decision failed: {exc} — using rule-based fallback"
        log_action("orchestrator", error_msg, "warning")
        fallback = _rule_based_decision(state)
        next_agent = fallback["next"]
        reason = fallback["reason"]

    # ── Validate LLM response ────────────────────────────────────
    valid_agents = {"recon", "enumerate", "exploit", "post_exploit", "report"}
    if next_agent not in valid_agents:
        log_action("orchestrator", f"LLM returned invalid agent '{next_agent}' — using rule-based fallback", "warning")
        fallback = _rule_based_decision(state)
        next_agent = fallback["next"]
        reason = fallback["reason"]

    render_orchestrator_decision(round_num, next_agent, reason)

    return {
        **state,
        "orchestrator_round": round_num,
        "next_agent": next_agent,
        "orchestrator_reasoning": reason,
    }


# ── Graph Builder ─────────────────────────────────────────────────────────────

def build_graph():
    """
    Build and compile the SPIDER LangGraph StateGraph.
    
    Returns:
        Compiled LangGraph app ready to invoke.
    """
    from spider.agents.recon import recon_agent
    from spider.agents.enumeration import enumeration_agent
    from spider.agents.exploitation import exploitation_agent
    from spider.agents.post_exploit import post_exploit_agent
    from spider.agents.reporting import reporting_agent

    graph = StateGraph(SpiderState)

    # Register all nodes
    graph.add_node("orchestrator", orchestrator_node)
    graph.add_node("recon", recon_agent)
    graph.add_node("enumerate", enumeration_agent)
    graph.add_node("exploit", exploitation_agent)
    graph.add_node("post_exploit", post_exploit_agent)
    graph.add_node("report", reporting_agent)

    # Entry point
    graph.set_entry_point("orchestrator")

    # Conditional edges FROM orchestrator → agent nodes
    graph.add_conditional_edges(
        "orchestrator",
        lambda s: s["next_agent"],
        {
            "recon":        "recon",
            "enumerate":    "enumerate",
            "exploit":      "exploit",
            "post_exploit": "post_exploit",
            "report":       "report",
        },
    )

    # All agents (except report) loop back to orchestrator
    for node in ["recon", "enumerate", "exploit", "post_exploit"]:
        graph.add_edge(node, "orchestrator")

    # Report is terminal
    graph.add_edge("report", END)

    return graph.compile()


def build_initial_state(
    run_id: int,
    target_ip: str,
    msfrpcd_available: bool = False,
    start_from: str = "recon",
    existing_ports: list = None,
    existing_findings: list = None,
) -> SpiderState:
    """
    Build the initial LangGraph state for a new or resumed run.
    """
    return SpiderState(
        run_id=run_id,
        target_ip=target_ip,
        open_ports=existing_ports or [],
        findings=existing_findings or [],
        sessions=[],
        privesc_vectors=[],
        credentials=[],
        msfrpcd_available=msfrpcd_available,
        next_agent=start_from,
        orchestrator_round=0,
        orchestrator_reasoning="",
        report_path=None,
        error_log=[],
        attack_chain=[],
    )
