"""
SPIDER — Reporting Agent
Pulls all findings from SQLite, generates executive summary via LLM,
renders Jinja2 HTML report, converts to PDF via weasyprint.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from spider.agents.orchestrator import SpiderState
from spider.state.store import StateStore
from spider.config import SPIDER_DB_PATH, REPORT_DIR
from spider.ui.display import log_action, render_success_banner
from spider.llm.client import call_qwen
from spider.llm.prompts import EXEC_SUMMARY_SYSTEM_PROMPT, EXEC_SUMMARY_USER_PROMPT


def _build_report_context(
    store: StateStore,
    run_id: int,
    target_ip: str,
    attack_chain: list,
    start_time: datetime,
) -> dict:
    """Build the full Jinja2 template context from SQLite data."""
    findings = store.get_findings(run_id)
    open_ports = store.get_open_ports(run_id)
    sessions = store.get_active_sessions(run_id)
    privesc_vectors = store.get_privesc_vectors(run_id)
    credentials = store.get_credentials(run_id)
    sev_counts = store.count_findings_by_severity(run_id)

    run_date = datetime.utcnow().strftime("%Y-%m-%d")
    duration = int((datetime.utcnow() - start_time).total_seconds() / 60) if start_time else 0
    root_achieved = any(v.get("root_achieved") for v in privesc_vectors)

    # Number findings for display
    numbered_findings = []
    for i, f in enumerate(findings, 1):
        f["display_id"] = f"SPIDER-{i:03d}"
        numbered_findings.append(f)

    # Build top findings for LLM summary
    top_findings_text = "\n".join(
        f"- [{f.get('severity','?').upper()}] {f.get('title','?')} "
        f"(CVE: {f.get('cve_id','N/A')}, CVSS: {f.get('cvss_score','N/A')})"
        for f in findings[:5]
    )

    return {
        "target_ip": target_ip,
        "run_date": run_date,
        "run_duration_minutes": duration,
        "findings": numbered_findings,
        "open_ports": open_ports,
        "sessions_opened": len(sessions),
        "root_achieved": root_achieved,
        "credentials": credentials,
        "privesc_vectors": privesc_vectors,
        "attack_chain_summary": attack_chain,
        "sev_counts": sev_counts,
        "finding_count": len(findings),
        # LLM summary injected later
        "executive_summary": "",
        # For LLM prompt
        "_top_findings_text": top_findings_text,
        "_sev_counts": sev_counts,
    }


def _generate_executive_summary(context: dict) -> str:
    """Call Qwen to generate an executive summary paragraph."""
    sev = context["_sev_counts"]
    user_prompt = EXEC_SUMMARY_USER_PROMPT.format(
        target_ip=context["target_ip"],
        run_date=context["run_date"],
        duration_minutes=context["run_duration_minutes"],
        critical_count=sev.get("critical", 0),
        high_count=sev.get("high", 0),
        medium_count=sev.get("medium", 0),
        low_count=sev.get("low", 0),
        top_findings=context["_top_findings_text"] or "No findings.",
        attack_chain="\n".join(f"- {step}" for step in context["attack_chain_summary"]),
        root_achieved=context["root_achieved"],
        sessions_opened=context["sessions_opened"],
    )

    try:
        summary = call_qwen(
            EXEC_SUMMARY_SYSTEM_PROMPT,
            user_prompt,
            max_tokens=600,
            temperature=0.3,
        )
        return summary.strip()
    except Exception as e:
        log_action("reporting", f"LLM summary generation failed: {e}", "warning")
        return (
            f"This report summarizes a penetration test conducted against {context['target_ip']} "
            f"on {context['run_date']}. "
            f"A total of {context['finding_count']} findings were identified across the target, "
            f"including {context['_sev_counts'].get('critical', 0)} critical and "
            f"{context['_sev_counts'].get('high', 0)} high severity issues. "
            f"{'Root access was achieved during post-exploitation.' if context['root_achieved'] else 'Root access was not obtained.'} "
            f"Immediate remediation is recommended for all critical and high severity findings."
        )


def _render_html(context: dict, template_dir: str) -> str:
    """Render the Jinja2 HTML report template."""
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")
    return template.render(**context)


def _html_to_pdf(html_path: str, pdf_path: str) -> bool:
    """Convert HTML report to PDF using weasyprint. Returns True on success."""
    try:
        from weasyprint import HTML as WPHtml
        WPHtml(filename=html_path).write_pdf(pdf_path)
        return True
    except ImportError:
        log_action("reporting", "weasyprint not installed — PDF skipped. Install: pip install weasyprint", "warning")
        return False
    except Exception as e:
        log_action("reporting", f"PDF generation failed: {e}", "warning")
        return False


def reporting_agent(state: SpiderState) -> SpiderState:
    """
    Reporting Agent node.
    
    1. Pull all data from SQLite
    2. LLM generates executive summary
    3. Jinja2 renders HTML report
    4. weasyprint converts to PDF
    5. Saves to ./reports/
    """
    store = StateStore(db_path=SPIDER_DB_PATH)
    store.update_phase(state["run_id"], "report")

    log_action("reporting", "Building pentest report...", "info")

    # Ensure report directory exists
    report_dir = Path(REPORT_DIR)
    report_dir.mkdir(parents=True, exist_ok=True)

    # Template directory
    template_dir = str(Path(__file__).parent.parent / "templates")

    # Build context
    start_time = datetime.utcnow()  # Approximate — real start_time not in state
    context = _build_report_context(
        store=store,
        run_id=state["run_id"],
        target_ip=state["target_ip"],
        attack_chain=state["attack_chain"],
        start_time=start_time,
    )

    # Generate executive summary
    log_action("reporting", "Generating executive summary via LLM...", "info")
    context["executive_summary"] = _generate_executive_summary(context)

    # Render HTML
    log_action("reporting", "Rendering HTML report...", "info")
    timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H%M")
    safe_ip = state["target_ip"].replace(".", "-")
    base_name = f"{timestamp}_{safe_ip}"
    html_path = str(report_dir / f"{base_name}.html")
    pdf_path = str(report_dir / f"{base_name}.pdf")

    try:
        html_content = _render_html(context, template_dir)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        log_action("reporting", f"HTML report saved: {html_path}", "success")
    except Exception as e:
        log_action("reporting", f"HTML render failed: {e}", "error")
        store.complete_run(state["run_id"])
        return {
            **state,
            "error_log": state["error_log"] + [f"[REPORTING] HTML render failed: {e}"],
        }

    # Convert to PDF
    log_action("reporting", "Converting to PDF via weasyprint...", "info")
    pdf_ok = _html_to_pdf(html_path, pdf_path)

    final_path = pdf_path if pdf_ok else html_path

    # Mark run complete
    store.complete_run(state["run_id"])

    # Display success banner
    sev = context["_sev_counts"]
    root_str = "YES 🔴" if context["root_achieved"] else "NO"
    render_success_banner(
        f"SPIDER run complete — {state['target_ip']}",
        detail=(
            f"Findings: {context['finding_count']} "
            f"| Sessions: {context['sessions_opened']} "
            f"| Root: {root_str}\n"
            f"Report: {final_path}"
        ),
    )

    log_action("reporting", f"✓ Report generated: {final_path}", "success")

    return {
        **state,
        "report_path": final_path,
        "attack_chain": state["attack_chain"] + [f"Report: saved to {final_path}"],
    }
