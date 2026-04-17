"""
SPIDER — Enumeration Agent
Deep service enumeration using gobuster, nikto, enum4linux, banner grabs.
LLM interprets raw output and tags CVE findings.
"""

from __future__ import annotations

from spider.agents.orchestrator import SpiderState
from spider.state.store import StateStore
from spider.config import SPIDER_DB_PATH
from spider.ui.display import log_action, render_findings_table
from spider.llm.client import call_qwen_json
from spider.llm.prompts import (
    ENUM_INTERPRETATION_SYSTEM_PROMPT,
    ENUM_INTERPRETATION_USER_PROMPT,
)


def _interpret_with_llm(tool_name: str, target_ip: str, port: int, raw_output: str) -> list[dict]:
    """
    Call Qwen to interpret raw tool output and produce structured findings.
    Returns list of finding dicts. Falls back to empty list on failure.
    """
    if not raw_output.strip() or len(raw_output) < 10:
        return []

    # Truncate to avoid token limits (keep first 3000 chars)
    truncated = raw_output[:3000]

    user_prompt = ENUM_INTERPRETATION_USER_PROMPT.format(
        tool_name=tool_name,
        target_ip=target_ip,
        port=port,
        raw_output=truncated,
    )

    try:
        result = call_qwen_json(ENUM_INTERPRETATION_SYSTEM_PROMPT, user_prompt, max_tokens=1500)
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return [result]
        return []
    except Exception as e:
        log_action("enumeration", f"LLM interpretation failed for {tool_name}:{port}: {e}", "warning")
        return []


def enumeration_agent(state: SpiderState) -> SpiderState:
    """
    Enumeration Agent node.
    
    Runs tools selectively based on open ports:
    - FTP (21): banner grab — detect vsftpd version
    - HTTP (80, 8080, etc.): nikto + gobuster
    - HTTPS (443): nikto with SSL
    - SMB (139, 445): enum4linux
    - Other services: banner grab
    
    All raw output sent to Qwen for CVE tagging.
    """
    store = StateStore(db_path=SPIDER_DB_PATH)
    store.update_phase(state["run_id"], "enumerate")

    log_action("enumeration", "Starting deep service enumeration...", "info")

    ports = state["open_ports"]
    target_ip = state["target_ip"]
    all_findings: list[dict] = []

    # Categorize ports
    http_ports = [p for p in ports if p.get("service") in ("http", "http-alt", "www") or p.get("port") in (80, 8080, 8000, 8888)]
    https_ports = [p for p in ports if p.get("service") in ("https", "ssl/http") or p.get("port") in (443, 8443)]
    ftp_ports = [p for p in ports if p.get("service") == "ftp" or p.get("port") == 21]
    smb_ports = [p for p in ports if p.get("service") in ("netbios-ssn", "microsoft-ds", "smb") or p.get("port") in (139, 445)]
    ssh_ports = [p for p in ports if p.get("service") == "ssh" or p.get("port") == 22]

    # ── FTP Enumeration ───────────────────────────────────────────
    for p in ftp_ports:
        port_num = p["port"]
        log_action("enumeration", f"FTP banner grab on port {port_num}...", "info")
        try:
            from spider.tools.nikto_tool import grab_ftp_banner
            banner = grab_ftp_banner(target_ip, port_num)
            if banner:
                log_action("enumeration", f"FTP banner: {banner[:80]}", "info")
                raw = f"FTP Service Banner:\n{banner}\n\nVersion from nmap: {p.get('version','')}"
                findings = _interpret_with_llm("ftp-banner", target_ip, port_num, raw)
                all_findings.extend(findings)
        except Exception as e:
            log_action("enumeration", f"FTP banner grab failed: {e}", "warning")

    # ── HTTP Enumeration ──────────────────────────────────────────
    for p in http_ports:
        port_num = p["port"]
        log_action("enumeration", f"Running nikto on HTTP port {port_num}...", "info")
        try:
            from spider.tools.nikto_tool import run_nikto
            with __import__("spider.ui.display", fromlist=["get_progress_spinner"]).get_progress_spinner() as progress:
                task = progress.add_task(f"[cyan]nikto http://{target_ip}:{port_num}...", total=None)
                nikto_out = run_nikto(target_ip, port=port_num, ssl=False)
                progress.remove_task(task)

            if nikto_out.strip():
                findings = _interpret_with_llm("nikto", target_ip, port_num, nikto_out)
                all_findings.extend(findings)
        except Exception as e:
            log_action("enumeration", f"nikto failed on port {port_num}: {e}", "warning")

        # gobuster
        log_action("enumeration", f"Running gobuster on http://{target_ip}:{port_num}...", "info")
        try:
            from spider.tools.gobuster_tool import run_gobuster
            paths = run_gobuster(f"http://{target_ip}:{port_num}")
            if paths:
                gb_text = f"gobuster found {len(paths)} paths:\n"
                gb_text += "\n".join(f"{p2['path']} [{p2['status_code']}]" for p2 in paths[:20])
                findings = _interpret_with_llm("gobuster", target_ip, port_num, gb_text)
                all_findings.extend(findings)
        except Exception as e:
            log_action("enumeration", f"gobuster failed: {e}", "warning")

    # ── HTTPS Enumeration ─────────────────────────────────────────
    for p in https_ports:
        port_num = p["port"]
        log_action("enumeration", f"Running nikto on HTTPS port {port_num}...", "info")
        try:
            from spider.tools.nikto_tool import run_nikto
            nikto_out = run_nikto(target_ip, port=port_num, ssl=True)
            if nikto_out.strip():
                findings = _interpret_with_llm("nikto-ssl", target_ip, port_num, nikto_out)
                all_findings.extend(findings)
        except Exception as e:
            log_action("enumeration", f"nikto SSL failed on port {port_num}: {e}", "warning")

    # ── SMB Enumeration ───────────────────────────────────────────
    if smb_ports:
        log_action("enumeration", f"Running enum4linux on {target_ip}...", "info")
        try:
            from spider.tools.enum4linux_tool import run_enum4linux, parse_enum4linux
            with __import__("spider.ui.display", fromlist=["get_progress_spinner"]).get_progress_spinner() as progress:
                task = progress.add_task(f"[cyan]enum4linux {target_ip}...", total=None)
                raw = run_enum4linux(target_ip)
                progress.remove_task(task)

            parsed = parse_enum4linux(raw)
            summary = (
                f"SMB Enumeration Results:\n"
                f"Users found: {', '.join(parsed['users']) or 'none'}\n"
                f"Shares: {', '.join(s['name'] for s in parsed['shares']) or 'none'}\n"
                f"OS: {parsed['os_info'] or 'unknown'}\n"
                f"Workgroup: {parsed['workgroup'] or 'unknown'}\n\n"
                f"Raw output excerpt:\n{raw[:2000]}"
            )
            findings = _interpret_with_llm("enum4linux", target_ip, 445, summary)
            all_findings.extend(findings)
        except Exception as e:
            log_action("enumeration", f"enum4linux failed: {e}", "warning")

    # ── SSH Banner ────────────────────────────────────────────────
    for p in ssh_ports:
        port_num = p["port"]
        version_str = p.get("version", "") or p.get("banner", "")
        if version_str:
            raw = f"SSH service on port {port_num}:\nBanner: {version_str}\nVersion: {p.get('product','')} {version_str}"
            findings = _interpret_with_llm("ssh-banner", target_ip, port_num, raw)
            all_findings.extend(findings)

    # ── Deduplicate + Normalize ───────────────────────────────────
    all_findings = _normalize_findings(all_findings)

    # ── Store findings ────────────────────────────────────────────
    for finding in all_findings:
        try:
            store.add_finding(state["run_id"], finding)
        except Exception as e:
            log_action("enumeration", f"Failed to store finding: {e}", "warning")

    # ── Display results ───────────────────────────────────────────
    if all_findings:
        try:
            from rich.console import Console
            console = Console()
            table = render_findings_table(all_findings)
            console.print(table)
        except Exception:
            pass

    critical_count = sum(1 for f in all_findings if f.get("severity") == "critical")
    high_count = sum(1 for f in all_findings if f.get("severity") == "high")
    log_action(
        "enumeration",
        f"✓ Complete — {len(all_findings)} findings ({critical_count} critical, {high_count} high)",
        "success",
    )

    return {
        **state,
        "findings": all_findings,
        "attack_chain": state["attack_chain"] + [
            f"Enum: {len(all_findings)} findings ({critical_count} critical)"
        ],
    }


def _normalize_findings(findings: list[dict]) -> list[dict]:
    """
    Normalize and deduplicate findings list.
    Ensures required fields exist with defaults.
    """
    seen_titles = set()
    normalized = []

    for f in findings:
        if not isinstance(f, dict):
            continue

        title = f.get("title", "Unknown Finding")
        if title in seen_titles:
            continue
        seen_titles.add(title)

        normalized.append({
            "agent": "enumeration",
            "service": f.get("service", "unknown"),
            "port": f.get("port"),
            "title": title,
            "description": f.get("description", ""),
            "severity": _normalize_severity(f.get("severity", "info")),
            "cvss_score": _safe_float(f.get("cvss_score")),
            "cve_id": f.get("cve_id") or None,
            "attack_tactic": f.get("attack_tactic") or None,
            "attack_technique": f.get("attack_technique") or None,
            "evidence": f.get("evidence", ""),
            "recommendation": f.get("recommendation", ""),
            "exploitable": False,
        })

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    normalized.sort(key=lambda x: sev_order.get(x["severity"], 5))

    return normalized


def _normalize_severity(sev: str) -> str:
    sev = str(sev).lower().strip()
    if sev in ("critical", "high", "medium", "low", "info"):
        return sev
    return "info"


def _safe_float(val) -> float | None:
    try:
        return float(val)
    except (TypeError, ValueError):
        return None
