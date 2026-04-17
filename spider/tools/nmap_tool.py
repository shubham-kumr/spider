"""
SPIDER — nmap Tool Wrapper
Runs nmap via subprocess, parses XML output using python-libnmap.
"""

from __future__ import annotations

import subprocess
import tempfile
import os
from pathlib import Path


class ToolNotFoundError(Exception):
    pass


class TargetUnreachableError(Exception):
    pass


def _check_nmap() -> None:
    import shutil
    if not shutil.which("nmap"):
        raise ToolNotFoundError(
            "nmap not found in PATH. Install with: sudo apt install nmap"
        )


def run_nmap(
    target_ip: str,
    ports: str = None,
    fast: bool = False,
) -> list[dict]:
    """
    Run nmap -sV -sC against target, parse XML, return list of open port dicts.
    
    Args:
        target_ip: Target IP address
        ports: Optional port range string (e.g. "21-100,443,8080")
        fast: If True, scan top 1000 ports faster (-F --min-rate 2000)
    
    Returns:
        List of dicts with keys: port, protocol, state, service, version,
        product, banner, extra_info
    
    Raises:
        ToolNotFoundError: nmap not in PATH
        TargetUnreachableError: target doesn't respond
    """
    _check_nmap()

    # Write XML output to a temp file
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False, prefix="spider_nmap_") as f:
        out_file = f.name

    try:
        cmd = ["nmap", "-sV", "-sC", f"--open", "-oX", out_file]

        if fast:
            cmd += ["-F", "--min-rate", "2000"]
        elif ports:
            cmd += ["-p", ports]
        else:
            cmd += ["-p-", "--min-rate", "1000"]

        cmd.append(target_ip)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=360,  # 6 minutes max
        )

        # Check if target was unreachable
        if "0 hosts up" in result.stdout or "Failed to resolve" in result.stdout:
            raise TargetUnreachableError(f"Target {target_ip} is not reachable")

        # Parse XML with python-libnmap
        try:
            from libnmap.parser import NmapParser
            report = NmapParser.parse_fromfile(out_file)
        except ImportError:
            # Fallback: parse raw grep output if libnmap not available
            return _parse_nmap_fallback(result.stdout)

        ports_found = []
        for host in report.hosts:
            if host.is_up():
                for svc in host.services:
                    if svc.state in ("open", "open|filtered"):
                        port_dict = {
                            "port": svc.port,
                            "protocol": svc.protocol or "tcp",
                            "state": svc.state,
                            "service": svc.service or "",
                            "version": svc.banner or "",
                            "product": svc.product or "",
                            "extra_info": svc.extrainfo or "",
                            "banner": svc.banner or "",
                        }
                        ports_found.append(port_dict)

        return ports_found

    except subprocess.TimeoutExpired:
        raise TargetUnreachableError(f"nmap timed out scanning {target_ip}")
    finally:
        # Cleanup temp file
        try:
            os.unlink(out_file)
        except OSError:
            pass


def _parse_nmap_fallback(stdout: str) -> list[dict]:
    """
    Minimal fallback parser for nmap stdout (grep format) when libnmap unavailable.
    Parses lines like: 21/tcp   open  ftp     vsftpd 2.3.4
    """
    import re
    ports = []
    pattern = re.compile(
        r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)"
    )
    for line in stdout.splitlines():
        m = pattern.match(line.strip())
        if m:
            ports.append({
                "port": int(m.group(1)),
                "protocol": m.group(2),
                "state": "open",
                "service": m.group(3),
                "version": m.group(4).strip(),
                "product": "",
                "extra_info": "",
                "banner": m.group(4).strip(),
            })
    return ports


def check_host_up(target_ip: str, timeout: int = 10) -> bool:
    """Quick ping / TCP connectivity test to see if target is reachable."""
    import platform
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    result = subprocess.run(
        ["ping", flag, "3", target_ip],
        capture_output=True,
        timeout=timeout,
    )
    return result.returncode == 0
