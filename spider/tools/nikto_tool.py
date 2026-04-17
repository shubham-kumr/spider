"""
SPIDER — nikto Tool Wrapper
Runs nikto web vulnerability scanner, parses text output.
"""

from __future__ import annotations

import subprocess
import shutil
import re


class ToolNotFoundError(Exception):
    pass


def _check_nikto() -> None:
    if not shutil.which("nikto"):
        raise ToolNotFoundError(
            "nikto not found in PATH. Install with: sudo apt install nikto"
        )


def run_nikto(target_ip: str, port: int = 80, ssl: bool = False, timeout: int = 180) -> str:
    """
    Run nikto against a web service, return raw output string.
    
    Args:
        target_ip: Target IP or hostname
        port: Web server port (default 80)
        ssl: Use SSL/TLS (for port 443)
        timeout: Max seconds to wait
    
    Returns:
        Raw nikto text output
    """
    _check_nikto()

    scheme = "https" if ssl else "http"
    target_url = f"{scheme}://{target_ip}:{port}"

    cmd = [
        "nikto",
        "-h", target_url,
        "-Format", "txt",
        "-nointeractive",
        "-timeout", "10",
    ]

    if ssl:
        cmd += ["-ssl"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return f"[nikto timeout after {timeout}s against {target_url}]"
    except Exception as e:
        return f"[nikto error: {e}]"


def extract_nikto_findings(raw_output: str) -> list[str]:
    """
    Extract individual finding lines from nikto raw output.
    Returns list of finding strings (lines starting with '+').
    """
    findings = []
    for line in raw_output.splitlines():
        line = line.strip()
        if line.startswith("+ "):
            findings.append(line[2:].strip())
    return findings


def grab_banner(target_ip: str, port: int, timeout: int = 10) -> str:
    """
    Simple TCP banner grab for non-HTTP services.
    Connects, reads up to 1024 bytes, returns banner string.
    """
    import socket
    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as sock:
            try:
                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                return banner
            except Exception:
                return ""
    except Exception as e:
        return f"[banner grab failed: {e}]"


def grab_ftp_banner(target_ip: str, port: int = 21, timeout: int = 10) -> str:
    """Grab FTP service banner and version string."""
    banner = grab_banner(target_ip, port, timeout)
    return banner
