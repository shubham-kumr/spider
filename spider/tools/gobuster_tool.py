"""
SPIDER — gobuster Tool Wrapper
Runs gobuster dir against HTTP/HTTPS targets, returns discovered paths.
"""

from __future__ import annotations

import subprocess
import shutil
import re


class ToolNotFoundError(Exception):
    pass


# Default wordlist (gobuster built-in fallback)
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
FALLBACK_WORDLIST = "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt"


def _check_gobuster() -> None:
    if not shutil.which("gobuster"):
        raise ToolNotFoundError(
            "gobuster not found in PATH. Install with: sudo apt install gobuster"
        )


def run_gobuster(
    target_url: str,
    wordlist: str = None,
    extensions: str = "php,html,txt,bak",
    timeout: int = 120,
) -> list[dict]:
    """
    Run gobuster dir against a URL, return list of discovered paths.
    
    Returns:
        List of dicts: {path, status_code, size, redirect}
    """
    _check_gobuster()

    # Find a working wordlist
    wl = wordlist or _find_wordlist()
    if not wl:
        return [{"path": "/", "status_code": 0, "size": 0, "note": "No wordlist found — gobuster skipped"}]

    cmd = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", wl,
        "-x", extensions,
        "--no-progress",
        "--quiet",
        "-t", "20",
        "--timeout", "10s",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return _parse_gobuster_output(result.stdout)
    except subprocess.TimeoutExpired:
        return [{"path": "timeout", "status_code": 0, "size": 0, "note": "gobuster timed out"}]
    except Exception as e:
        return [{"path": "error", "status_code": 0, "size": 0, "note": str(e)}]


def _find_wordlist() -> str | None:
    """Find a usable wordlist on the system."""
    candidates = [
        DEFAULT_WORDLIST,
        FALLBACK_WORDLIST,
        "/usr/share/wordlists/dirb/small.txt",
        "/opt/useful/SecLists/Discovery/Web-Content/common.txt",
    ]
    for wl in candidates:
        import os
        if os.path.exists(wl):
            return wl
    return None


def _parse_gobuster_output(output: str) -> list[dict]:
    """
    Parse gobuster stdout lines like:
    /admin                (Status: 301) [Size: 311] [--> http://...]
    """
    results = []
    pattern = re.compile(
        r"(/\S*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\](?:\s+\[-->\s*(\S+)\])?"
    )
    for line in output.splitlines():
        m = pattern.search(line)
        if m:
            results.append({
                "path": m.group(1),
                "status_code": int(m.group(2)),
                "size": int(m.group(3)),
                "redirect": m.group(4) or "",
            })
    return results
