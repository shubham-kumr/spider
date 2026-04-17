"""
SPIDER — enum4linux Tool Wrapper
Runs enum4linux for SMB enumeration, parses user list and share info.
"""

from __future__ import annotations

import subprocess
import shutil
import re


class ToolNotFoundError(Exception):
    pass


def _check_enum4linux() -> None:
    if not shutil.which("enum4linux"):
        raise ToolNotFoundError(
            "enum4linux not found in PATH. Install with: sudo apt install enum4linux"
        )


def run_enum4linux(target_ip: str, timeout: int = 120) -> str:
    """
    Run enum4linux -a against target, return raw output.
    
    Args:
        target_ip: Target IP address with SMB (port 139/445)
        timeout: Max seconds to wait
    
    Returns:
        Raw enum4linux text output
    """
    _check_enum4linux()

    cmd = ["enum4linux", "-a", target_ip]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return f"[enum4linux timeout after {timeout}s against {target_ip}]"
    except Exception as e:
        return f"[enum4linux error: {e}]"


def parse_enum4linux(raw_output: str) -> dict:
    """
    Parse enum4linux raw output into structured dict.
    
    Returns:
        {
            "users": [...],
            "shares": [...],
            "workgroup": "...",
            "os_info": "...",
            "password_policy": "...",
        }
    """
    result = {
        "users": [],
        "shares": [],
        "workgroup": "",
        "os_info": "",
        "password_policy": "",
    }

    # Extract users (lines like: user:[root] rid:[0x1f4])
    user_pattern = re.compile(r"user:\[(\S+)\]\s+rid:\[")
    result["users"] = list(set(user_pattern.findall(raw_output)))

    # Extract shares (lines like: //IP/share  Disk  ...)
    share_pattern = re.compile(r"//\S+/(\S+)\s+(Disk|IPC|Printer)\s*(.*)")
    for m in share_pattern.finditer(raw_output):
        result["shares"].append({
            "name": m.group(1),
            "type": m.group(2),
            "comment": m.group(3).strip(),
        })

    # Workgroup
    wg_match = re.search(r"Workgroup\s*:\s*(\S+)", raw_output, re.IGNORECASE)
    if wg_match:
        result["workgroup"] = wg_match.group(1)

    # OS info
    os_match = re.search(r"OS=\[([^\]]+)\]", raw_output)
    if os_match:
        result["os_info"] = os_match.group(1)

    # Password policy
    pp_match = re.search(r"Minimum password length:\s*(\d+)", raw_output)
    if pp_match:
        result["password_policy"] = f"Min password length: {pp_match.group(1)}"

    return result
