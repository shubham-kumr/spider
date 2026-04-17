"""
SPIDER — CVE to Metasploit Module Lookup Table
Maps known CVEs (common on Metasploitable 2 and lab targets) to Metasploit modules.
"""

from __future__ import annotations

# CVE → Metasploit module configuration
CVE_TO_MSF_MODULE: dict[str, dict] = {
    "CVE-2011-2523": {
        "module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "service": "ftp",
        "default_port": 21,
        "payload": "cmd/unix/interact",
        "session_type": "shell",
        "options": {},
        "description": "VSFTPD 2.3.4 Backdoor — Triggers backdoor via malformed username",
    },
    "CVE-2007-2447": {
        "module": "exploit/multi/samba/usermap_script",
        "service": "smb",
        "default_port": 139,
        "payload": "cmd/unix/reverse_netcat",
        "session_type": "shell",
        "options": {},
        "description": "Samba 3.0.x usermap_script — Command injection via username map script",
    },
    "CVE-2012-1823": {
        "module": "exploit/multi/http/php_cgi_arg_injection",
        "service": "http",
        "default_port": 80,
        "payload": "php/meterpreter/reverse_tcp",
        "session_type": "meterpreter",
        "options": {"TARGETURI": "/cgi-bin/php"},
        "description": "PHP CGI Argument Injection — RCE via query string in PHP-CGI mode",
    },
    "CVE-2004-2687": {
        "module": "exploit/unix/misc/distcc_exec",
        "service": "distcc",
        "default_port": 3632,
        "payload": "cmd/unix/reverse_bash",
        "session_type": "shell",
        "options": {},
        "description": "distccd exec — Command execution via distcc daemon",
    },
    "CVE-2009-4510": {
        "module": "exploit/unix/webapp/tikiwiki_graph_formula_exec",
        "service": "http",
        "default_port": 80,
        "payload": "php/meterpreter/reverse_tcp",
        "session_type": "meterpreter",
        "options": {},
        "description": "TikiWiki graph formula exec — RCE via graphviz formula injection",
    },
    "CVE-2008-0166": {
        "module": "exploit/unix/ssh/debian_openssh_pkcs8_prng",
        "service": "ssh",
        "default_port": 22,
        "payload": "cmd/unix/interact",
        "session_type": "shell",
        "options": {},
        "description": "Debian OpenSSL PRNG — Predictable random number generation in SSH keys",
    },
    "CVE-2010-1138": {
        "module": "exploit/multi/http/phpmyadmin_config",
        "service": "http",
        "default_port": 80,
        "payload": "php/meterpreter/reverse_tcp",
        "session_type": "meterpreter",
        "options": {},
        "description": "phpMyAdmin config file write — Remote code execution via config injection",
    },
}


def get_module_for_cve(cve_id: str) -> dict | None:
    """Return Metasploit module config for a given CVE, or None if not mapped."""
    return CVE_TO_MSF_MODULE.get(cve_id.upper())


def get_exploitable_cves(findings: list[dict]) -> list[dict]:
    """
    Filter findings list to those with mapped Metasploit modules.
    Returns sorted by cvss_score descending.
    
    Args:
        findings: List of finding dicts (from StateStore.get_findings)
    
    Returns:
        List of {finding, module_config} dicts, sorted by CVSS score
    """
    exploitable = []
    for f in findings:
        cve = f.get("cve_id")
        if cve and cve in CVE_TO_MSF_MODULE:
            exploitable.append({
                "finding": f,
                "module_config": CVE_TO_MSF_MODULE[cve],
            })

    # Sort by CVSS score descending
    exploitable.sort(
        key=lambda x: x["finding"].get("cvss_score") or 0.0,
        reverse=True,
    )
    return exploitable
