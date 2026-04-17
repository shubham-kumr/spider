# Application Flow Documentation
# SPIDR — System for Penetration Testing, Intelligence, Discovery & Reconnaissance

**Version**: 1.0  
**Last Updated**: 2026-04-17

---

## 1. Entry Points

### Primary Entry Point
- **CLI Command**: `spidr run --target <IP>` — starts the full automated pipeline
- **Resume Command**: `spidr run --target <IP> --start-from <phase>` — resumes from a specific phase
- **Report Command**: `spidr report --target <IP>` — regenerates report from stored findings
- **Status Command**: `spidr status` — shows current run state from SQLite

### Pre-Flight Entry (Automatic)
Before any agent runs, SPIDR performs a pre-flight check:
1. Verify tools in PATH: nmap, gobuster, nikto, enum4linux
2. Verify Together AI API key in `.env`
3. Verify target IP is reachable (ping check)
4. Verify msfrpcd is running (for exploitation phase)

---

## 2. Core Agent Flows

---

### Flow 1: Full Automated Pipeline (`spidr run --target <IP>`)

**Goal**: Fully automated pentest from target IP to final report  
**Entry Point**: `spidr run --target 192.168.56.101`  
**Frequency**: Primary use case

#### Happy Path

```
Step 1: CLI Invocation
  User Input: spidr run --target 192.168.56.101
  System: Parse args → initialize SQLiteStateStore → clear previous run data
  Output: Rich terminal panel opens, "SPIDR v1.0 starting..."

Step 2: Pre-Flight Checks
  System: Check nmap, gobuster, nikto, enum4linux in PATH
  System: Validate Together AI API key
  System: Ping target (3 attempts)
  System: Check msfrpcd connectivity
  Output: Green checkmarks or red error messages per check
  Trigger: If all checks pass → initialize Orchestrator Agent

Step 3: Orchestrator Decision (Round 1)
  Input: Current state = {target: "192.168.56.101", open_ports: [], findings: [], sessions: []}
  LLM Call: "State has no open ports. What is the next step?"
  LLM Output: {"next": "recon", "reason": "No port data exists. Must scan first."}
  Terminal: Prints ">> ORCHESTRATOR: Running Recon Agent — [reason]"
  Trigger: Invoke Recon Agent

Step 4: Recon Agent
  Command: nmap -sV -sC -oX /tmp/spidr_nmap.xml 192.168.56.101
  Processing: Parse XML output → extract open ports, services, versions, banners
  Storage: INSERT into open_ports table (port, service, version, banner)
  Terminal: Rich table printed with all open ports
  Output: {open_ports: [{port: 21, service: "ftp", version: "vsftpd 2.3.4"}, ...]}
  Trigger: Return to Orchestrator

Step 5: Orchestrator Decision (Round 2)
  Input: State has 23 open ports including FTP, HTTP, SMB, SSH
  LLM Output: {"next": "enumerate", "reason": "FTP/HTTP/SMB present. Deep enumeration needed."}
  Trigger: Invoke Enumeration Agent

Step 6: Enumeration Agent
  Sub-task A: FTP (port 21) — banner grab + check vsftpd version
    → Finds: "vsftpd 2.3.4" → LLM tags: "Possible CVE-2011-2523 (backdoor)"
  Sub-task B: HTTP (port 80) — nikto scan
    → Finds: Apache 2.2.8, outdated version, DVWA installation
  Sub-task C: SMB (port 139/445) — enum4linux
    → Finds: anonymous access enabled, user list obtained
  Storage: INSERT into findings table with service, port, finding, severity, suggested_cve
  Terminal: Findings printed with severity color coding (Critical/High/Medium/Low)
  Trigger: Return to Orchestrator

Step 7: Orchestrator Decision (Round 3)
  Input: State has critical finding — CVE-2011-2523 candidate on port 21
  LLM Output: {"next": "exploit", "reason": "CVE-2011-2523 VSFTPD backdoor is critical and exploitable via Metasploit."}
  Trigger: Invoke Exploitation Agent

Step 8: Exploitation Agent
  Pre-check: Verify msfrpcd is running
  Action: Connect via pymetasploit3 to msfrpcd
  Module lookup: CVE-2011-2523 → exploit/unix/ftp/vsftpd_234_backdoor
  Execute:
    - use exploit/unix/ftp/vsftpd_234_backdoor
    - set RHOSTS 192.168.56.101
    - set RPORT 21
    - run
  Result: Session ID returned (e.g., session_id = 1)
  Storage: INSERT into sessions table (session_id, target_ip, shell_type, timestamp)
  Terminal: ">> EXPLOIT SUCCESS: Meterpreter session 1 opened on 192.168.56.101"
  Trigger: Return to Orchestrator

Step 9: Orchestrator Decision (Round 4)
  Input: Active session exists, no post-exploitation data yet
  LLM Output: {"next": "post_exploit", "reason": "Active session available. Escalate privileges and harvest credentials."}
  Trigger: Invoke Post-Exploitation Agent

Step 10: Post-Exploitation Agent
  Action A: Upload linpeas.sh to target via session
  Action B: Execute linpeas.sh → capture output
  Parse output:
    → SUID binary: /bin/bash has SUID set
    → Cron job: root runs /tmp/backup.sh (world-writable)
    → Credential: Found .bash_history with credentials
  GTFOBins lookup: /bin/bash -p → root shell
  Execute: bash -p → root shell confirmed
  Storage: INSERT into privesc_vectors, credentials tables
  Terminal: ">> ROOT SHELL OBTAINED via SUID bash"
  Trigger: Return to Orchestrator

Step 11: Orchestrator Decision (Round 5)
  Input: Post-exploitation complete, root shell obtained
  LLM Output: {"next": "report", "reason": "Full chain complete. Generate report."}
  Trigger: Invoke Reporting Agent

Step 12: Reporting Agent
  Pull all data from SQLite
  LLM generates executive summary paragraph
  Jinja2 renders HTML report
  weasyprint converts to PDF
  Save: ./reports/2026-04-17_192.168.56.101.pdf
  Terminal: ">> REPORT GENERATED: ./reports/2026-04-17_192.168.56.101.pdf"
  Output: Full path to PDF and HTML report
```

#### Error States

| Scenario | Display | Recovery |
|----------|---------|----------|
| Target unreachable | Red panel: "Target 192.168.56.101 not reachable after 3 pings" | Exit with instructions to check network |
| Tool not found (nmap) | Red panel: "nmap not found in PATH" | Print install command, exit |
| msfrpcd not running | Yellow panel: "msfrpcd not running — skipping exploitation" | Continue to reporting with available findings |
| Exploit fails | Yellow panel: "Exploit failed for CVE-XXXX. Trying next CVE..." | Try next ranked exploit in findings |
| LLM API rate limit | Yellow panel: "Rate limited, retrying in 5s..." | Exponential backoff, max 3 retries |
| No exploitable CVEs found | Blue panel: "No exploitable CVEs in findings. Proceeding to report." | Skip exploitation + post-exploitation |
| Session dies mid-post-exploit | Red panel: "Session 1 died. Re-exploitation required." | Log and skip to reporting |

#### Edge Cases
- Target has no web service → skip nikto, run only enum4linux and banner grabs
- Metasploitable 2 returns no Meterpreter (only cmd shell) → post-exploit adapts to cmd shell commands
- User presses Ctrl+C mid-run → graceful shutdown saves current state, prints resume command

---

### Flow 2: Resume from Specific Phase

**Goal**: Resume pipeline from a given phase without re-running earlier phases  
**Entry Point**: `spidr run --target <IP> --start-from <enum|exploit|post_exploit|report>`

#### Happy Path
1. CLI parses `--start-from` flag
2. System loads existing SQLite state for target IP
3. Orchestrator skips phases before specified start
4. Pipeline continues from specified phase

#### Error State
- No existing state found for target → "No prior run found for this IP. Starting from beginning."

---

### Flow 3: Report Regeneration

**Entry Point**: `spidr report --target <IP>`

#### Happy Path
1. CLI invokes Reporting Agent directly
2. Reads all findings from SQLite for target IP
3. LLM generates fresh executive summary
4. Jinja2 renders HTML → weasyprint → PDF
5. PDF saved with new timestamp
6. Path printed to terminal

#### Error State
- No findings in SQLite → "No findings found for this target. Run `spidr run` first."

---

### Flow 4: Status Check

**Entry Point**: `spidr status`

#### Happy Path
1. Read all tables from SQLite
2. Rich table printed: target IPs, phases completed, findings count, session count
3. Last run timestamp shown

---

## 3. Navigation Map (State Machine)

```
[CLI Invocation]
       |
       v
[Pre-Flight Checks]
       |
   PASS? ── NO ──> [Error: Print fix instructions, exit]
       |
      YES
       |
       v
[Orchestrator] <─────────────────────────────────────────┐
       |                                                  │
       ├─── next = "recon"  ──────> [Recon Agent]         │
       │                                └──────────────── ┘
       │                                                  │
       ├─── next = "enumerate" ───> [Enumeration Agent]   │
       │                                └──────────────── ┘
       │                                                  │
       ├─── next = "exploit" ─────> [Exploitation Agent]  │
       │                                └──────────────── ┘
       │                                                  │
       ├─── next = "post_exploit" -> [Post-Exploit Agent] │
       │                                └──────────────── ┘
       │
       └─── next = "report" ──────> [Reporting Agent]
                                           |
                                           v
                                      [PDF + HTML]
                                           |
                                           v
                                        [END]
```

---

## 4. Screen / Terminal View Inventory

### View 1: Startup Banner
- Displays: SPIDR ASCII art, version, target IP
- Shown: On every `spidr run` invocation

### View 2: Pre-Flight Check Panel
- Displays: Checklist with pass/fail per tool and API key
- State Variants: All green (continue), Any red (halt)

### View 3: Orchestrator Decision Panel
- Displays: Current round, LLM decision, reasoning
- Updates: Each time orchestrator is called

### View 4: Recon Agent Panel
- Displays: Live nmap progress, then table of open ports
- Columns: Port | Service | Version | Banner

### View 5: Enumeration Agent Panel
- Displays: Sub-tasks running in sequence, then findings table
- Color coding: Critical (red), High (orange), Medium (yellow), Low (blue)

### View 6: Exploitation Agent Panel
- Displays: Module selected, RHOSTS, RPORT, execution status
- Success: Green banner with session ID
- Failure: Red banner with next step

### View 7: Post-Exploitation Panel
- Displays: linpeas upload progress, parsed findings table
- Highlights: Privesc vectors in red, credentials in yellow

### View 8: Report Generation Panel
- Displays: LLM generating summary, Jinja2 render progress, PDF path

### View 9: Status Table (spidr status)
- Displays: All runs with target IP, phases completed, findings count, timestamp

---

## 5. Decision Points (LLM Orchestrator Logic)

```
GIVEN current_state:
  - open_ports: list
  - findings: list  
  - sessions: list
  - privesc_vectors: list

IF open_ports is EMPTY:
  THEN next = "recon"

ELSE IF findings is EMPTY:
  THEN next = "enumerate"

ELSE IF findings has CRITICAL severity AND sessions is EMPTY:
  AND msfrpcd is reachable:
    THEN next = "exploit"
  AND msfrpcd is NOT reachable:
    THEN next = "report" (with note: exploitation skipped)

ELSE IF sessions is NOT EMPTY AND privesc_vectors is EMPTY:
  THEN next = "post_exploit"

ELSE IF post_exploit data exists OR all paths exhausted:
  THEN next = "report"
```

---

## 6. Error Handling Flows

### Tool Not Found
- Display: Rich error panel with tool name and install command
- Action: Exit with code 1

### API Error (Together AI)
- Display: Yellow warning, retry countdown
- Action: Exponential backoff (1s, 2s, 4s, 8s), max 3 retries
- After 3 failures: Fallback to rule-based decision (not LLM)

### msfrpcd Connection Failure
- Display: Yellow warning panel
- Action: Skip exploitation and post-exploitation, proceed to reporting
- Report note: "Exploitation phase skipped — msfrpcd not available"

### Empty Findings After Enumeration
- Display: Blue info panel
- Action: Proceed to report with available data

---

## 7. Responsive / Environment Behavior

### Kali Linux (Primary)
- All tools available by default
- Rich terminal renders with full color support
- msfrpcd can be started with `msfrpcd -P yourpassword`

### Ubuntu 22+ (Secondary)
- Tools must be manually installed
- Pre-flight check will flag missing tools with apt install commands

### macOS (Partial Support)
- nmap available via brew
- Metasploit via brew or docker
- gobuster/nikto need manual install
- Pre-flight check handles per-tool guidance

### Headless / CI Environment
- SPIDR_NO_RICH=1 env var disables Rich formatting
- Plain text output mode for log files

---

## 8. Logging & Audit Trail

All agent actions are written to `./logs/spidr_<timestamp>.log`:

```
[2026-04-17 14:32:01] [ORCHESTRATOR] Round 1 decision: recon (no port data)
[2026-04-17 14:32:01] [RECON] Running: nmap -sV -sC -oX /tmp/spidr_nmap.xml 192.168.56.101
[2026-04-17 14:34:22] [RECON] Found 23 open ports. Stored to DB.
[2026-04-17 14:34:22] [ORCHESTRATOR] Round 2 decision: enumerate (HTTP/SMB/FTP detected)
...
```
