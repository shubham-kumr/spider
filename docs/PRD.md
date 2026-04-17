# Product Requirements Document (PRD)
# SPIDR — System for Penetration Testing, Intelligence, Discovery & Reconnaissance

**Version**: 1.0  
**Last Updated**: 2026-04-17  
**Owner**: Shubham  
**Status**: Active

---

## 1. Problem Statement

Penetration testing is manual, slow, and requires deep multi-domain expertise across recon, enumeration, exploitation, and post-exploitation. Junior security practitioners lack orchestrated tooling that ties the full kill chain together. There is no open-source, LLM-powered multi-agent framework that automates this pipeline, reasons about findings, and generates structured pentest reports — all against controlled lab environments for ethical, educational use.

SPIDR solves this by acting as an AI-driven co-pentester that pipelines every phase of an engagement, making decisions at each step using a free LLM backbone (Qwen2.5 via Together AI), and producing professional-grade output.

---

## 2. Goals & Objectives

### Primary Goal
Build a functional, resume-worthy multi-agent offensive security framework that automates the full penetration testing kill chain against lab environments.

### Career Goals
- G1: Demonstrate multi-agent LLM orchestration — measurable by functioning LangGraph pipeline with 5 specialized agents
- G2: Achieve automated RCE on Metasploitable 2 — measurable by Meterpreter session ID returned without manual intervention
- G3: Generate a publishable pentest report — measurable by PDF/HTML output with CVSS scores and ATT&CK mappings
- G4: Open-source on GitHub with a clean README and demo video

---

## 3. Success Metrics

| Metric | Target |
|--------|--------|
| Time from target IP to first finding | < 2 minutes |
| Agents chained end-to-end | 5/5 |
| CVEs correctly identified on Metasploitable 2 | >= 3 |
| Automated privesc success rate | >= 1 vector |
| Report generation time | < 30 seconds |
| CLI cold-start time | < 5 seconds |

---

## 4. Target Users & Personas

### Primary Persona: Fresher Security Practitioner
- **Profile**: CS/cybersecurity student, 0–1 years experience
- **Pain Points**: Overwhelmed by tool count, can't tie recon to exploitation
- **Goals**: Learn end-to-end pentesting, build a portfolio project
- **Technical Proficiency**: Medium — comfortable with Python and CLI

### Secondary Persona: CTF Player
- **Profile**: Intermediate practitioner running HTB/THM labs
- **Pain Points**: Repetitive recon tasks, wants to focus on creative exploitation
- **Goals**: Automate boring phases, get faster at machines
- **Technical Proficiency**: High — familiar with all tools SPIDR wraps

---

## 5. Features & Requirements

### P0 — Must-Have (MVP)

**F1: Recon Agent**
- Description: Wraps nmap for port scanning and service/version detection
- User Story: As a user, I want SPIDR to scan a target and return open ports with service versions so that I know the attack surface
- Acceptance Criteria:
  - [ ] Accepts target IP as CLI argument
  - [ ] Runs `nmap -sV -sC` and parses output to JSON
  - [ ] Stores open ports, service names, versions in SQLite
  - [ ] Completes in < 3 minutes for a standard VM
- Success Metric: Port list matches manual nmap scan

**F2: Enumeration Agent**
- Description: Deep service enumeration based on recon results (gobuster, nikto, enum4linux)
- User Story: As a user, I want SPIDR to enumerate web services, SMB, and FTP automatically so that I don't run each tool manually
- Acceptance Criteria:
  - [ ] Triggers automatically after recon finds HTTP, SMB, or FTP
  - [ ] Runs nikto on web ports, enum4linux on SMB, banner grab on FTP
  - [ ] LLM interprets raw output and tags actionable findings
  - [ ] Findings stored with `service:port:finding` format
- Success Metric: Correctly identifies VSFTPD 2.3.4 backdoor indicator

**F3: Orchestrator Agent**
- Description: LangGraph StateGraph that decides next agent using Qwen LLM reasoning
- User Story: As a user, I want SPIDR to decide what to do next without me directing each step so the engagement runs autonomously
- Acceptance Criteria:
  - [ ] Makes next-step decisions via Qwen API at each state transition
  - [ ] Reasoning printed to terminal in real time
  - [ ] Handles dead-ends gracefully with explanation
  - [ ] Loops back to orchestrator after each agent until reporting is reached
- Success Metric: Full pipeline runs from `spidr run --target <IP>` to report

**F4: Exploitation Agent**
- Description: Uses pymetasploit3 to select and execute exploits against identified CVEs
- User Story: As a user, I want SPIDR to automatically select and fire the right exploit for a detected vulnerability
- Acceptance Criteria:
  - [ ] Connects to msfrpcd via pymetasploit3
  - [ ] Maps CVEs to Metasploit module names via lookup table
  - [ ] Executes exploit and captures session ID
  - [ ] Handles exploit failure gracefully
- Success Metric: Meterpreter session opened on Metasploitable 2

**F5: Post-Exploitation Agent**
- Description: Given an active session, runs linpeas, enumerates SUID binaries, harvests credentials
- User Story: As a user, I want SPIDR to escalate privileges and harvest credentials after initial access
- Acceptance Criteria:
  - [ ] Uploads and runs linpeas.sh via Meterpreter session
  - [ ] Parses output for SUID binaries, sudo misconfigs, cron jobs, credentials
  - [ ] Attempts automated privesc via GTFOBins lookup
  - [ ] Stores findings with severity ratings in SQLite
- Success Metric: Identifies at least one privesc vector, achieves root shell

**F6: Reporting Agent**
- Description: Pulls all findings, assigns CVSS scores, maps ATT&CK TTPs, renders HTML/PDF report
- User Story: As a user, I want SPIDR to generate a structured pentest report I can submit as a deliverable
- Acceptance Criteria:
  - [ ] Renders Jinja2 HTML report with all findings
  - [ ] Converts to PDF via weasyprint
  - [ ] Each finding: Title, Description, CVSS, ATT&CK TTP, Evidence, Recommendation
  - [ ] Executive summary generated by LLM
  - [ ] Saved to `./reports/` with timestamp
- Success Metric: Report is complete and mirrors professional pentest report format

**F7: Shared State Store**
- Description: SQLite database as single source of truth across all agents
- Acceptance Criteria:
  - [ ] Tables: open_ports, findings, sessions, credentials, privesc_vectors
  - [ ] Thread-safe reads/writes
  - [ ] Persists across agent invocations within a run
  - [ ] Cleared/archived at start of each new run

**F8: CLI Entry Point**
- Description: Click-based CLI with `run`, `status`, `report` commands
- Acceptance Criteria:
  - [ ] `spidr run --target <IP>` starts full pipeline
  - [ ] `spidr status` shows current state from SQLite
  - [ ] `spidr report` regenerates report from stored findings
  - [ ] Rich terminal output with progress panels and agent activity feed

---

### P1 — Should-Have

- Shodan CLI integration in Recon Agent
- Custom wordlists for gobuster
- Web dashboard (Flask) showing live agent activity
- Multiple target support (CIDR range)

### P2 — Nice-to-Have

- BloodHound integration for AD environments
- Automatic screenshot of discovered web services
- Docker container for portable deployment
- Report templates (detailed / executive / one-pager)

---

## 6. Explicitly OUT OF SCOPE (MVP)

- Attacking real-world production systems or any non-lab network
- WiFi / wireless attack capabilities
- Social engineering modules
- Active Directory / Kerberos attack chains
- Cloud provider enumeration (AWS, GCP, Azure)
- GUI desktop application
- Multi-user collaboration features
- C2 framework functionality
- AV evasion / AMSI patching techniques

---

## 7. User Scenarios

### Scenario 1: Full Automated Run Against Metasploitable 2
- **Context**: Metasploitable 2 in VirtualBox, msfrpcd running on attacker
- **Steps**:
  1. `spidr run --target 192.168.56.101`
  2. Orchestrator → Recon Agent → finds 23 open ports
  3. Orchestrator → Enumeration Agent → identifies VSFTPD 2.3.4 on port 21
  4. LLM maps to CVE-2011-2523
  5. Orchestrator → Exploitation Agent → opens Meterpreter session
  6. Orchestrator → Post-Exploitation Agent → linpeas finds SUID bash
  7. Orchestrator → Reporting Agent → PDF saved
- **Expected Outcome**: Full report with 5+ findings, CVSS, ATT&CK

### Scenario 2: Resume from Enumeration
- **Context**: User already ran recon manually, wants to continue from enumeration
- **Steps**:
  1. Insert port findings to SQLite manually
  2. `spidr run --target 192.168.56.101 --start-from enum`
- **Expected Outcome**: Pipeline resumes from enumeration without re-scanning

### Scenario 3: Report Regeneration
- **Steps**:
  1. `spidr report --target 192.168.56.101`
  2. Reporting Agent reads SQLite and renders fresh PDF
- **Expected Outcome**: Updated PDF without re-running any scan

---

## 8. Dependencies & Constraints

### Technical Constraints
- Kali Linux or Ubuntu 22+ (or Kali WSL2) required
- Python 3.11+ required
- Metasploit Framework installed; msfrpcd must be running before exploitation phase
- nmap, gobuster, nikto, enum4linux must be in PATH
- Together AI free API — rate limit ~60 req/min
- Target must be a controlled lab VM (ethical enforcement via README + disclaimer)

### External Dependencies
- Together AI API for Qwen2.5-72B-Instruct (free tier)
- pymetasploit3 for Metasploit RPC
- weasyprint for PDF generation

---

## 9. Non-Functional Requirements

| Requirement | Specification |
|-------------|---------------|
| Performance | Full pipeline < 15 min on Metasploitable 2 |
| Reliability | Graceful failure on any agent error — pipeline continues |
| Security | API keys in `.env` only, never logged or hardcoded |
| Usability | Cold start to first output < 10 seconds |
| Portability | Runs on Kali Linux, Ubuntu 22+, macOS (with nmap) |
| Logging | All agent actions logged to `./logs/` with timestamps |

---

## 10. Risks & Assumptions

### Risks
| Risk | Impact | Mitigation |
|------|--------|------------|
| Together AI rate limits throttle orchestrator | Medium | Exponential backoff + LLM response caching |
| msfrpcd not running at exploitation time | High | Pre-flight check before exploitation phase |
| Qwen model API changes behavior | Medium | Pin model version string in config |
| nmap / tool not in PATH | High | Pre-flight tool availability check at startup |

### Assumptions
- Metasploitable 2 running in host-only or NAT network
- Kali Linux with nmap, gobuster, nikto pre-installed
- Metasploit Community Edition installed
- Together AI free tier remains available
