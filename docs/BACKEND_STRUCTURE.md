# Backend Architecture & Database Structure
# SPIDR — System for Penetration Testing, Intelligence, Discovery & Reconnaissance

**Version**: 1.0  
**Last Updated**: 2026-04-17

---

## 1. Architecture Overview

SPIDR is a single-process Python application. There is no web server, no REST API, and no client-server separation. The "backend" is the agent engine itself.

```
[CLI Input]
    |
    v
[Pre-Flight Checks]
    |
    v
[LangGraph StateGraph (Orchestrator)]
    |
    ├── [Recon Agent]       ──> wraps: subprocess(nmap)
    ├── [Enumeration Agent] ──> wraps: subprocess(gobuster, nikto, enum4linux)
    ├── [Exploitation Agent]──> wraps: pymetasploit3 → msfrpcd
    ├── [Post-Exploit Agent]──> wraps: Meterpreter session commands
    └── [Reporting Agent]   ──> wraps: Jinja2 + weasyprint
          |
          v (all agents read/write)
    [SQLite StateStore]
          |
          v (reporting agent reads)
    [Jinja2 Template]
          |
          v
    [PDF + HTML Report]
```

### Data Flow
1. CLI parses args → creates `SpidrRun` record in SQLite
2. Orchestrator reads `SpidrState` from SQLite → calls Qwen LLM → decides next agent
3. Each agent executes, writes results to SQLite, returns control to orchestrator
4. Orchestrator loops until `next = "report"`
5. Reporting Agent reads all findings and renders output

---

## 2. Database Schema

**Engine**: SQLite 3 (via SQLAlchemy 2.0)  
**File Path**: `./spidr_state.db` (configurable via env)  
**Naming**: snake_case for all tables and columns  
**ORM**: SQLAlchemy declarative models in `spidr/state/models.py`

---

### Table: `runs`

**Purpose**: Tracks each SPIDR engagement run

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique run ID |
| target_ip | VARCHAR(45) | NOT NULL | Target IP address |
| status | VARCHAR(20) | NOT NULL, DEFAULT 'running' | running / complete / failed |
| current_phase | VARCHAR(20) | NOT NULL, DEFAULT 'preflight' | Current pipeline phase |
| start_time | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Run start time |
| end_time | DATETIME | NULL | Run completion time |
| notes | TEXT | NULL | Optional run notes |

**Indexes**:
- `idx_runs_target_ip` ON (target_ip)
- `idx_runs_status` ON (status)

---

### Table: `open_ports`

**Purpose**: Stores nmap scan results per run

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | Row ID |
| run_id | INTEGER | FOREIGN KEY → runs(id) ON DELETE CASCADE, NOT NULL | Parent run |
| port | INTEGER | NOT NULL | Port number (1-65535) |
| protocol | VARCHAR(5) | NOT NULL, DEFAULT 'tcp' | tcp or udp |
| state | VARCHAR(10) | NOT NULL, DEFAULT 'open' | open / filtered |
| service | VARCHAR(50) | NULL | Service name (ftp, http, smb...) |
| version | VARCHAR(100) | NULL | Service version string |
| banner | TEXT | NULL | Raw service banner |
| product | VARCHAR(100) | NULL | Product name from nmap |
| extra_info | TEXT | NULL | Extra nmap info |
| scanned_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Scan timestamp |

**Indexes**:
- `idx_open_ports_run_id` ON (run_id)
- `idx_open_ports_port` ON (port)

---

### Table: `findings`

**Purpose**: Stores all vulnerability/issue findings from enumeration, exploitation, and post-exploitation agents

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | Finding ID |
| run_id | INTEGER | FOREIGN KEY → runs(id) ON DELETE CASCADE, NOT NULL | Parent run |
| agent | VARCHAR(30) | NOT NULL | Which agent found this |
| service | VARCHAR(50) | NOT NULL | Affected service name |
| port | INTEGER | NULL | Affected port (null if not port-specific) |
| title | VARCHAR(200) | NOT NULL | Short finding title |
| description | TEXT | NOT NULL | Detailed description |
| severity | VARCHAR(10) | NOT NULL | critical / high / medium / low / info |
| cvss_score | FLOAT | NULL | CVSS v3 score (0.0 - 10.0) |
| cve_id | VARCHAR(20) | NULL | CVE identifier (e.g., CVE-2011-2523) |
| attack_tactic | VARCHAR(50) | NULL | MITRE ATT&CK tactic name |
| attack_technique | VARCHAR(20) | NULL | MITRE ATT&CK technique ID (e.g., T1190) |
| evidence | TEXT | NULL | Raw evidence / command output snippet |
| recommendation | TEXT | NULL | Remediation recommendation |
| exploitable | BOOLEAN | NOT NULL, DEFAULT FALSE | Whether this was exploited |
| found_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Discovery timestamp |

**Indexes**:
- `idx_findings_run_id` ON (run_id)
- `idx_findings_severity` ON (severity)
- `idx_findings_cve_id` ON (cve_id)
- `idx_findings_agent` ON (agent)

---

### Table: `sessions`

**Purpose**: Tracks active Meterpreter / shell sessions opened during exploitation

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | Internal ID |
| run_id | INTEGER | FOREIGN KEY → runs(id) ON DELETE CASCADE, NOT NULL | Parent run |
| msf_session_id | INTEGER | NOT NULL | Metasploit session ID |
| session_type | VARCHAR(20) | NOT NULL | meterpreter / shell |
| target_ip | VARCHAR(45) | NOT NULL | Target IP |
| target_port | INTEGER | NOT NULL | Exploited port |
| exploit_module | VARCHAR(200) | NOT NULL | Metasploit module path used |
| cve_id | VARCHAR(20) | NULL | CVE that was exploited |
| username | VARCHAR(50) | NULL | Current user in session |
| hostname | VARCHAR(100) | NULL | Target hostname |
| os_info | TEXT | NULL | OS version from session |
| alive | BOOLEAN | NOT NULL, DEFAULT TRUE | Whether session is still active |
| opened_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Session open time |
| closed_at | DATETIME | NULL | Session close time |

**Indexes**:
- `idx_sessions_run_id` ON (run_id)
- `idx_sessions_msf_session_id` ON (msf_session_id)
- `idx_sessions_alive` ON (alive)

---

### Table: `privesc_vectors`

**Purpose**: Stores discovered privilege escalation paths

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | Row ID |
| run_id | INTEGER | FOREIGN KEY → runs(id) ON DELETE CASCADE, NOT NULL | Parent run |
| session_id | INTEGER | FOREIGN KEY → sessions(id) ON DELETE CASCADE, NOT NULL | Associated session |
| vector_type | VARCHAR(30) | NOT NULL | suid / sudo / cron / writable_service / kernel |
| binary_path | VARCHAR(255) | NULL | Full path to vulnerable binary |
| gtfobins_command | TEXT | NULL | GTFOBins exploitation command |
| root_achieved | BOOLEAN | NOT NULL, DEFAULT FALSE | Whether root was obtained |
| evidence | TEXT | NULL | Raw linpeas output excerpt |
| found_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Discovery timestamp |

**Indexes**:
- `idx_privesc_run_id` ON (run_id)
- `idx_privesc_session_id` ON (session_id)

---

### Table: `credentials`

**Purpose**: Stores harvested credentials during post-exploitation

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | Row ID |
| run_id | INTEGER | FOREIGN KEY → runs(id) ON DELETE CASCADE, NOT NULL | Parent run |
| session_id | INTEGER | FOREIGN KEY → sessions(id), NOT NULL | Source session |
| cred_type | VARCHAR(20) | NOT NULL | plaintext / hash / ssh_key / token |
| username | VARCHAR(100) | NOT NULL | Username |
| secret | TEXT | NOT NULL | Password, hash, or key content |
| source_file | VARCHAR(255) | NULL | File path where found |
| service | VARCHAR(50) | NULL | Service this credential is for |
| found_at | DATETIME | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Discovery timestamp |

**Indexes**:
- `idx_credentials_run_id` ON (run_id)
- `idx_credentials_cred_type` ON (cred_type)

**Security Note**: Credential values stored for report generation only. DB file should not be committed or shared.

---

## 3. SQLAlchemy ORM Models

```python
# spidr/state/models.py

from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

Base = declarative_base()

class Run(Base):
    __tablename__ = "runs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    target_ip = Column(String(45), nullable=False)
    status = Column(String(20), nullable=False, default="running")
    current_phase = Column(String(20), nullable=False, default="preflight")
    start_time = Column(DateTime, server_default=func.now())
    end_time = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)

    open_ports = relationship("OpenPort", back_populates="run", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="run", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="run", cascade="all, delete-orphan")


class OpenPort(Base):
    __tablename__ = "open_ports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(5), nullable=False, default="tcp")
    state = Column(String(10), nullable=False, default="open")
    service = Column(String(50), nullable=True)
    version = Column(String(100), nullable=True)
    banner = Column(Text, nullable=True)
    product = Column(String(100), nullable=True)
    extra_info = Column(Text, nullable=True)
    scanned_at = Column(DateTime, server_default=func.now())

    run = relationship("Run", back_populates="open_ports")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    agent = Column(String(30), nullable=False)
    service = Column(String(50), nullable=False)
    port = Column(Integer, nullable=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(10), nullable=False)
    cvss_score = Column(Float, nullable=True)
    cve_id = Column(String(20), nullable=True)
    attack_tactic = Column(String(50), nullable=True)
    attack_technique = Column(String(20), nullable=True)
    evidence = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    exploitable = Column(Boolean, nullable=False, default=False)
    found_at = Column(DateTime, server_default=func.now())

    run = relationship("Run", back_populates="findings")


class Session(Base):
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    msf_session_id = Column(Integer, nullable=False)
    session_type = Column(String(20), nullable=False)
    target_ip = Column(String(45), nullable=False)
    target_port = Column(Integer, nullable=False)
    exploit_module = Column(String(200), nullable=False)
    cve_id = Column(String(20), nullable=True)
    username = Column(String(50), nullable=True)
    hostname = Column(String(100), nullable=True)
    os_info = Column(Text, nullable=True)
    alive = Column(Boolean, nullable=False, default=True)
    opened_at = Column(DateTime, server_default=func.now())
    closed_at = Column(DateTime, nullable=True)

    run = relationship("Run", back_populates="sessions")
    privesc_vectors = relationship("PrivescVector", back_populates="session", cascade="all, delete-orphan")
    credentials = relationship("Credential", back_populates="session", cascade="all, delete-orphan")


class PrivescVector(Base):
    __tablename__ = "privesc_vectors"
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    session_id = Column(Integer, ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False)
    vector_type = Column(String(30), nullable=False)
    binary_path = Column(String(255), nullable=True)
    gtfobins_command = Column(Text, nullable=True)
    root_achieved = Column(Boolean, nullable=False, default=False)
    evidence = Column(Text, nullable=True)
    found_at = Column(DateTime, server_default=func.now())

    session = relationship("Session", back_populates="privesc_vectors")


class Credential(Base):
    __tablename__ = "credentials"
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False)
    cred_type = Column(String(20), nullable=False)
    username = Column(String(100), nullable=False)
    secret = Column(Text, nullable=False)
    source_file = Column(String(255), nullable=True)
    service = Column(String(50), nullable=True)
    found_at = Column(DateTime, server_default=func.now())

    session = relationship("Session", back_populates="credentials")
```

---

## 4. StateStore Class (CRUD Interface)

```python
# spidr/state/store.py

from sqlalchemy import create_engine
from sqlalchemy.orm import Session as DBSession
from .models import Base, Run, OpenPort, Finding, Session, PrivescVector, Credential

class StateStore:
    def __init__(self, db_path: str = "./spidr_state.db"):
        self.engine = create_engine(f"sqlite:///{db_path}", echo=False)
        Base.metadata.create_all(self.engine)

    def create_run(self, target_ip: str) -> int:
        with DBSession(self.engine) as session:
            run = Run(target_ip=target_ip, status="running", current_phase="preflight")
            session.add(run)
            session.commit()
            return run.id

    def update_phase(self, run_id: int, phase: str) -> None:
        with DBSession(self.engine) as session:
            run = session.get(Run, run_id)
            run.current_phase = phase
            session.commit()

    def complete_run(self, run_id: int) -> None:
        from datetime import datetime
        with DBSession(self.engine) as session:
            run = session.get(Run, run_id)
            run.status = "complete"
            run.end_time = datetime.utcnow()
            session.commit()

    def add_open_ports(self, run_id: int, ports: list[dict]) -> None:
        with DBSession(self.engine) as session:
            for p in ports:
                session.add(OpenPort(run_id=run_id, **p))
            session.commit()

    def get_open_ports(self, run_id: int) -> list[OpenPort]:
        with DBSession(self.engine) as session:
            return session.query(OpenPort).filter_by(run_id=run_id).all()

    def add_finding(self, run_id: int, finding: dict) -> int:
        with DBSession(self.engine) as session:
            f = Finding(run_id=run_id, **finding)
            session.add(f)
            session.commit()
            return f.id

    def get_findings(self, run_id: int, severity: str = None) -> list[Finding]:
        with DBSession(self.engine) as session:
            query = session.query(Finding).filter_by(run_id=run_id)
            if severity:
                query = query.filter_by(severity=severity)
            return query.order_by(Finding.cvss_score.desc().nullslast()).all()

    def add_session(self, run_id: int, session_data: dict) -> int:
        with DBSession(self.engine) as session:
            s = Session(run_id=run_id, **session_data)
            session.add(s)
            session.commit()
            return s.id

    def get_active_sessions(self, run_id: int) -> list[Session]:
        with DBSession(self.engine) as session:
            return session.query(Session).filter_by(run_id=run_id, alive=True).all()

    def add_privesc_vector(self, run_id: int, session_id: int, vector: dict) -> None:
        with DBSession(self.engine) as session:
            session.add(PrivescVector(run_id=run_id, session_id=session_id, **vector))
            session.commit()

    def add_credential(self, run_id: int, session_id: int, cred: dict) -> None:
        with DBSession(self.engine) as session:
            session.add(Credential(run_id=run_id, session_id=session_id, **cred))
            session.commit()
```

---

## 5. LangGraph State Definition

```python
# spidr/agents/orchestrator.py

from typing import TypedDict, Optional

class SpidrState(TypedDict):
    run_id: int
    target_ip: str
    open_ports: list          # Populated by Recon Agent
    findings: list            # Populated by Enumeration Agent
    sessions: list            # Populated by Exploitation Agent
    privesc_vectors: list     # Populated by Post-Exploit Agent
    credentials: list         # Populated by Post-Exploit Agent
    msfrpcd_available: bool   # Set during pre-flight
    next_agent: str           # Set by Orchestrator
    orchestrator_reasoning: str  # LLM reasoning text
    report_path: Optional[str]   # Set by Reporting Agent on success
    error_log: list           # Accumulated errors across agents
```

---

## 6. Orchestrator LLM Prompt Contract

### System Prompt

```python
ORCHESTRATOR_SYSTEM_PROMPT = """
You are the Orchestrator of SPIDR, an automated penetration testing framework.
Your job is to analyze the current state of a pentest engagement and decide which agent to run next.

Available agents and when to use them:
- "recon": Use when open_ports is empty. Must run first.
- "enumerate": Use when open_ports is populated but findings is empty.
- "exploit": Use when findings contains critical/high CVEs AND msfrpcd_available is true AND sessions is empty.
- "post_exploit": Use when sessions is non-empty AND privesc_vectors is empty.
- "report": Use when post_exploit data exists, OR all paths are exhausted, OR msfrpcd_available is false.

Respond ONLY with a valid JSON object. No markdown, no extra text.
Format: {"next": "<agent_name>", "reason": "<one sentence explanation>"}
"""
```

### User Prompt Template

```python
ORCHESTRATOR_USER_PROMPT = """
Current engagement state:
- Target: {target_ip}
- Open ports found: {port_count} ({port_summary})
- Findings: {finding_count} ({critical_count} critical, {high_count} high)
- Active sessions: {session_count}
- Privesc vectors found: {privesc_count}
- msfrpcd available: {msfrpcd_available}

What should SPIDR do next?
"""
```

---

## 7. CVE-to-Metasploit Module Lookup Table

```python
# spidr/tools/cve_module_map.py

CVE_TO_MSF_MODULE = {
    "CVE-2011-2523": {
        "module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "service": "ftp",
        "default_port": 21,
        "payload": "cmd/unix/interact",
        "options": {}
    },
    "CVE-2012-1823": {
        "module": "exploit/multi/http/php_cgi_arg_injection",
        "service": "http",
        "default_port": 80,
        "payload": "php/meterpreter/reverse_tcp",
        "options": {"TARGETURI": "/cgi-bin/php"}
    },
    "CVE-2007-2447": {
        "module": "exploit/multi/samba/usermap_script",
        "service": "smb",
        "default_port": 139,
        "payload": "cmd/unix/reverse_netcat",
        "options": {}
    },
    "CVE-2004-2687": {
        "module": "exploit/unix/misc/distcc_exec",
        "service": "distcc",
        "default_port": 3632,
        "payload": "cmd/unix/reverse_bash",
        "options": {}
    },
    "CVE-2009-4510": {
        "module": "exploit/unix/webapp/tikiwiki_graph_formula_exec",
        "service": "http",
        "default_port": 80,
        "payload": "php/meterpreter/reverse_tcp",
        "options": {}
    },
}
```

---

## 8. Reporting Agent — Data Contract

The Reporting Agent reads from SQLite and passes this context to Jinja2:

```python
# Report context structure passed to report.html template

report_context = {
    "target_ip": "192.168.56.101",
    "run_date": "2026-04-17",
    "run_duration_minutes": 12,
    "executive_summary": "<LLM-generated paragraph>",
    "findings": [
        {
            "id": "SPIDR-001",
            "title": "VSFTPD 2.3.4 Backdoor",
            "severity": "critical",
            "cvss_score": 10.0,
            "cve_id": "CVE-2011-2523",
            "attack_tactic": "Initial Access",
            "attack_technique": "T1190",
            "service": "ftp",
            "port": 21,
            "description": "...",
            "evidence": "...",
            "recommendation": "..."
        }
    ],
    "open_ports": [...],
    "sessions_opened": 1,
    "root_achieved": True,
    "credentials": [...],
    "privesc_vectors": [...],
    "attack_chain_summary": [
        "Recon: 23 ports found",
        "Enum: CVE-2011-2523 identified on FTP",
        "Exploit: Meterpreter session via vsftpd backdoor",
        "Privesc: SUID /bin/bash → root shell",
    ]
}
```

---

## 9. Error Handling Strategy

All agents follow this error handling pattern:

```python
def run_agent(state: SpidrState) -> SpidrState:
    try:
        # ... agent logic
        return {**state, "field": updated_value}
    except ToolNotFoundError as e:
        error = f"[{agent_name}] Tool not found: {e}"
        return {**state, "error_log": state["error_log"] + [error]}
    except MSFConnectionError as e:
        error = f"[{agent_name}] msfrpcd error: {e}"
        return {**state, "error_log": state["error_log"] + [error], "msfrpcd_available": False}
    except RateLimitError as e:
        # Retry with backoff handled by llm/client.py
        raise
    except Exception as e:
        error = f"[{agent_name}] Unexpected error: {e}"
        return {**state, "error_log": state["error_log"] + [error]}
```

### Error Types

| Error Class | Trigger | Recovery |
|------------|---------|----------|
| `ToolNotFoundError` | CLI tool not in PATH | Log, skip agent |
| `MSFConnectionError` | msfrpcd unreachable | Set msfrpcd_available=False, skip exploitation |
| `ExploitFailedError` | Metasploit module failed | Log, try next CVE |
| `SessionDeadError` | Meterpreter session died | Log, skip post-exploit |
| `RateLimitError` | Together AI 429 | Exponential backoff in `llm/client.py` |
| `LLMParseError` | LLM returned invalid JSON | Fall back to rule-based decision |
