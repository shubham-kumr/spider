# Technology Stack Documentation
# SPIDR — System for Penetration Testing, Intelligence, Discovery & Reconnaissance

**Version**: 1.0  
**Last Updated**: 2026-04-17

---

## 1. Stack Overview

| Property | Value |
|----------|-------|
| Architecture | Single-process multi-agent pipeline (no microservices) |
| Language | Python 3.11+ |
| Agent Framework | LangGraph (LangChain ecosystem) |
| LLM Backbone | Qwen2.5-72B-Instruct via Together AI (free tier) |
| Deployment | Local CLI tool — runs on attacker machine |
| State Store | SQLite (single-file, zero infra) |
| UI | Rich terminal dashboard (no web UI in MVP) |
| Package Manager | pip + virtualenv |

---

## 2. Core Python Stack

### Language & Runtime
- **Language**: Python
- **Version**: 3.11.8
- **Reason**: LangGraph, pymetasploit3, and weasyprint all support 3.11; avoids 3.12 breaking changes in some libs
- **Virtual Environment**: venv (built-in, zero setup)

### Agent Orchestration
- **Library**: langgraph
- **Version**: 0.2.28
- **Reason**: Built for stateful multi-agent graphs; native LangChain integration; TypedDict-based state is perfect for pentest findings
- **Documentation**: https://langchain-ai.github.io/langgraph/
- **License**: MIT

### LangChain Core (dependency of langgraph)
- **Library**: langchain-core
- **Version**: 0.3.15
- **License**: MIT

### LLM Client — Together AI (Qwen)
- **Library**: openai
- **Version**: 1.51.0
- **Reason**: Together AI exposes an OpenAI-compatible API. Use `openai` client pointed at Together AI base URL — no extra SDK needed
- **Base URL**: `https://api.together.xyz/v1`
- **Model**: `Qwen/Qwen2.5-72B-Instruct-Turbo`
- **License**: MIT
- **Alternatives Considered**: anthropic SDK (rejected: not free), ollama (rejected: too slow on CPU for 72B)

### State Store
- **Database**: SQLite
- **Version**: Built into Python 3.11 (sqlite3 stdlib)
- **Wrapper**: sqlalchemy 2.0.36
- **Reason**: Zero infrastructure, single file, sufficient for per-run state storage
- **Alternatives Considered**: Redis (rejected: overkill for single process), PostgreSQL (rejected: requires server setup)

### Metasploit Integration
- **Library**: pymetasploit3
- **Version**: 1.0.3
- **Reason**: Official Python client for Metasploit RPC daemon; wraps msfrpcd REST API
- **Documentation**: https://github.com/DanMcInerney/pymetasploit3
- **License**: BSD
- **Requirement**: Metasploit Framework installed + msfrpcd running

### Terminal UI
- **Library**: rich
- **Version**: 13.9.4
- **Reason**: Beautiful terminal output with panels, tables, progress bars, and colors — essential for live agent activity display
- **Documentation**: https://rich.readthedocs.io
- **License**: MIT

### CLI Framework
- **Library**: click
- **Version**: 8.1.8
- **Reason**: Clean, well-documented CLI creation; supports subcommands and options well
- **Documentation**: https://click.palletsprojects.com
- **License**: BSD

### Report Generation — HTML
- **Library**: jinja2
- **Version**: 3.1.4
- **Reason**: Industry-standard templating; renders the pentest report HTML from SQLite data
- **Documentation**: https://jinja.palletsprojects.com
- **License**: BSD

### Report Generation — PDF
- **Library**: weasyprint
- **Version**: 62.3
- **Reason**: Converts HTML to PDF with CSS support; produces professional-grade PDFs
- **Documentation**: https://weasyprint.org
- **License**: BSD
- **System Dependency**: `libpango-1.0-0` (apt install libpango-1.0-0 on Debian/Ubuntu)

### HTTP Requests
- **Library**: requests
- **Version**: 2.32.3
- **Reason**: Used by Shodan CLI wrapper and Together AI fallback calls
- **License**: Apache 2.0

### Environment Variables
- **Library**: python-dotenv
- **Version**: 1.0.1
- **Reason**: Loads `.env` file for API keys; keeps secrets out of code
- **License**: BSD

### Data Validation
- **Library**: pydantic
- **Version**: 2.9.2
- **Reason**: Validates LLM JSON outputs (orchestrator decisions, finding structures)
- **License**: MIT

### XML Parsing (nmap output)
- **Library**: python-libnmap
- **Version**: 0.7.3
- **Reason**: Parses nmap XML output into structured Python objects
- **License**: BSD

---

## 3. External Security Tools (System Dependencies)

These are CLI tools that SPIDR wraps via `subprocess`. They must be installed on the host system.

| Tool | Version | Installation | Purpose |
|------|---------|-------------|---------|
| nmap | 7.94+ | `apt install nmap` | Port scanning, service detection |
| gobuster | 3.6.0 | `apt install gobuster` | Web directory enumeration |
| nikto | 2.1.6 | `apt install nikto` | Web server vulnerability scanner |
| enum4linux | 0.9.1 | `apt install enum4linux` | SMB enumeration |
| Metasploit Framework | 6.3+ | `apt install metasploit-framework` | Exploitation engine |
| msfrpcd | 6.3+ | Included with Metasploit | RPC daemon for pymetasploit3 |

---

## 4. Directory Structure

```
spidr/
├── spidr/
│   ├── __init__.py
│   ├── cli.py                  # Click CLI entry point
│   ├── config.py               # Config loader from .env
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── orchestrator.py     # LangGraph StateGraph
│   │   ├── recon.py            # nmap wrapper agent
│   │   ├── enumeration.py      # gobuster/nikto/enum4linux agent
│   │   ├── exploitation.py     # pymetasploit3 agent
│   │   ├── post_exploit.py     # linpeas + privesc agent
│   │   └── reporting.py        # Jinja2 + weasyprint agent
│   ├── state/
│   │   ├── __init__.py
│   │   ├── models.py           # SQLAlchemy ORM models
│   │   └── store.py            # StateStore class (CRUD)
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── nmap_tool.py        # subprocess nmap wrapper
│   │   ├── gobuster_tool.py    # subprocess gobuster wrapper
│   │   ├── nikto_tool.py       # subprocess nikto wrapper
│   │   ├── enum4linux_tool.py  # subprocess enum4linux wrapper
│   │   ├── msf_tool.py         # pymetasploit3 client wrapper
│   │   └── gtfobins.py         # GTFOBins SUID lookup
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── client.py           # Together AI / Qwen client
│   │   └── prompts.py          # All LLM prompt templates
│   └── templates/
│       ├── report.html         # Jinja2 pentest report template
│       └── report.css          # Report styling
├── reports/                    # Generated PDF/HTML reports
├── logs/                       # Agent activity logs
├── tests/
│   ├── test_recon.py
│   ├── test_enumeration.py
│   ├── test_exploitation.py
│   ├── test_state_store.py
│   └── test_reporting.py
├── .env.example                # Environment variable template
├── .env                        # Local secrets (gitignored)
├── .gitignore
├── README.md
├── requirements.txt
├── requirements-dev.txt
└── setup.py                    # or pyproject.toml
```

---

## 5. Environment Variables

All secrets loaded from `.env` via python-dotenv.

```bash
# Together AI (Qwen)
TOGETHER_API_KEY="your_together_ai_key_here"
TOGETHER_BASE_URL="https://api.together.xyz/v1"
TOGETHER_MODEL="Qwen/Qwen2.5-72B-Instruct-Turbo"
TOGETHER_MAX_TOKENS="1024"

# Metasploit RPC
MSF_RPC_HOST="127.0.0.1"
MSF_RPC_PORT="55553"
MSF_RPC_PASSWORD="yourmsfrpcpassword"
MSF_RPC_SSL="true"

# SQLite
SPIDR_DB_PATH="./spidr_state.db"

# Logging
LOG_LEVEL="INFO"
LOG_DIR="./logs"

# Report output
REPORT_DIR="./reports"

# UI
SPIDR_NO_RICH="false"         # Set to "true" for plain text (CI/headless)
```

---

## 6. requirements.txt

```
langgraph==0.2.28
langchain-core==0.3.15
openai==1.51.0
sqlalchemy==2.0.36
pymetasploit3==1.0.3
rich==13.9.4
click==8.1.8
jinja2==3.1.4
weasyprint==62.3
requests==2.32.3
python-dotenv==1.0.1
pydantic==2.9.2
python-libnmap==0.7.3
```

---

## 7. requirements-dev.txt

```
pytest==8.3.3
pytest-cov==5.0.0
pytest-mock==3.14.0
black==24.10.0
ruff==0.7.4
mypy==1.13.0
```

---

## 8. setup.py / pyproject.toml

```toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.backends.legacy:build"

[project]
name = "spidr"
version = "1.0.0"
description = "System for Penetration Testing, Intelligence, Discovery & Reconnaissance"
requires-python = ">=3.11"
dependencies = [
    "langgraph==0.2.28",
    "langchain-core==0.3.15",
    "openai==1.51.0",
    "sqlalchemy==2.0.36",
    "pymetasploit3==1.0.3",
    "rich==13.9.4",
    "click==8.1.8",
    "jinja2==3.1.4",
    "weasyprint==62.3",
    "requests==2.32.3",
    "python-dotenv==1.0.1",
    "pydantic==2.9.2",
    "python-libnmap==0.7.3",
]

[project.scripts]
spidr = "spidr.cli:main"
```

---

## 9. CLI Scripts (pip install entry points)

After `pip install -e .`:

| Command | Function |
|---------|----------|
| `spidr run --target <IP>` | Full pipeline |
| `spidr run --target <IP> --start-from <phase>` | Resume from phase |
| `spidr status` | Show current state |
| `spidr report --target <IP>` | Regenerate report |
| `spidr preflight` | Run pre-flight checks only |
| `spidr clean` | Clear SQLite state for a target |

---

## 10. Together AI — Qwen Free Tier Notes

| Property | Value |
|----------|-------|
| API Base URL | `https://api.together.xyz/v1` |
| Free Model | `Qwen/Qwen2.5-72B-Instruct-Turbo` |
| Free Tier Rate Limit | 60 requests/minute |
| Free Tier Token Limit | 10M tokens/month |
| Sign-Up | https://api.together.ai/signup |
| Compatible Client | `openai` Python SDK (just change base_url) |

**Free tier is sufficient** for SPIDR because:
- Orchestrator makes ~5-10 LLM calls per full run
- Report summary generation is 1-2 calls
- Total tokens per run: ~3,000-8,000 tokens

---

## 11. Security Considerations

- `.env` is gitignored — never commit API keys
- msfrpcd password must be set (not default)
- SPIDR only runs against IPs in lab CIDR ranges (enforced by README disclaimer, not code)
- Logs do not write credential values, only finding labels
- SQLite DB has no auth — keep it local, don't expose it
- weasyprint HTML rendering uses Jinja2 autoescaping — prevents XSS in report data

---

## 12. Version Upgrade Policy

| Dependency | Upgrade Frequency | Process |
|------------|------------------|---------|
| langgraph | On minor releases | Test agent graph behavior |
| openai SDK | On minor releases | Verify Together AI compatibility |
| weasyprint | On patch releases | Verify PDF output unchanged |
| pymetasploit3 | As needed | Test against live msfrpcd |
| All others | Security patches immediately | `pip install --upgrade <pkg>` |
