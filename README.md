# SPIDER 🕷️

**System for Penetration Testing, Intelligence, Discovery, Exploit & Recon**

> ⚠️ **ETHICAL USE ONLY** — SPIDER is designed exclusively for controlled lab environments and authorized penetration testing. See [DISCLAIMER.md](DISCLAIMER.md). Never use against systems you don't own or have explicit permission to test.

---

```
  ███████╗██████╗ ██╗██████╗ ███████╗██████╗
  ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗
  ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝
  ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗
  ███████║██║     ██║██████╔╝███████╗██║  ██║
  ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
```

SPIDER is an **AI-driven multi-agent offensive security framework** that automates the full penetration testing kill chain — from recon to report — using a **LangGraph** pipeline of specialized agents powered by **Qwen2.5 (free tier via Together AI)**.

---

## 🏗️ Architecture

```
[CLI: spider run --target <IP>]
        |
        v
[Pre-Flight Checks]
        |
        v
[LangGraph Orchestrator] ←──────────────────────────────┐
        |                                                 │
        ├─── recon ──────► [Recon Agent]     (nmap)       │
        │                         └──────────────────────┘
        ├─── enumerate ──► [Enum Agent]      (nikto, gobuster, enum4linux)
        │                         └──────────────────────┘
        ├─── exploit ────► [Exploit Agent]   (pymetasploit3 → msfrpcd)
        │                         └──────────────────────┘
        ├─── post_exploit► [Post-Exploit]    (linpeas, GTFOBins)
        │                         └──────────────────────┘
        └─── report ─────► [Reporting Agent] (Jinja2 + weasyprint → PDF)
                                    |
                             [SQLite StateStore]
```

---

## 🚀 Prerequisites

### System
- **OS**: Kali Linux, Ubuntu 22+, or Kali WSL2 (recommended)
- **Python**: 3.11+
- **Tools in PATH**:
  ```bash
  sudo apt install nmap gobuster nikto enum4linux metasploit-framework
  ```
- **System libs** (for PDF generation):
  ```bash
  sudo apt install libpango-1.0-0 libpangoft2-1.0-0
  ```

### Accounts
- **Together AI** (free tier) — [Sign up here](https://api.together.ai/signup)
  - Get your API key from the dashboard
  - Free tier: 10M tokens/month — sufficient for SPIDER

### Lab environment
- **Target**: [Metasploitable 2](https://sourceforge.net/projects/metasploitable/) in VirtualBox
- **Network**: Host-only adapter (e.g. `192.168.56.0/24`)
- **Metasploit RPC daemon** (for exploitation phase):
  ```bash
  msfrpcd -P yourpassword -S -a 127.0.0.1
  ```

---

## 📦 Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/spider.git
cd spider

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install SPIDER
pip install -r requirements.txt
pip install -e .

# 4. Configure environment
cp .env.example .env
# Edit .env — add your TOGETHER_API_KEY and MSF_RPC_PASSWORD

# 5. Verify installation
spider --help
```

---

## ⚙️ Configuration

Edit `.env` with your settings:

```bash
# Together AI (required)
TOGETHER_API_KEY="your_key_here"
TOGETHER_MODEL="Qwen/Qwen2.5-72B-Instruct-Turbo"

# Metasploit RPC (required for exploitation phase)
MSF_RPC_HOST="127.0.0.1"
MSF_RPC_PORT="55553"
MSF_RPC_PASSWORD="yourmsfrpcpassword"

# Output paths
SPIDER_DB_PATH="./spider_state.db"
REPORT_DIR="./reports"
LOG_DIR="./logs"
```

---

## 🎯 Usage

### Full automated pentest
```bash
spider run --target 192.168.56.101
```

### Resume from a specific phase
```bash
spider run --target 192.168.56.101 --start-from enumerate
spider run --target 192.168.56.101 --start-from exploit
spider run --target 192.168.56.101 --start-from report
```

### Check run status
```bash
spider status
```

### Regenerate report from stored data
```bash
spider report --target 192.168.56.101
```

### Run pre-flight checks only
```bash
spider preflight --target 192.168.56.101
```

### Clear state database
```bash
spider clean
spider clean --target 192.168.56.101
```

---

## 📊 Example Output

### Terminal (Rich UI)

```
  ███████╗██████╗ ██╗██████╗ ███████╗██████╗
  ...
  System for Penetration Testing, Intelligence, Discovery, Exploit & Recon
  Version 1.0.0  |  Target: 192.168.56.101

14:32:01 [SYSTEM] Running pre-flight checks...
┌──────────────────────────────────────────┐
│  Pre-Flight Checks                       │
├──────────────────────┬────────┬──────────┤
│  nmap                │ ✓ PASS │ 7.94     │
│  gobuster            │ ✓ PASS │ found    │
│  nikto               │ ✓ PASS │ found    │
│  Together AI API key │ ✓ PASS │ ...abc12 │
│  Target reachable    │ ✓ PASS │ ping OK  │
│  msfrpcd             │ ✓ PASS │ 127.0.0.1│
└──────────────────────┴────────┴──────────┘

╭─ ORCHESTRATOR ─────────────────────────────╮
│ Round 1                                    │
│ >> Next Agent: RECON                       │
│ Reasoning: No port data. Must scan first.  │
╰────────────────────────────────────────────╯

14:32:02 [RECON] Starting nmap scan against 192.168.56.101...
⠸ nmap -sV -sC 192.168.56.101...  0:02:21

Recon Results — 23 Open Ports
┌──────┬───────┬─────────────┬─────────────────────┐
│ Port │ Proto │ Service     │ Version             │
├──────┼───────┼─────────────┼─────────────────────┤
│   21 │ tcp   │ ftp         │ vsftpd 2.3.4        │
│   22 │ tcp   │ ssh         │ OpenSSH 4.7p1       │
│   80 │ tcp   │ http        │ Apache 2.2.8        │
│  139 │ tcp   │ netbios-ssn │ Samba smbd 3.X      │
│  445 │ tcp   │ microsoft-ds│ Samba smbd 3.X      │
└──────┴───────┴─────────────┴─────────────────────┘

...

>> EXPLOIT SUCCESS — Session ID: 1
Report: ./reports/2026-04-17_1200_192-168-56-101.pdf
```

### Generated Report

The HTML/PDF report includes:
- Cover page with severity summary
- Executive summary (LLM-generated)
- Full attack chain timeline
- Open ports table
- Finding cards with CVSS, CVE, ATT&CK TTP
- Credentials harvested
- Privilege escalation paths
- MITRE ATT&CK mapping table

---

## 🗄️ Database Structure

SQLite (`spider_state.db`) stores all pentest data:

| Table          | Purpose                               |
|----------------|---------------------------------------|
| `runs`         | Engagement runs (one per target/run)  |
| `open_ports`   | nmap scan results                     |
| `findings`     | Vulnerability findings with CVE/CVSS  |
| `sessions`     | Metasploit sessions opened            |
| `privesc_vectors` | Privilege escalation paths         |
| `credentials`  | Harvested credentials                 |

---

## 🧪 Running Tests

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=spider --cov-report=term-missing
```

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Agent Framework | LangGraph 0.2.28 |
| LLM | Qwen2.5-72B-Instruct-Turbo (Together AI) |
| CLI | Click 8.1.8 |
| Terminal UI | Rich 13.9.4 |
| Database | SQLite + SQLAlchemy 2.0 |
| Metasploit | pymetasploit3 1.0.3 |
| Report HTML | Jinja2 3.1.4 |
| Report PDF | weasyprint 62.3 |
| nmap parsing | python-libnmap 0.7.3 |

---

## 🗺️ Roadmap

- [ ] Shodan integration in Recon Agent
- [ ] Multiple target support (CIDR ranges)
- [ ] Flask web dashboard (live agent activity)
- [ ] Docker container for portable deployment
- [ ] BloodHound AD integration
- [ ] Ollama fallback (local LLM, no API key required)

---

## ⚠️ Ethical Use

**SPIDER must only be used against systems you own or have explicit written authorization to test.**

See [DISCLAIMER.md](DISCLAIMER.md) for full ethical use requirements.

Recommended lab targets:
- [Metasploitable 2](https://sourceforge.net/projects/metasploitable/)
- [DVWA](https://dvwa.co.uk/)
- [HackTheBox](https://hackthebox.com) (official VPN environments)
- [TryHackMe](https://tryhackme.com) (openvpn environments)

---

## 📄 License

MIT — see [LICENSE](LICENSE)
