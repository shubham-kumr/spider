```
  ███████╗██████╗ ██╗██████╗ ███████╗██████╗
  ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗
  ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝
  ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗
  ███████║██║     ██║██████╔╝███████╗██║  ██║
  ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
```

**System for Pentesting, Initial Discovery, Exploitation & Reconnaissance - SPIDER**


**SPIDER** is an **AI-driven multi-agent offensive security framework** that automates the full penetration testing kill chain — from recon to report — using a **LangGraph** pipeline of specialized agents powered by **Qwen3 Coder (free tier via OpenRouter)**.

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
        ├─── exploit ────► [Exploit Agent]   (Manual Command Generation)
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
  sudo apt install nmap gobuster nikto enum4linux
  ```
- **System libs** (for PDF generation):
  ```bash
  sudo apt install libpango-1.0-0 libpangoft2-1.0-0
  ```

### Accounts
- **OpenRouter** (free tier) — [Sign up here](https://openrouter.ai/)
  - Get your API key from the dashboard
  - Free tier usage includes strict rate limits (up to 8 requests/min), which SPIDER automatically handles with retry logic.

### Target Environment
- **Target**: Ensure you have explicit permission to test the target
- **Reachability**: Target must be reachable by your host machine

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
# Edit .env — add your OPENROUTER_API_KEY

# 5. Verify installation
spider --help
```

---

## ⚙️ Configuration

Edit `.env` with your settings:

```bash
# OpenRouter (required)
OPENROUTER_API_KEY="your_key_here"
OPENROUTER_MODEL="qwen/qwen3-coder:free"

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

## 🗄️ Database Structure

SQLite (`spider_state.db`) stores all pentest data:

| Table          | Purpose                               |
|----------------|---------------------------------------|
| `runs`         | Engagement runs (one per target/run)  |
| `open_ports`   | nmap scan results                     |
| `findings`     | Vulnerability findings with CVE/CVSS  |
| `sessions`     | Reverse shells / sessions opened      |
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
| LLM | Qwen3 Coder (OpenRouter) |
| CLI | Click 8.1.8 |
| Terminal UI | Rich 13.9.4 |
| Database | SQLite + SQLAlchemy 2.0 |
| Report HTML | Jinja2 3.1.4 |
| Report PDF | weasyprint 62.3 |
| nmap parsing | python-libnmap 0.7.3 |

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
