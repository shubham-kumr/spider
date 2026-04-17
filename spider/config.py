"""
SPIDER Configuration Loader
Loads all settings from .env file via python-dotenv.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── Together AI (Qwen) ──────────────────────────────────────────
TOGETHER_API_KEY: str = os.getenv("TOGETHER_API_KEY", "")
TOGETHER_BASE_URL: str = os.getenv("TOGETHER_BASE_URL", "https://api.together.xyz/v1")
TOGETHER_MODEL: str = os.getenv("TOGETHER_MODEL", "Qwen/Qwen2.5-72B-Instruct-Turbo")
TOGETHER_MAX_TOKENS: int = int(os.getenv("TOGETHER_MAX_TOKENS", "1024"))

# ── Metasploit RPC ───────────────────────────────────────────────
MSF_RPC_HOST: str = os.getenv("MSF_RPC_HOST", "127.0.0.1")
MSF_RPC_PORT: int = int(os.getenv("MSF_RPC_PORT", "55553"))
MSF_RPC_PASSWORD: str = os.getenv("MSF_RPC_PASSWORD", "")
MSF_RPC_SSL: bool = os.getenv("MSF_RPC_SSL", "true").lower() == "true"

# ── SQLite ───────────────────────────────────────────────────────
SPIDER_DB_PATH: str = os.getenv("SPIDER_DB_PATH", "./spider_state.db")

# ── Logging ──────────────────────────────────────────────────────
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
LOG_DIR: str = os.getenv("LOG_DIR", "./logs")

# ── Report Output ────────────────────────────────────────────────
REPORT_DIR: str = os.getenv("REPORT_DIR", "./reports")

# ── UI ───────────────────────────────────────────────────────────
SPIDER_NO_RICH: bool = os.getenv("SPIDER_NO_RICH", "false").lower() == "true"

# ── Version ──────────────────────────────────────────────────────
SPIDER_VERSION: str = "1.0.0"
