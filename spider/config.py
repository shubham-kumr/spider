"""
SPIDER Configuration Loader
Loads all settings from .env file via python-dotenv.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── OpenRouter (Qwen) ──────────────────────────────────────────
OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "").strip()
OPENROUTER_BASE_URL: str = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
OPENROUTER_MODEL: str = os.getenv("OPENROUTER_MODEL", "qwen/qwen3-coder:free")
LLM_MAX_TOKENS: int = int(os.getenv("LLM_MAX_TOKENS", "2048"))


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
