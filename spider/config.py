"""
SPIDER Configuration Loader
Loads all settings from .env file via python-dotenv.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Always find .env from the project root (parent of the spider/ package)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_PATH = _PROJECT_ROOT / ".env"
load_dotenv(_ENV_PATH)

# ── OpenRouter (Qwen) ──────────────────────────────────────────
OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "").strip()
OPENROUTER_BASE_URL: str = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").strip()
OPENROUTER_MODEL: str = os.getenv("OPENROUTER_MODEL", "qwen/qwen3-coder:free").strip()
LLM_MAX_TOKENS: int = int(os.getenv("OPENROUTER_MAX_TOKENS", os.getenv("LLM_MAX_TOKENS", "2048")))

# Startup diagnostic (safe — only shows key length + first 10 chars)
if OPENROUTER_API_KEY:
    print(f"[CONFIG] .env loaded from: {_ENV_PATH}")
    print(f"[CONFIG] OPENROUTER_API_KEY: len={len(OPENROUTER_API_KEY)}, starts with '{OPENROUTER_API_KEY[:10]}...'")
else:
    print(f"[CONFIG] WARNING: OPENROUTER_API_KEY is empty! Checked: {_ENV_PATH}")


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
