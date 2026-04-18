"""
SPIDER — LLM Client
Uses the openai SDK pointed at OpenRouter's API (recommended integration path).
Includes exponential backoff for the 8 RPM free-tier rate limit.
"""

from __future__ import annotations

import json
import re
import time

import httpx
from openai import OpenAI, RateLimitError

from spider.config import (
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    OPENROUTER_MODEL,
    LLM_MAX_TOKENS,
)

# Lazy singleton — created once and reused
_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        if not OPENROUTER_API_KEY:
            raise RuntimeError(
                "OPENROUTER_API_KEY is not set. "
                "Add it to your .env file: OPENROUTER_API_KEY=\"sk-or-v1-...\""
            )
        _client = OpenAI(
            api_key=OPENROUTER_API_KEY,
            base_url=OPENROUTER_BASE_URL,
            http_client=httpx.Client(),
            default_headers={
                "HTTP-Referer": "https://github.com/spider-framework/spider",
                "X-Title": "SPIDER Pentest Framework",
            },
        )
    return _client


def call_qwen(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = None,
    temperature: float = 0.1,
) -> str:
    """
    Call Qwen via OpenRouter with exponential backoff on rate limits.
    Returns the raw text response (may be JSON or prose).
    """
    max_tokens = max_tokens or LLM_MAX_TOKENS
    client = _get_client()

    for attempt in range(5):
        try:
            response = client.chat.completions.create(
                model=OPENROUTER_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return response.choices[0].message.content.strip()
        except RateLimitError as e:
            if attempt < 4:
                # OpenRouter free tier: 8 RPM — wait long enough for bucket to reset
                wait_time = 10 * (2 ** attempt)  # 10s, 20s, 40s, 80s
                print(f"[!] Rate limit hit. Waiting {wait_time}s before retry {attempt + 1}/4... ({e})")
                time.sleep(wait_time)
                continue
            raise

    raise RuntimeError("LLM call failed after 5 retries")


def call_qwen_json(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = None,
) -> dict | list:
    """
    Call Qwen and parse JSON response.
    Falls back to extracting JSON from markdown blocks if needed.
    Raises ValueError if no valid JSON found.
    """
    raw = call_qwen(system_prompt, user_prompt, max_tokens=max_tokens)

    # Direct parse
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Strip markdown code fences (```json ... ```)
    stripped = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # Try to extract first {...} or [...] block
    obj_match = re.search(r"\{.*\}", raw, re.DOTALL)
    arr_match = re.search(r"\[.*\]", raw, re.DOTALL)

    if arr_match:
        try:
            return json.loads(arr_match.group())
        except json.JSONDecodeError:
            pass

    if obj_match:
        try:
            return json.loads(obj_match.group())
        except json.JSONDecodeError:
            pass

    raise ValueError(f"LLM returned non-JSON response:\n{raw[:500]}")
