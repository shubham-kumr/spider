"""
SPIDER — LLM Client (Together AI / Qwen)
OpenAI-compatible client pointed at Together AI with exponential backoff on rate limits.
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

# Lazy singleton — instantiated on first use
_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        # Creating a custom httpx.Client bypasses proxy issues
        # in legacy openai wrappers where 'proxies' kwarg errors occur.
        http_client = httpx.Client()
        _client = OpenAI(
            api_key=OPENROUTER_API_KEY,
            base_url=OPENROUTER_BASE_URL,
            http_client=http_client
        )
    return _client


def call_qwen(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = None,
    temperature: float = 0.1,
) -> str:
    """
    Call Qwen via OpenRouter AI with exponential backoff on rate limits.
    Returns the raw text response (may be JSON or prose).
    """
    max_tokens = max_tokens or LLM_MAX_TOKENS
    client = _get_client()

    for attempt in range(4):
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
        except RateLimitError:
            if attempt < 3:
                wait = 2 ** attempt  # 1s, 2s, 4s
                time.sleep(wait)
                continue
            raise
        except Exception:
            raise

    raise RuntimeError("LLM call failed after 4 retries")


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
