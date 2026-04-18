"""
SPIDER — LLM Client
Direct httpx POST to OpenRouter with an explicit Authorization: Bearer header.
No SDK auth magic — what you set is exactly what gets sent.
Includes exponential backoff for the 8 RPM free-tier rate limit.
"""

from __future__ import annotations

import json
import re
import time

import httpx

from spider.config import (
    OPENROUTER_API_KEY,
    OPENROUTER_MODEL,
    LLM_MAX_TOKENS,
)

_OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"


def _validate_key() -> str:
    """Return the API key or raise a clear error before any network call."""
    key = OPENROUTER_API_KEY.strip()
    if not key or key.startswith("your_"):
        raise RuntimeError(
            "OPENROUTER_API_KEY is missing or still set to the placeholder.\n"
            "  1. Get your key at https://openrouter.ai/keys\n"
            "  2. Set it in .env:  OPENROUTER_API_KEY=\"sk-or-v1-...\""
        )
    return key


def call_qwen(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = None,
    temperature: float = 0.1,
) -> str:
    """
    POST directly to OpenRouter using httpx with an explicit Authorization header.
    Retries up to 4 times with exponential backoff on 429 rate-limit responses.
    """
    api_key = _validate_key()
    max_tokens = max_tokens or LLM_MAX_TOKENS

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/spider-framework/spider",
        "X-Title": "SPIDER Pentest Framework",
    }
    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }

    for attempt in range(5):
        try:
            resp = httpx.post(
                _OPENROUTER_ENDPOINT,
                headers=headers,
                json=payload,
                timeout=120,
            )

            if resp.status_code == 429:
                wait_time = 10 * (2 ** attempt)  # 10s, 20s, 40s, 80s
                print(f"[!] Rate limit hit (429). Waiting {wait_time}s before retry {attempt + 1}/4...")
                time.sleep(wait_time)
                continue

            if resp.status_code != 200:
                raise RuntimeError(f"OpenRouter error {resp.status_code}: {resp.text}")

            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()

        except httpx.TimeoutException:
            if attempt < 4:
                print(f"[!] Request timed out. Retrying ({attempt + 1}/4)...")
                time.sleep(5)
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
