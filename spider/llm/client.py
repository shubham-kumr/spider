"""
SPIDER — LLM Client (Together AI / Qwen)
OpenAI-compatible client pointed at Together AI with exponential backoff on rate limits.
"""

from __future__ import annotations

import json
import re
import time
from openrouter import OpenRouter

from spider.config import (
    OPENROUTER_API_KEY,
    OPENROUTER_MODEL,
    LLM_MAX_TOKENS,
)


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

    for attempt in range(5):
        try:
            with OpenRouter(
                api_key=OPENROUTER_API_KEY,
            ) as client:
                response = client.chat.send(
                    model=OPENROUTER_MODEL,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ]
                )
                return response.choices[0].message.content.strip()
        except Exception as e:
            err_str = str(e).lower()
            if attempt < 4 and ("429" in err_str or "rate limit" in err_str):
                # OpenRouter free tier limits are often 8 RPM
                wait_time = 10 * (2 ** attempt)  # 10s, 20s, 40s, 80s
                print(f"[!] OpenRouter Rate Limit Exceeded. Waiting {wait_time}s before retry {attempt+1}... ({e})")
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
