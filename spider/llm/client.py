"""
SPIDER — LLM Client
Direct requests.post to OpenRouter with explicit Authorization: Bearer header.
Includes exponential backoff for the 8 RPM free-tier rate limit.
"""

from __future__ import annotations

import json
import re
import time

import requests

from spider.config import (
    OPENROUTER_API_KEY,
    OPENROUTER_MODEL,
    LLM_MAX_TOKENS,
)

_OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"

# Reusable session for connection pooling
_session: requests.Session | None = None


def _get_session() -> requests.Session:
    """Create or return a persistent requests.Session with auth headers."""
    global _session
    if _session is None:
        key = OPENROUTER_API_KEY.strip()
        print(f"[DEBUG] OPENROUTER_API_KEY: len={len(key)}, prefix={key[:10]!r}")
        if not key or key.startswith("your_"):
            raise RuntimeError(
                "OPENROUTER_API_KEY is missing or still set to the placeholder.\n"
                "  1. Get your key at https://openrouter.ai/keys\n"
                "  2. Set it in .env:  OPENROUTER_API_KEY=\"sk-or-v1-...\""
            )
        _session = requests.Session()
        _session.headers.update({
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/spider-framework/spider",
            "X-Title": "SPIDER Pentest Framework",
        })
        # Debug: confirm the exact header value (masked)
        auth_header = _session.headers.get("Authorization", "")
        print(f"[DEBUG] Authorization header set: {auth_header[:20]}...{auth_header[-6:]}")
    return _session


def call_qwen(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = None,
    temperature: float = 0.1,
) -> str:
    """
    POST to OpenRouter using requests with an explicit Authorization header.
    Tests primary model, backs off on 429, and cleanly falls back to a secondary
    model if persistent rate limits are encountered.
    """
    session = _get_session()
    max_tokens = max_tokens or LLM_MAX_TOKENS

    models_to_try = []
    if OPENROUTER_MODEL not in models_to_try:
        models_to_try.append(OPENROUTER_MODEL)
    
    fallback = "qwen/qwen3-next-80b-a3b-instruct:free"
    if fallback not in models_to_try:
        models_to_try.append(fallback)

    payload = {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }

    last_error = None

    for model_name in models_to_try:
        payload["model"] = model_name
        print(f"[LLM] Attempting request with model: {model_name}")

        for attempt in range(4):
            try:
                resp = session.post(
                    _OPENROUTER_ENDPOINT,
                    json=payload,
                    timeout=120,
                )

                if resp.status_code == 429:
                    try:
                        err_msg = resp.json().get("error", {}).get("message", resp.text)
                    except Exception:
                        err_msg = resp.text
                        
                    last_error = f"429 Rate Limit: {err_msg}"
                    if attempt < 3:
                        wait_time = 10 * (2 ** attempt)  # 10s, 20s, 40s
                        print(f"[!] Rate limit hit (429) on {model_name}: {err_msg}")
                        print(f"[!] Waiting {wait_time}s before retry {attempt + 1}/3...")
                        time.sleep(wait_time)
                        continue
                    else:
                        print(f"[!] Exhausted retries for {model_name}. Falling back...")
                        break  # Break inner loop to try next model

                if resp.status_code != 200:
                    # Dump actual request headers for debugging
                    print(f"[DEBUG] Request headers sent: { {k: (v[:20]+'...' if len(v)>20 else v) for k,v in resp.request.headers.items()} }")
                    last_error = f"HTTP {resp.status_code}: {resp.text}"
                    print(f"[!] API Error on {model_name}: {last_error}")
                    break  # Break inner loop on hard 4xx/5xx errors

                data = resp.json()
                return data["choices"][0]["message"]["content"].strip()

            except requests.exceptions.Timeout:
                last_error = "Timeout"
                if attempt < 3:
                    print(f"[!] Request timed out on {model_name}. Retrying ({attempt + 1}/3)...")
                    time.sleep(5)
                    continue
                else:
                    print(f"[!] Exhausted timeouts for {model_name}. Falling back...")
                    break  # Break inner loop

    raise RuntimeError(f"LLM call failed for all models. Last error: {last_error}")


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
