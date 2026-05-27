"""Unified AI provider — tries Groq (free) → OpenRouter (free) → OpenAI → Anthropic."""

import logging
from src.env import ENV

logger = logging.getLogger("phishguard-providers")


# ── HTTP helper for provider APIs (zero extra deps) ──────────────────────


def _http_post_json(url: str, headers: dict, payload: dict, timeout: int = 30) -> dict:
    import json
    import urllib.request
    import urllib.error
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        logger.warning("HTTP %s from %s: %s", e.code, url, body[:200])
        return {}
    except Exception as e:
        logger.warning("Request to %s failed: %s", url, e)
        return {}


# ── Groq (free tier: ~30 req/min, models: mixtral, llama) ───────────────


GROQ_MODEL = "mixtral-8x7b-32768"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def _groq_completion(system: str, user: str, max_tokens: int = 1000) -> str | None:
    if not ENV.GROQ_API_KEY:
        return None
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }
    headers = {
        "Authorization": f"Bearer {ENV.GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    data = _http_post_json(GROQ_URL, headers, payload)
    choices = data.get("choices", [])
    if choices:
        return choices[0].get("message", {}).get("content", "")
    logger.warning("Groq returned no choices: %s", str(data)[:200])
    return None


# ── OpenRouter (free tier: many models, credits per day) ─────────────────


OPENROUTER_MODEL = "meta-llama/llama-3.1-8b-instruct:free"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


def _openrouter_completion(system: str, user: str, max_tokens: int = 1000) -> str | None:
    if not ENV.OPENROUTER_API_KEY:
        return None
    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }
    headers = {
        "Authorization": f"Bearer {ENV.OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://phishguard-ai.hf.space",
    }
    data = _http_post_json(OPENROUTER_URL, headers, payload)
    choices = data.get("choices", [])
    if choices:
        return choices[0].get("message", {}).get("content", "")
    logger.warning("OpenRouter returned no choices: %s", str(data)[:200])
    return None


# ── OpenAI (paid) ────────────────────────────────────────────────────────


def _openai_completion(system: str, user: str, max_tokens: int = 1000) -> str | None:
    if not ENV.OPENAI_API_KEY:
        return None
    try:
        from openai import OpenAI
        client = OpenAI(api_key=ENV.OPENAI_API_KEY)
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=max_tokens,
            temperature=0.3,
        )
        return resp.choices[0].message.content or ""
    except Exception as e:
        logger.warning("OpenAI failed: %s", e)
        return None


# ── Anthropic (paid) ─────────────────────────────────────────────────────


def _anthropic_completion(system: str, user: str, max_tokens: int = 1000) -> str | None:
    if not ENV.ANTHROPIC_API_KEY:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ENV.ANTHROPIC_API_KEY)
        resp = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return resp.content[0].text
    except Exception as e:
        logger.warning("Anthropic failed: %s", e)
        return None


# ── Public API ───────────────────────────────────────────────────────────


def get_completion(
    system_prompt: str,
    user_message: str,
    max_tokens: int = 1000,
) -> str:
    """Try each provider in priority order. Returns response text or an error message."""
    chain = [
        ("Groq (free)", _groq_completion),
        ("OpenRouter (free)", _openrouter_completion),
        ("OpenAI", _openai_completion),
        ("Anthropic", _anthropic_completion),
    ]
    for name, fn in chain:
        try:
            result = fn(system_prompt, user_message, max_tokens)
            if result:
                logger.info("AI response from %s", name)
                return result
        except Exception as e:
            logger.warning("%s raised: %s", name, e)
    return (
        "⚠ No AI provider available. Configure one of: "
        "`GROQ_API_KEY`, `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY`."
    )


def get_chat_completion(
    messages: list,
    system_prompt: str = "",
    max_tokens: int = 1000,
) -> str:
    """Multi-turn chat via provider chain. messages: list of {"role", "content"}."""
    last_user = ""
    for m in messages:
        if m.get("role") == "user":
            last_user = m.get("content", "")

    context_parts = []
    if system_prompt:
        context_parts.append(f"[System]\n{system_prompt}")
    for m in messages[:-1] if len(messages) > 1 else []:
        role = m.get("role", "user")
        text = m.get("content", "")
        if text.strip():
            context_parts.append(f"[{role.upper()}]\n{text}")
    context_parts.append(f"[USER]\n{last_user}")
    combined_user = "\n\n".join(context_parts)

    return get_completion(system_prompt, combined_user, max_tokens)


def get_available_provider() -> str:
    """Return the name of the first configured provider, or 'none'."""
    if ENV.GROQ_API_KEY:
        return "groq"
    if ENV.OPENROUTER_API_KEY:
        return "openrouter"
    if ENV.OPENAI_API_KEY:
        return "openai"
    if ENV.ANTHROPIC_API_KEY:
        return "anthropic"
    return "none"
