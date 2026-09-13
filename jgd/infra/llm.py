"""Dual-model LLM client for adversarial auditing (finder + verifier).

Both models are configured via `config/models.json` or environment variables.
No keys are stored in the repository. See `config/models.example.json`.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from pathlib import Path

from jgd import PROJECT_ROOT

CONFIG = PROJECT_ROOT / "config" / "models.json"


def _load_config() -> dict:
    """Load model config from config/models.json or env vars."""
    if CONFIG.exists():
        return json.loads(CONFIG.read_text(encoding="utf-8"))
    return {
        "finder": {
            "endpoint": os.environ.get("JGD_FINDER_ENDPOINT", ""),
            "api_key": os.environ.get("JGD_FINDER_API_KEY", ""),
            "model": os.environ.get("JGD_FINDER_MODEL", ""),
            "protocol": os.environ.get("JGD_FINDER_PROTOCOL", "openai"),
        },
        "verifier": {
            "endpoint": os.environ.get("JGD_VERIFIER_ENDPOINT", ""),
            "api_key": os.environ.get("JGD_VERIFIER_API_KEY", ""),
            "model": os.environ.get("JGD_VERIFIER_MODEL", ""),
            "protocol": os.environ.get("JGD_VERIFIER_PROTOCOL", "openai"),
        },
    }


def _call(cfg: dict, system: str, user: str, temperature: float,
          max_tokens: int, timeout: int = 150) -> dict:
    """Generic OpenAI-compatible or Anthropic-compatible API call."""
    url = cfg["endpoint"]
    key = cfg["api_key"]
    model = cfg["model"]
    proto = cfg.get("protocol", "openai")

    if not url or not key or not model:
        return {"ok": False, "error": "model-not-configured", "content": ""}

    if proto == "anthropic":
        body = json.dumps({
            "model": model, "max_tokens": max_tokens, "system": system,
            "thinking": {"type": "disabled"},
            "messages": [{"role": "user", "content": user}]}).encode()
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01",
                   "Content-Type": "application/json"}
    else:
        body = json.dumps({
            "model": model, "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}]}).encode()
        headers = {"Authorization": f"Bearer {key}",
                   "Content-Type": "application/json"}

    req = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read().decode())

    if proto == "anthropic":
        content = "".join(b.get("text", "") for b in data.get("content", [])
                          if b.get("type") == "text")
    else:
        content = data["choices"][0]["message"]["content"]

    return {"ok": True, "model": model, "content": content,
            "usage": data.get("usage", {})}


def ask(role: str, system: str, user: str, temperature: float = 0.2,
        max_tokens: int = 2400, timeout: int = 150) -> dict:
    """Call a model by role ('finder' or 'verifier')."""
    role = role if role in ("finder", "verifier", "glm", "ds") else "finder"
    if role == "glm":
        role = "finder"
    elif role == "ds":
        role = "verifier"

    cfg = _load_config().get(role, {})
    if not cfg.get("endpoint"):
        return {"role": role, "ok": False, "error": "model-not-configured",
                "content": ""}

    try:
        time.sleep(1)
        out = _call(cfg, system, user, temperature, max_tokens, timeout)
        out["role"] = role
        return out
    except Exception as e:
        return {"role": role, "ok": False,
                "error": f"{type(e).__name__}: {str(e)[:120]}", "content": ""}


def key_of(role: str) -> str:
    """Check if a role has a configured API key."""
    role = {"glm": "finder", "ds": "verifier"}.get(role, role)
    cfg = _load_config().get(role, {})
    return cfg.get("api_key", "")


def extract_json(text: str) -> dict | list | None:
    """Extract JSON from LLM response text (handles fenced code blocks)."""
    if not text:
        return None
    fenced = text.split("```")
    for chunk in ([fenced[1][4:]] if len(fenced) > 1 else []) + [text]:
        try:
            return json.loads(chunk.strip())
        except Exception:
            continue
    start = min([i for i in (text.find("{"), text.find("[")) if i >= 0],
                default=-1)
    if start < 0:
        return None
    for end in range(len(text), start, -1):
        try:
            return json.loads(text[start:end])
        except Exception:
            continue
    return None
