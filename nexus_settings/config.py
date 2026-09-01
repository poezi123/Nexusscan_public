from __future__ import annotations

import json
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "nexus_config.json"

SCHEMA: dict[str, tuple[str, object, type]] = {
    "ai_backend":     ("NEXUS_AI_BACKEND",        "auto",                    str),
    "ollama_url":     ("NEXUS_AI_OLLAMA_URL",      "http://localhost:11434",  str),
    "ollama_model":   ("NEXUS_AI_OLLAMA_MODEL",    "",                        str),
    "local_url":      ("NEXUS_AI_LOCAL_URL",       "",                        str),
    "local_model":    ("NEXUS_AI_LOCAL_MODEL",     "",                        str),
    "max_tokens":     ("NEXUS_AI_MAX_TOKENS",      1500,                      int),
    "timeout":        ("NEXUS_AI_TIMEOUT",         600,                       int),
    "followup_mode":  ("NEXUS_AI_FOLLOWUP",        "auto",                    str),
    "web_default":    ("NEXUS_AI_WEB_DEFAULT",     True,                      bool),
}

DEFAULTS = {key: default for key, (_env, default, _t) in SCHEMA.items()}


def _coerce(value, typ):
    try:
        if typ is bool:
            if isinstance(value, str):
                return value.strip().lower() in ("1", "true", "yes", "on", "ja", "y")
            return bool(value)
        if typ is int:
            return int(str(value).strip())
        return str(value)
    except (TypeError, ValueError):
        return None


def load() -> dict:
    settings = dict(DEFAULTS)
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                on_disk = json.load(f)
            for key in DEFAULTS:
                if key in on_disk:
                    coerced = _coerce(on_disk[key], SCHEMA[key][2])
                    if coerced is not None:
                        settings[key] = coerced
        except (json.JSONDecodeError, OSError):
            pass
    return settings


def save(settings: dict) -> None:
    to_write = {}
    for key in DEFAULTS:
        value = settings.get(key, DEFAULTS[key])
        coerced = _coerce(value, SCHEMA[key][2])
        to_write[key] = DEFAULTS[key] if coerced is None else coerced
    tmp = CONFIG_PATH.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(to_write, f, indent=2)
    tmp.replace(CONFIG_PATH)


def resolve(key: str):
    env_name, default, typ = SCHEMA[key]
    env_value = os.getenv(env_name)
    if env_value is not None and env_value != "":
        coerced = _coerce(env_value, typ)
        if coerced is not None:
            return coerced
    return load().get(key, default)
