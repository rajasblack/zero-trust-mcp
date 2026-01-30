from __future__ import annotations

import re
from typing import Any

DEFAULT_DENY_KEYS = ["password", "token", "secret", "api_key", "authorization"]

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")


def _should_redact_key(key: str, deny_keys: list[str]) -> bool:
    k = key.lower()
    return any(k == dk.lower() for dk in deny_keys)


def redact_value(
    value: Any,
    *,
    deny_keys: list[str] | None = None,
    pii_emails: bool = True,
    pii_phones: bool = False,
    max_string_len: int = 2048,
) -> Any:
    deny_keys = deny_keys or DEFAULT_DENY_KEYS

    if value is None:
        return None

    if isinstance(value, str):
        s = value
        if max_string_len and len(s) > max_string_len:
            s = s[:max_string_len] + "…"
        if pii_emails:
            s = EMAIL_RE.sub("[REDACTED_EMAIL]", s)
        if pii_phones:
            s = PHONE_RE.sub("[REDACTED_PHONE]", s)
        return s

    if isinstance(value, (int, float, bool)):
        return value

    if isinstance(value, list):
        return [redact_value(v, deny_keys=deny_keys, pii_emails=pii_emails, pii_phones=pii_phones, max_string_len=max_string_len) for v in value]

    if isinstance(value, tuple):
        return tuple(
            redact_value(v, deny_keys=deny_keys, pii_emails=pii_emails, pii_phones=pii_phones, max_string_len=max_string_len)
            for v in value
        )

    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and _should_redact_key(k, deny_keys):
                out[k] = "[REDACTED]"
            else:
                out[str(k)] = redact_value(
                    v,
                    deny_keys=deny_keys,
                    pii_emails=pii_emails,
                    pii_phones=pii_phones,
                    max_string_len=max_string_len,
                )
        return out

    # fallback for unknown objects
    try:
        return redact_value(
            str(value),
            deny_keys=deny_keys,
            pii_emails=pii_emails,
            pii_phones=pii_phones,
            max_string_len=max_string_len,
        )
    except Exception:
        return "[REDACTED]"
