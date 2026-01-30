from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..pipeline.context import CallContext
from ..policy.schema import RedactConfig
from ..redaction import redact_value


def redact_layer(cfg: RedactConfig | None):
    def _layer(ctx: CallContext, nxt: Callable[[], Any]) -> Any:
        out = nxt()
        if cfg is None or not cfg.enabled:
            return out

        redacted = redact_value(
            out,
            deny_keys=cfg.deny_keys,
            pii_emails=cfg.pii_emails,
            pii_phones=cfg.pii_phones,
            max_string_len=cfg.max_string_len or 0,
        )
        ctx.tool_result = redacted
        return redacted

    return _layer
