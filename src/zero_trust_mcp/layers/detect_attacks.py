from __future__ import annotations

import re
from typing import Any, Callable, Iterable

from ..decisions import Decision, PolicyDeniedError
from ..pipeline.context import CallContext
from ..policy.schema import DetectAttacksConfig

SQLI_RE = re.compile(r"(?i)\b(select|union|insert|update|delete|drop|alter)\b")
TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\)")
SSRF_RE = re.compile(r"(?i)\b(169\.254\.169\.254|localhost|127\.0\.0\.1)\b")


def _collect_strings(obj: Any, keys_of_interest: set[str]) -> Iterable[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k in keys_of_interest and isinstance(v, str):
                yield v
            yield from _collect_strings(v, keys_of_interest)
    elif isinstance(obj, list):
        for v in obj:
            yield from _collect_strings(v, keys_of_interest)


def detect_attacks_layer(policy_id: str, cfg: DetectAttacksConfig | None):
    def _layer(ctx: CallContext, nxt: Callable[[], Any]) -> Any:
        if cfg is None or not cfg.enabled:
            return nxt()

        fields = set(cfg.fields or [])
        haystacks = list(_collect_strings(ctx.tool_call.arguments or {}, fields))

        suspicious = any(SQLI_RE.search(s) or TRAVERSAL_RE.search(s) or SSRF_RE.search(s) for s in haystacks)

        if suspicious and cfg.on_detect == "deny":
            decision = Decision(
                allowed=False,
                reason="Potential injection/abuse pattern detected in arguments",
                policy_id=policy_id,
                remediation="Remove suspicious patterns from arguments.",
                layer="detect_attacks",
            )
            ctx.decision = decision
            ctx.layer = "detect_attacks"
            raise PolicyDeniedError(decision)

        return nxt()

    return _layer
