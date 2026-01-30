from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..decisions import Decision, PolicyDeniedError
from ..pipeline.context import CallContext
from ..policy.schema import RateLimitConfig
from ..rate_limit import InMemoryRateLimiter


def rate_limit_layer(
    policy_id: str, cfg: RateLimitConfig | None, limiter: InMemoryRateLimiter | None = None
):
    limiter = limiter or InMemoryRateLimiter()

    def _key(ctx: CallContext) -> str:
        tc = ctx.tool_call
        if cfg is None:
            return "global"
        if cfg.scope == "actor":
            return f"actor:{tc.actor or 'unknown'}"
        if cfg.scope == "session":
            sid = (tc.client or {}).get("session_id", "unknown")
            return f"session:{sid}"
        if cfg.scope == "tool":
            return f"tool:{tc.tool_name}"
        if cfg.scope == "actor+tool":
            return f"actor:{tc.actor or 'unknown'}:tool:{tc.tool_name}"
        return "global"

    def _layer(ctx: CallContext, nxt: Callable[[], Any]) -> Any:
        if cfg is None or not cfg.enabled or not cfg.limit_per_minute:
            return nxt()

        ok, meta = limiter.allow(_key(ctx), cfg.limit_per_minute, cfg.burst or 0)
        ctx.meta["rate_limit"] = meta
        if not ok:
            decision = Decision(
                allowed=False,
                reason="Rate limit exceeded",
                policy_id=policy_id,
                remediation="Wait and retry later.",
                layer="rate_limit",
            )
            ctx.decision = decision
            ctx.layer = "rate_limit"
            raise PolicyDeniedError(decision)

        return nxt()

    return _layer
