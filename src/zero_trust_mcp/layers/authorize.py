from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..decisions import PolicyDeniedError
from ..pipeline.context import CallContext
from ..policy.engine import PolicyEngine


def authorize_layer(engine: PolicyEngine):
    def _layer(ctx: CallContext, nxt: Callable[[], Any]) -> Any:
        decision = engine.evaluate(ctx.tool_call)
        ctx.decision = decision
        ctx.layer = decision.layer or "authorize"
        if not decision.allowed:
            raise PolicyDeniedError(decision)
        return nxt()

    return _layer
