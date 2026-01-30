from __future__ import annotations

from typing import Any, Callable

from ..decisions import Decision, PolicyDeniedError
from ..pipeline.context import CallContext
from ..policy.schema import ValidateConfig


def validate_layer(policy_id: str, cfg: ValidateConfig | None):
    def _layer(ctx: CallContext, nxt: Callable[[], Any]) -> Any:
        if cfg is None:
            return nxt()

        if cfg.max_arg_bytes:
            size = ctx.tool_call.arguments_size_bytes()
            if size > cfg.max_arg_bytes:
                decision = Decision(
                    allowed=False,
                    reason=f"Arguments too large (>{cfg.max_arg_bytes} bytes)",
                    policy_id=policy_id,
                    remediation="Reduce arguments payload size.",
                    layer="validate",
                )
                ctx.decision = decision
                ctx.layer = "validate"
                raise PolicyDeniedError(decision)

        return nxt()

    return _layer
