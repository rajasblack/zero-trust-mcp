from __future__ import annotations

from typing import Any, Callable

from ..audit.logger import AuditLogger
from ..pipeline.context import CallContext
from ..policy.schema import AuditConfig


def audit_layer(audit_logger: AuditLogger | None, cfg: AuditConfig | None):
    def _layer(ctx: CallContext, nxt: Callable[[], Any]) -> Any:
        try:
            out = nxt()
            if audit_logger and (cfg is None or cfg.enabled):
                audit_logger.log(
                    action="tool_call",
                    tool_name=ctx.tool_call.tool_name,
                    decision="allow",
                    reason=(ctx.decision.reason if ctx.decision else "Allowed"),
                    policy_id=ctx.policy_id,
                    actor=ctx.tool_call.actor,
                    request_id=ctx.tool_call.request_id,
                    arguments=ctx.tool_call.arguments,
                    layer=(ctx.decision.layer if ctx.decision else ctx.layer),
                    latency_ms=ctx.meta.get("latency_ms"),
                    client=ctx.tool_call.client,
                    result=out,
                    include_result=bool(cfg and cfg.include_result),
                    include_argument_values=bool(cfg and cfg.include_argument_values),
                )
            return out
        except Exception as e:
            if audit_logger and (cfg is None or cfg.enabled):
                audit_logger.log(
                    action="tool_call",
                    tool_name=ctx.tool_call.tool_name,
                    decision="deny" if (ctx.decision and not ctx.decision.allowed) else "error",
                    reason=(ctx.decision.reason if ctx.decision else str(e)),
                    policy_id=ctx.policy_id,
                    actor=ctx.tool_call.actor,
                    request_id=ctx.tool_call.request_id,
                    arguments=ctx.tool_call.arguments,
                    layer=(ctx.decision.layer if ctx.decision else ctx.layer),
                    latency_ms=ctx.meta.get("latency_ms"),
                    client=ctx.tool_call.client,
                    result=None,
                    include_result=False,
                    include_argument_values=bool(cfg and cfg.include_argument_values),
                )
            raise

    return _layer
