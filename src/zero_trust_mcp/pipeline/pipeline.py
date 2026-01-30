from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from ..models import ToolCall
from ..policy.engine import PolicyEngine
from .context import CallContext, LayerFunc


class Pipeline:
    def __init__(self, *, engine: PolicyEngine, layers: list[LayerFunc] | None = None):
        self.engine = engine
        self.layers = layers or []

    def execute(self, tool_call: ToolCall, tool_fn: Callable[..., Any]) -> Any:
        ctx = CallContext(
            tool_call=tool_call,
            policy_id=self.engine.policy.policy_id,
            start_ns=time.perf_counter_ns(),
        )

        def forward() -> Any:
            return tool_fn(**(tool_call.arguments or {}))

        nxt: Callable[[], Any] = forward
        for layer in reversed(self.layers):
            prev = nxt

            def make_next(layer_func: LayerFunc, prev_nxt: Callable[[], Any]) -> Callable[[], Any]:
                return lambda: layer_func(ctx, prev_nxt)

            nxt = make_next(layer, prev)

        return nxt()

    @staticmethod
    def latency_ms(start_ns: int) -> int:
        return int((time.perf_counter_ns() - start_ns) / 1_000_000)
