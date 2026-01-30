from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..decisions import Decision
from ..models import ToolCall


@dataclass(slots=True)
class CallContext:
    """Context for a single tool call through the pipeline."""

    tool_call: ToolCall
    policy_id: str
    start_ns: int = 0
    decision: Decision | None = None
    layer: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
    tool_result: Any = None


LayerFunc = Callable[[CallContext, Callable[[], Any]], Any]
