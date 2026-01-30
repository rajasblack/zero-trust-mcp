from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..decisions import Decision
from ..models import ToolCall


@dataclass(slots=True)
class CallContext:
    tool_call: ToolCall
    policy_id: str
    start_ns: int

    decision: Decision | None = None
    tool_result: Any = None
    error: BaseException | None = None

    layer: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


LayerFunc = Callable[[CallContext, Callable[[], Any]], Any]
