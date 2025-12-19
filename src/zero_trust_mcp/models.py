"""
Pydantic models for Zero Trust MCP.
"""

from typing import Any

from pydantic import BaseModel, Field


class ToolCall(BaseModel):
    """
    Represents a tool/function call to be evaluated against policies.

    Attributes:
        tool_name: Name of the tool being called
        arguments: Dictionary of arguments passed to the tool
        actor: Optional identifier of who is making the call (e.g., user email)
        request_id: Optional unique request identifier for audit trail
    """

    tool_name: str = Field(..., description="Name of the tool being called")
    arguments: dict[str, Any] = Field(
        default_factory=dict, description="Arguments passed to the tool"
    )
    actor: str | None = Field(
        None, description="Actor making the call (e.g., user email or service name)"
    )
    request_id: str | None = Field(None, description="Unique request identifier")

    model_config = {
        "json_schema_extra": {
            "example": {
                "tool_name": "search",
                "arguments": {"query": "urgent items"},
                "actor": "user@example.com",
                "request_id": "req-12345",
            }
        }
    }
