"""
Pydantic models for Zero Trust MCP.
"""

import json
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
        client: Optional client information dictionary
    """

    tool_name: str = Field(..., description="Name of the tool being called")
    arguments: dict[str, Any] = Field(
        default_factory=dict, description="Arguments passed to the tool"
    )
    actor: str | None = Field(
        None, description="Actor making the call (e.g., user email or service name)"
    )
    request_id: str | None = Field(None, description="Unique request identifier")
    client: dict[str, Any] | None = Field(
        None, description="Client information (e.g., session_id, ip_address)"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "tool_name": "search",
                "arguments": {"query": "urgent items"},
                "actor": "user@example.com",
                "request_id": "req-12345",
                "client": {"session_id": "sess-123", "ip_address": "192.168.1.1"},
            }
        }
    }

    def arguments_size_bytes(self) -> int:
        """
        Calculate the size of arguments in bytes.

        Returns:
            Size of JSON-encoded arguments in bytes
        """
        return len(json.dumps(self.arguments).encode("utf-8"))
