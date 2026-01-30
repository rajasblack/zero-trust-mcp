"""
Enforcement wrapper for applying policies to tool calls.
"""

from collections.abc import Callable
from typing import TypeVar

from zero_trust_mcp.audit.logger import AuditLogger
from zero_trust_mcp.decisions import PolicyDeniedError
from zero_trust_mcp.models import ToolCall
from zero_trust_mcp.policy.engine import PolicyEngine

T = TypeVar("T")


class Enforcer:
    """
    Enforces policy on tool calls.

    Evaluates policy decisions, raises exceptions on denials,
    calls tool functions on approvals, and logs all decisions.
    """

    def __init__(self, policy_engine: PolicyEngine, audit_logger: AuditLogger) -> None:
        """
        Initialize Enforcer.

        Args:
            policy_engine: PolicyEngine instance for evaluation
            audit_logger: AuditLogger instance for logging decisions
        """
        self.engine = policy_engine
        self.logger = audit_logger

    def enforce(self, tool_call: ToolCall, tool_fn: Callable[..., T]) -> T:
        """
        Enforce policy on a tool call and execute if allowed.

        Args:
            tool_call: ToolCall to enforce
            tool_fn: Callable tool function to execute if allowed

        Returns:
            Result from tool_fn(**tool_call.arguments)

        Raises:
            PolicyDeniedError: If policy denies the call
        """
        # Evaluate policy
        decision = self.engine.evaluate(tool_call)

        if not decision.allowed:
            # Log denial
            self.logger.log(
                action="tool_call",
                tool_name=tool_call.tool_name,
                decision="deny",
                reason=decision.reason,
                policy_id=decision.policy_id,
                actor=tool_call.actor,
                request_id=tool_call.request_id,
                arguments=tool_call.arguments,
                layer="enforce",
            )
            # Raise exception
            raise PolicyDeniedError(decision)

        # Log approval
        self.logger.log(
            action="tool_call",
            tool_name=tool_call.tool_name,
            decision="allow",
            reason=decision.reason,
            policy_id=decision.policy_id,
            actor=tool_call.actor,
            request_id=tool_call.request_id,
            arguments=tool_call.arguments,
            layer="enforce",
        )

        # Call tool function
        return tool_fn(**tool_call.arguments)
