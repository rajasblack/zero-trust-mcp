"""
Audit logging with safe-by-default secret redaction.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any


class AuditLogger:
    """
    Structured audit logger that redacts sensitive fields.

    Logs policy decisions in JSON format with automatic redaction of:
    - token, password, secret, api_key, authorization
    """

    # Sensitive field names that should be redacted
    SENSITIVE_FIELDS = {"token", "password", "secret", "api_key", "authorization"}

    def __init__(self) -> None:
        """Initialize AuditLogger."""
        self.logger = logging.getLogger("zero_trust_mcp.audit")

    def log(
        self,
        action: str,
        tool_name: str,
        decision: str,
        reason: str,
        policy_id: str,
        actor: str | None = None,
        request_id: str | None = None,
        arguments: dict[str, Any] | None = None,
        layer: str | None = None,
        latency_ms: float | None = None,
        client: dict[str, Any] | None = None,
        result: Any = None,
        include_result: bool = False,
        include_argument_values: bool = False,
    ) -> None:
        """
        Log a policy decision.

        Args:
            action: Action type (e.g., "tool_call")
            tool_name: Name of the tool being called
            decision: "allow" or "deny"
            reason: Reason for the decision
            policy_id: Policy ID that made the decision
            actor: Optional actor (e.g., user email)
            request_id: Optional request ID
            arguments: Optional arguments dict
            layer: Optional layer that made the decision
            latency_ms: Optional latency in milliseconds
            client: Optional client info dict
            result: Optional tool result
            include_result: Whether to include result in log
            include_argument_values: Whether to include argument values
        """
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "tool_name": tool_name,
            "decision": decision,
            "reason": reason,
            "policy_id": policy_id,
        }

        if actor:
            log_entry["actor"] = actor

        if request_id:
            log_entry["request_id"] = request_id

        if layer:
            log_entry["layer"] = layer

        if latency_ms is not None:
            log_entry["latency_ms"] = latency_ms

        if client:
            log_entry["client"] = client

        if include_argument_values and arguments:
            log_entry["arguments"] = self.redact_dict(arguments)
        elif arguments:
            log_entry["arguments_summary"] = {
                "keys": list(arguments.keys()),
                "key_count": len(arguments),
            }

        if include_result and result is not None:
            if isinstance(result, dict):
                log_entry["result"] = self.redact_dict(result)
            else:
                log_entry["result"] = str(result)

        # Log as JSON
        self.logger.info(json.dumps(log_entry))

    def redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Return a redacted copy of a dictionary.

        Redacts known sensitive fields recursively.

        Args:
            data: Dictionary to redact

        Returns:
            New dictionary with sensitive fields redacted
        """
        redacted = {}
        for key, value in data.items():
            if key.lower() in self.SENSITIVE_FIELDS:
                redacted[key] = "[REDACTED]"
            elif isinstance(value, dict):
                redacted[key] = self.redact_dict(value)
            elif isinstance(value, list):
                redacted[key] = [self.redact_dict(v) if isinstance(v, dict) else v for v in value]
            else:
                redacted[key] = value
        return redacted


_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """
    Get the global AuditLogger instance.

    Uses singleton pattern to ensure a single logger instance.

    Returns:
        AuditLogger instance
    """
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
        # Configure basic logging if not already configured
        if not logging.getLogger("zero_trust_mcp.audit").handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(message)s"))
            logging.getLogger("zero_trust_mcp.audit").addHandler(handler)
            logging.getLogger("zero_trust_mcp.audit").setLevel(logging.INFO)
    return _audit_logger
