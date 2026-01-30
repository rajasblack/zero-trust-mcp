"""
Policy schema and validation.
"""

from typing import Any

from pydantic import BaseModel, Field


class ConstraintModel(BaseModel):
    """
    Constraint on a tool argument.

    Supports: type, pattern (regex for strings), enum, min/max (for numbers), required (boolean).
    """

    type: str | None = Field(None, description="Type: string, integer, boolean")
    pattern: str | None = Field(None, description="Regex pattern for string matching")
    enum: list[Any] | None = Field(None, description="Allowed values")
    min: int | None = Field(None, description="Minimum value (for integers)")
    max: int | None = Field(None, description="Maximum value (for integers)")
    required: bool | None = Field(None, description="Whether this argument is required")
    description: str | None = Field(None, description="Human-readable description")

    model_config = {"extra": "allow"}


class RuleConstraints(BaseModel):
    """Constraints for a rule, keyed by argument name."""

    model_config = {"extra": "allow"}


class AllowRule(BaseModel):
    """
    An allow rule for a tool.

    Args:
        tool: Tool name that is allowed
        constraints: Optional constraints on arguments
        description: Optional description
    """

    tool: str = Field(..., description="Tool name to allow")
    constraints: dict[str, ConstraintModel] | None = Field(None, description="Argument constraints")
    description: str | None = Field(None, description="Rule description")

    model_config = {"extra": "allow"}


class DenyRule(BaseModel):
    """
    A deny rule for a tool.

    Args:
        tool: Tool name to deny
        condition: Optional condition (argument values to match)
        reason: Reason for denial
        description: Optional description
    """

    tool: str = Field(..., description="Tool name to deny")
    condition: dict[str, Any] | None = Field(
        None, description="Condition: argument values that trigger denial"
    )
    reason: str = Field(..., description="Why this tool/condition is denied")
    description: str | None = Field(None, description="Rule description")

    model_config = {"extra": "allow"}


class PolicySchema(BaseModel):
    """
    Complete policy schema.

    Args:
        policy_id: Unique identifier for this policy
        version: Policy version (e.g., "1.0")
        default: Default decision: "allow" or "deny"
        allow_rules: List of allow rules
        deny_rules: List of deny rules
    """

    policy_id: str = Field(..., description="Unique policy identifier")
    version: str | None = Field("1.0", description="Policy version")
    default: str = Field("deny", description="Default decision: allow or deny")
    allow_rules: list[AllowRule] | None = Field(default_factory=list, description="Allow rules")
    deny_rules: list[DenyRule] | None = Field(default_factory=list, description="Deny rules")

    model_config = {"extra": "allow"}


class ValidateConfig(BaseModel):
    """Validation configuration."""

    max_arg_bytes: int | None = Field(None, description="Maximum size of arguments in bytes")

    model_config = {"extra": "allow"}


class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""

    enabled: bool = Field(default=True, description="Whether rate limiting is enabled")
    scope: str = Field(
        default="actor", description="Scope: global, actor, session, tool, or actor+tool"
    )
    limit_per_minute: int = Field(default=60, description="Limit per minute")
    burst: int | None = Field(None, description="Burst limit")

    model_config = {"extra": "allow"}


class RedactConfig(BaseModel):
    """Redaction configuration."""

    enabled: bool = Field(default=True, description="Whether redaction is enabled")
    deny_keys: list[str] | None = Field(None, description="Keys to deny in results")
    pii_emails: bool = Field(default=False, description="Redact email addresses")
    pii_phones: bool = Field(default=False, description="Redact phone numbers")
    max_string_len: int | None = Field(None, description="Maximum string length before truncation")

    model_config = {"extra": "allow"}


class DetectAttacksConfig(BaseModel):
    """Attack detection configuration."""

    enabled: bool = Field(default=True, description="Whether attack detection is enabled")
    fields: list[str] | None = Field(None, description="Fields to check for attacks")
    on_detect: str = Field(default="deny", description="Action on detection: deny or warn")

    model_config = {"extra": "allow"}


class AuditConfig(BaseModel):
    """Audit logging configuration."""

    enabled: bool = Field(default=True, description="Whether audit logging is enabled")
    include_result: bool = Field(default=False, description="Include tool result in logs")
    include_argument_values: bool = Field(
        default=False, description="Include argument values in logs"
    )

    model_config = {"extra": "allow"}
