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
