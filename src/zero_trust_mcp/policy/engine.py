"""
Core policy engine for evaluating tool calls.
"""

import re
from pathlib import Path
from typing import Any

from zero_trust_mcp.decisions import Decision
from zero_trust_mcp.models import ToolCall
from zero_trust_mcp.policy.loader import PolicyLoader
from zero_trust_mcp.policy.schema import PolicySchema


class PolicyEngine:
    """
    Evaluates tool calls against zero-trust policies.

    Implements deny-by-default security model with explicit allow rules.
    """

    def __init__(self, policy: PolicySchema) -> None:
        """
        Initialize PolicyEngine with a policy.

        Args:
            policy: PolicySchema object containing rules
        """
        self.policy = policy

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        """
        Create PolicyEngine by loading policy from a file.

        Args:
            path: Path to YAML or JSON policy file

        Returns:
            PolicyEngine instance

        Raises:
            FileNotFoundError: If policy file not found
            ValueError: If policy validation fails
        """
        policy_dict = PolicyLoader.load_file(path)
        policy_schema = PolicyLoader.validate(policy_dict)
        return cls(policy_schema)

    @classmethod
    def from_dict(cls, policy_dict: dict[str, Any]) -> "PolicyEngine":
        """
        Create PolicyEngine from a dictionary.

        Args:
            policy_dict: Policy as dictionary

        Returns:
            PolicyEngine instance

        Raises:
            ValueError: If policy validation fails
        """
        policy_schema = PolicyLoader.validate(policy_dict)
        return cls(policy_schema)

    def evaluate(self, tool_call: ToolCall) -> Decision:
        """
        Evaluate a tool call against the policy.

        Evaluation order:
        1. Validate ToolCall using pydantic
        2. Check deny rules (explicit denies win)
        3. Check allow rules
        4. Apply default decision

        Args:
            tool_call: ToolCall to evaluate

        Returns:
            Decision object with allowed/denied status and reason
        """
        # ToolCall is already validated by pydantic
        tool_name = tool_call.tool_name
        arguments = tool_call.arguments

        # Step 1: Check deny rules (explicit denies win)
        for deny_rule in self.policy.deny_rules or []:
            if deny_rule.tool == tool_name:
                # Check condition if provided
                if deny_rule.condition:
                    if self._matches_condition(arguments, deny_rule.condition):
                        return Decision(
                            allowed=False,
                            reason=deny_rule.reason,
                            policy_id=self.policy.policy_id,
                        )
                else:
                    # No condition, always deny
                    return Decision(
                        allowed=False,
                        reason=deny_rule.reason,
                        policy_id=self.policy.policy_id,
                    )

        # Step 2: Check allow rules
        for allow_rule in self.policy.allow_rules or []:
            if allow_rule.tool == tool_name:
                # Check constraints if provided
                if allow_rule.constraints:
                    if self._validate_constraints(arguments, allow_rule.constraints):
                        return Decision(
                            allowed=True,
                            reason="Matched allow rule",
                            policy_id=self.policy.policy_id,
                        )
                else:
                    # No constraints, allow
                    return Decision(
                        allowed=True,
                        reason="Matched allow rule",
                        policy_id=self.policy.policy_id,
                    )

        # Step 3: Apply default decision
        allowed = self.policy.default == "allow"
        reason = f"Default policy: {self.policy.default}"
        return Decision(
            allowed=allowed,
            reason=reason,
            policy_id=self.policy.policy_id,
        )

    def _validate_constraints(self, arguments: dict[str, Any], constraints: dict[str, Any]) -> bool:
        """
        Validate arguments against constraints.

        All constraints must pass for validation to succeed.

        Args:
            arguments: Tool call arguments
            constraints: Constraint definitions

        Returns:
            True if all constraints pass, False otherwise
        """
        for arg_name, constraint in constraints.items():
            if arg_name not in arguments:
                # Convert to dict if it's a Pydantic model
                constraint_dict = (
                    constraint.model_dump(exclude_none=True)
                    if hasattr(constraint, "model_dump")
                    else constraint
                )
                if constraint_dict.get("required"):
                    return False
                # Not required, skip if missing
                continue

            arg_value = arguments[arg_name]

            # Convert to dict if it's a Pydantic model
            constraint_dict = (
                constraint.model_dump(exclude_none=True)
                if hasattr(constraint, "model_dump")
                else constraint
            )

            # Check type
            if constraint_dict.get("type"):
                if not self._check_type(arg_value, constraint_dict["type"]):
                    return False

            # Check pattern (regex for strings)
            if constraint_dict.get("pattern"):
                if not isinstance(arg_value, str):
                    return False
                if not re.match(constraint_dict["pattern"], arg_value):
                    return False

            # Check enum
            if constraint_dict.get("enum"):
                if arg_value not in constraint_dict["enum"]:
                    return False

            # Check min (for integers)
            if constraint_dict.get("min") is not None:
                if not isinstance(arg_value, (int, float)):
                    return False
                if arg_value < constraint_dict["min"]:
                    return False

            # Check max (for integers)
            if constraint_dict.get("max") is not None:
                if not isinstance(arg_value, (int, float)):
                    return False
                if arg_value > constraint_dict["max"]:
                    return False

        return True

    def _matches_condition(self, arguments: dict[str, Any], condition: dict[str, Any]) -> bool:
        """
        Check if arguments match a condition (used in deny rules).

        All condition fields must match for condition to succeed.

        Args:
            arguments: Tool call arguments
            condition: Condition to match

        Returns:
            True if all condition fields match, False otherwise
        """
        for field_name, expected_value in condition.items():
            if field_name not in arguments:
                return False

            if arguments[field_name] != expected_value:
                return False

        return True

    @staticmethod
    def _check_type(value: Any, type_str: str) -> bool:
        """
        Check if value matches the expected type string.

        Args:
            value: Value to check
            type_str: Type string: "string", "integer", "boolean"

        Returns:
            True if type matches, False otherwise
        """
        type_map = {
            "string": str,
            "integer": int,
            "boolean": bool,
            "number": (int, float),
        }

        expected_type = type_map.get(type_str.lower())
        if expected_type is None:
            return True  # Unknown type, don't fail

        return isinstance(value, expected_type)
