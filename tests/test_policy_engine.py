"""
Unit tests for PolicyEngine and policy evaluation.
"""

import tempfile
from pathlib import Path

import pytest

from zero_trust_mcp import PolicyEngine, ToolCall
from zero_trust_mcp.decisions import Decision


class TestPolicyEngineFromYAML:
    """Test PolicyEngine loading and evaluation from YAML."""

    @pytest.fixture
    def policy_file(self):
        """Create a temporary policy file."""
        policy_content = """
policy_id: test_policy
version: "1.0"
default: deny

allow_rules:
  - tool: search
    constraints:
      query:
        type: string
    description: "Allow search with any query"

  - tool: get_user
    constraints:
      user_id:
        type: string
        pattern: "^EMP[0-9]{6}$"
    description: "Allow get_user with valid employee ID"

  - tool: create_ticket
    constraints:
      priority:
        type: string
        enum: ["LOW", "MEDIUM", "HIGH"]
      customer_id:
        type: string
    description: "Allow create_ticket with valid priority"

deny_rules:
  - tool: delete_user
    reason: "User deletion not permitted"

  - tool: export_data
    condition:
      format: csv
    reason: "CSV exports not allowed"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(policy_content)
            f.flush()
            yield f.name

        # Cleanup
        Path(f.name).unlink()

    def test_load_policy_from_yaml(self, policy_file):
        """Test loading policy from YAML file."""
        engine = PolicyEngine.from_file(policy_file)
        assert engine.policy.policy_id == "test_policy"
        assert engine.policy.default == "deny"
        assert len(engine.policy.allow_rules) == 3
        assert len(engine.policy.deny_rules) == 2

    def test_evaluate_allowed_tool(self, policy_file):
        """Test evaluation of allowed tool."""
        engine = PolicyEngine.from_file(policy_file)
        call = ToolCall(tool_name="search", arguments={"query": "test"})
        decision = engine.evaluate(call)
        assert decision.allowed is True
        assert decision.reason == "Matched allow rule"

    def test_evaluate_denied_tool(self, policy_file):
        """Test evaluation of explicitly denied tool."""
        engine = PolicyEngine.from_file(policy_file)
        call = ToolCall(tool_name="delete_user", arguments={"user_id": "EMP123456"})
        decision = engine.evaluate(call)
        assert decision.allowed is False
        assert "User deletion not permitted" in decision.reason

    def test_evaluate_unknown_tool_default_deny(self, policy_file):
        """Test evaluation of unknown tool (defaults to deny)."""
        engine = PolicyEngine.from_file(policy_file)
        call = ToolCall(tool_name="unknown_tool", arguments={})
        decision = engine.evaluate(call)
        assert decision.allowed is False
        assert "Default policy: deny" in decision.reason


class TestConstraintValidation:
    """Test constraint validation."""

    @pytest.fixture
    def engine_with_constraints(self):
        """Create engine with constraint rules."""
        policy_dict = {
            "policy_id": "constraint_test",
            "default": "deny",
            "allow_rules": [
                {
                    "tool": "get_user",
                    "constraints": {
                        "user_id": {
                            "type": "string",
                            "pattern": "^EMP[0-9]{6}$",
                        }
                    },
                },
                {
                    "tool": "set_priority",
                    "constraints": {
                        "level": {
                            "type": "integer",
                            "min": 1,
                            "max": 10,
                        }
                    },
                },
                {
                    "tool": "create_item",
                    "constraints": {
                        "status": {
                            "type": "string",
                            "enum": ["draft", "active", "archived"],
                        }
                    },
                },
            ],
        }
        return PolicyEngine.from_dict(policy_dict)

    def test_constraint_pattern_match(self, engine_with_constraints):
        """Test regex pattern matching constraint."""
        # Valid employee ID
        call = ToolCall(tool_name="get_user", arguments={"user_id": "EMP123456"})
        decision = engine_with_constraints.evaluate(call)
        assert decision.allowed is True

        # Invalid employee ID
        call = ToolCall(tool_name="get_user", arguments={"user_id": "INVALID"})
        decision = engine_with_constraints.evaluate(call)
        assert decision.allowed is False

    def test_constraint_integer_range(self, engine_with_constraints):
        """Test integer min/max constraint."""
        # Valid range
        call = ToolCall(tool_name="set_priority", arguments={"level": 5})
        decision = engine_with_constraints.evaluate(call)
        assert decision.allowed is True

        # Below min
        call = ToolCall(tool_name="set_priority", arguments={"level": 0})
        decision = engine_with_constraints.evaluate(call)
        assert decision.allowed is False

        # Above max
        call = ToolCall(tool_name="set_priority", arguments={"level": 11})
        decision = engine_with_constraints.evaluate(call)
        assert decision.allowed is False

    def test_constraint_enum(self, engine_with_constraints):
        """Test enum constraint."""
        # Valid enum value
        call = ToolCall(tool_name="create_item", arguments={"status": "draft"})
        decision = engine_with_constraints.evaluate(call)
        assert decision.allowed is True

        # Invalid enum value
        call = ToolCall(tool_name="create_item", arguments={"status": "invalid"})
        decision = engine_with_constraints.evaluate(call)
        assert decision.allowed is False


class TestDenyRules:
    """Test deny rule evaluation."""

    @pytest.fixture
    def engine_with_deny_rules(self):
        """Create engine with deny rules."""
        policy_dict = {
            "policy_id": "deny_test",
            "default": "allow",
            "allow_rules": [
                {"tool": "create_ticket"},
                {"tool": "export_data"},
            ],
            "deny_rules": [
                {
                    "tool": "create_ticket",
                    "condition": {"priority": "CRITICAL"},
                    "reason": "CRITICAL requires approval",
                },
                {
                    "tool": "export_data",
                    "condition": {"format": "csv"},
                    "reason": "CSV exports not allowed",
                },
            ],
        }
        return PolicyEngine.from_dict(policy_dict)

    def test_deny_rule_no_condition(self, engine_with_deny_rules):
        """Test deny rule without condition."""
        policy_dict = {
            "policy_id": "deny_test",
            "default": "allow",
            "allow_rules": [{"tool": "search"}],
            "deny_rules": [{"tool": "delete_all", "reason": "Not allowed"}],
        }
        engine = PolicyEngine.from_dict(policy_dict)
        call = ToolCall(tool_name="delete_all", arguments={})
        decision = engine.evaluate(call)
        assert decision.allowed is False
        assert "Not allowed" in decision.reason

    def test_deny_rule_with_condition_match(self, engine_with_deny_rules):
        """Test deny rule with condition that matches."""
        call = ToolCall(
            tool_name="create_ticket",
            arguments={"priority": "CRITICAL"},
        )
        decision = engine_with_deny_rules.evaluate(call)
        assert decision.allowed is False
        assert "CRITICAL requires approval" in decision.reason

    def test_deny_rule_with_condition_no_match(self, engine_with_deny_rules):
        """Test deny rule with condition that doesn't match."""
        call = ToolCall(
            tool_name="create_ticket",
            arguments={"priority": "HIGH"},
        )
        decision = engine_with_deny_rules.evaluate(call)
        assert decision.allowed is True

    def test_deny_rules_override_allow(self, engine_with_deny_rules):
        """Test that deny rules override allow rules."""
        # export_data is in allow_rules but also has a deny rule
        call = ToolCall(
            tool_name="export_data",
            arguments={"format": "csv"},
        )
        decision = engine_with_deny_rules.evaluate(call)
        assert decision.allowed is False
        assert "CSV exports not allowed" in decision.reason


class TestDecisionObject:
    """Test Decision object."""

    def test_decision_allowed(self):
        """Test allowed decision."""
        decision = Decision(
            allowed=True,
            reason="Test passed",
            policy_id="test_policy",
        )
        assert decision.allowed is True
        assert decision.remediation is None
        assert "ALLOWED" in str(decision)

    def test_decision_denied_with_remediation(self):
        """Test denied decision with remediation."""
        decision = Decision(
            allowed=False,
            reason="Invalid user ID",
            policy_id="test_policy",
            remediation="Use format EMP######",
        )
        assert decision.allowed is False
        assert decision.remediation == "Use format EMP######"
        assert "DENIED" in str(decision)
        assert "Remediation" in str(decision)


class TestToolCallModel:
    """Test ToolCall pydantic model."""

    def test_tool_call_basic(self):
        """Test basic ToolCall creation."""
        call = ToolCall(tool_name="search", arguments={"query": "test"})
        assert call.tool_name == "search"
        assert call.arguments == {"query": "test"}
        assert call.actor is None
        assert call.request_id is None

    def test_tool_call_with_metadata(self):
        """Test ToolCall with actor and request_id."""
        call = ToolCall(
            tool_name="get_user",
            arguments={"user_id": "123"},
            actor="user@example.com",
            request_id="req-123",
        )
        assert call.actor == "user@example.com"
        assert call.request_id == "req-123"

    def test_tool_call_empty_arguments(self):
        """Test ToolCall with no arguments."""
        call = ToolCall(tool_name="list_all")
        assert call.arguments == {}
