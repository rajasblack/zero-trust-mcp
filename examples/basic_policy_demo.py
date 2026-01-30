"""
Basic policy demo showing Zero Trust MCP in action.

This example demonstrates:
1. Loading a policy from YAML
2. Creating tool functions
3. Enforcing policy on tool calls
4. Handling policy denials
"""

from pathlib import Path

from zero_trust_mcp import Enforcer, PolicyEngine, ToolCall
from zero_trust_mcp.audit import get_audit_logger


def search(query: str) -> dict:
    """Search function."""
    return {"status": "ok", "results": [f"Result for '{query}'"]}


def get_user(user_id: str) -> dict:
    """Get user by ID."""
    return {
        "status": "ok",
        "id": user_id,
        "name": "John Doe",
        "email": "john@example.com",
    }


def create_ticket(priority: str, customer_id: str) -> dict:
    """Create a support ticket."""
    return {
        "status": "created",
        "ticket_id": "TICK-001",
        "priority": priority,
        "customer_id": customer_id,
    }


def delete_user(user_id: str) -> dict:
    """Delete a user (not allowed by policy)."""
    return {"status": "deleted", "user_id": user_id}


def main() -> None:
    """Run the demo."""
    # Load policy from the same directory as this script
    policy_path = Path(__file__).parent / "policy.yaml"
    engine = PolicyEngine.from_file(policy_path)
    logger = get_audit_logger()

    # Create enforcer
    enforcer = Enforcer(engine, logger)

    print("=" * 70)
    print("Zero Trust MCP - Basic Policy Demo")
    print("=" * 70)
    print()

    # Test 1: Allowed search
    print("Test 1: Search (allowed)")
    print("-" * 70)
    try:
        call = ToolCall(
            tool_name="search",
            arguments={"query": "urgent items"},
            actor="agent@example.com",
            request_id="req-001",
        )
        result = enforcer.enforce(call, search)
        print(f"✓ ALLOWED: {result}")
    except Exception as e:
        print(f"✗ DENIED: {e}")
    print()

    # Test 2: Allowed get_user with valid employee ID
    print("Test 2: Get user with valid employee ID (allowed)")
    print("-" * 70)
    try:
        call = ToolCall(
            tool_name="get_user",
            arguments={"user_id": "EMP123456"},
            actor="agent@example.com",
            request_id="req-002",
        )
        result = enforcer.enforce(call, get_user)
        print(f"✓ ALLOWED: {result}")
    except Exception as e:
        print(f"✗ DENIED: {e}")
    print()

    # Test 3: Denied get_user with invalid employee ID
    print("Test 3: Get user with invalid employee ID (denied)")
    print("-" * 70)
    try:
        call = ToolCall(
            tool_name="get_user",
            arguments={"user_id": "INVALID"},
            actor="agent@example.com",
            request_id="req-003",
        )
        result = enforcer.enforce(call, get_user)
        print(f"✓ ALLOWED: {result}")
    except Exception as e:
        print(f"✗ DENIED: {e}")
    print()

    # Test 4: Allowed create_ticket with valid priority
    print("Test 4: Create ticket with valid priority (allowed)")
    print("-" * 70)
    try:
        call = ToolCall(
            tool_name="create_ticket",
            arguments={"priority": "HIGH", "customer_id": "CUST-789"},
            actor="agent@example.com",
            request_id="req-004",
        )
        result = enforcer.enforce(call, create_ticket)
        print(f"✓ ALLOWED: {result}")
    except Exception as e:
        print(f"✗ DENIED: {e}")
    print()

    # Test 5: Denied create_ticket with CRITICAL priority
    print("Test 5: Create CRITICAL ticket (denied by rule)")
    print("-" * 70)
    try:
        call = ToolCall(
            tool_name="create_ticket",
            arguments={"priority": "CRITICAL", "customer_id": "CUST-789"},
            actor="agent@example.com",
            request_id="req-005",
        )
        result = enforcer.enforce(call, create_ticket)
        print(f"✓ ALLOWED: {result}")
    except Exception as e:
        print(f"✗ DENIED: {e}")
    print()

    # Test 6: Denied delete_user
    print("Test 6: Delete user (denied by policy)")
    print("-" * 70)
    try:
        call = ToolCall(
            tool_name="delete_user",
            arguments={"user_id": "EMP123456"},
            actor="agent@example.com",
            request_id="req-006",
        )
        result = enforcer.enforce(call, delete_user)
        print(f"✓ ALLOWED: {result}")
    except Exception as e:
        print(f"✗ DENIED: {e}")
    print()

    # Test 7: Denied unknown tool (default deny)
    print("Test 7: Unknown tool (denied by default)")
    print("-" * 70)
    try:
        call = ToolCall(
            tool_name="dangerous_export",
            arguments={"format": "csv", "filter": "all"},
            actor="agent@example.com",
            request_id="req-007",
        )
        result = enforcer.enforce(call, lambda **kwargs: {"status": "exported"})
        print(f"✓ ALLOWED: {result}")
    except Exception as e:
        print(f"✗ DENIED: {e}")
    print()

    print("=" * 70)
    print("Demo complete!")
    print("Check the audit log above for structured decisions (JSON format)")
    print("=" * 70)


if __name__ == "__main__":
    main()
