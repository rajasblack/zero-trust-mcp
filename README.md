# Zero Trust MCP

**Zero Trust policy enforcement for MCP tool calls**

A lightweight Python library for enforcing zero-trust security policies on tool calls in Agent and MCP (Model Context Protocol) workflows.

## Overview

Zero Trust MCP provides:

- **Policy Engine**: Load security policies from YAML/JSON and evaluate tool call requests
- **Structured Decisions**: Clear allow/deny decisions with reasons and remediation guidance
- **Audit Logging**: Safe-by-default structured logging that redacts secrets
- **Type-Safe Models**: Pydantic-based validation of tool calls and policies
- **Enforcement Wrapper**: Simple decorator/wrapper to enforce policies around tool functions

## Why Zero Trust for Tool Calls?

When agents and LLMs can call external tools (APIs, databases, commands), the risk of:
- **Privilege escalation**: A tool call with unintended high-privilege arguments
- **Data exfiltration**: Using search/export tools to leak sensitive information
- **Injection attacks**: Crafted arguments that exploit downstream tools
- **Runaway agents**: Unchecked repeated tool invocations

Zero Trust MCP mitigates these by:
1. Defaulting to **deny** (security by default)
2. Enforcing **explicit allow policies** per tool
3. **Validating arguments** against constraints (regex, type, ranges)
4. **Auditing all decisions** for compliance and forensics

## Quickstart

### Installation

```bash
pip install -e ./zero-trust-mcp
# or from git
pip install git+https://github.com/rajasblack/zero-trust-mcp.git#subdirectory=zero-trust-mcp
```

### Basic Usage

#### 1. Define a Policy

Create `policy.yaml`:

```yaml
policy_id: "customer_support_policy"
version: "1.0"
default: deny

allow_rules:
  - tool: search
    constraints:
      query:
        type: string
        description: "Search query"
  - tool: get_user
    constraints:
      user_id:
        type: string
        pattern: "^EMP[0-9]{6}$"
        description: "Must be employee ID"
  - tool: create_ticket
    constraints:
      priority:
        type: string
        enum: ["LOW", "MEDIUM", "HIGH"]
      customer_id:
        type: string

deny_rules:
  - tool: delete_user
    reason: "User deletion not permitted in this context"
  - tool: create_ticket
    condition:
      priority: "CRITICAL"
    reason: "CRITICAL tickets require manager approval"
```

#### 2. Enforce with Python

```python
from zero_trust_mcp import PolicyEngine, Enforcer, ToolCall
from zero_trust_mcp.audit import get_audit_logger

# Load policy
engine = PolicyEngine.from_file("policy.yaml")
logger = get_audit_logger()

# Create enforcer
enforcer = Enforcer(engine, logger)

# Define tool functions
def search(query: str) -> dict:
    return {"results": [f"Result for {query}"]}

def get_user(user_id: str) -> dict:
    return {"id": user_id, "name": "John Doe"}

# Enforce calls
try:
    # This is allowed
    call = ToolCall(tool_name="search", arguments={"query": "urgent items"})
    result = enforcer.enforce(call, search)
    print(result)  # {"results": ["Result for urgent items"]}
    
    # This is allowed (valid employee ID)
    call = ToolCall(tool_name="get_user", arguments={"user_id": "EMP123456"})
    result = enforcer.enforce(call, get_user)
    print(result)  # {"id": "EMP123456", "name": "John Doe"}
    
    # This is DENIED (invalid employee ID)
    call = ToolCall(tool_name="get_user", arguments={"user_id": "INVALID"})
    result = enforcer.enforce(call, get_user)
    
except Exception as e:
    print(f"Policy violation: {e}")
    # Log includes decision reason and audit trail
```

## Policy Format

### Top-Level Fields

```yaml
policy_id: string           # Unique policy identifier
version: string             # Policy version (e.g., "1.0")
default: "allow" | "deny"   # Default decision if no rules match
allow_rules: [...]          # List of allow rules
deny_rules: [...]           # List of deny rules (override allows)
```

### Rule Structure

```yaml
allow_rules:
  - tool: string            # Tool/function name (required)
    constraints:
      arg_name:
        type: string | integer | boolean
        pattern: string     # Regex for string fields
        enum: [...]         # Allowed values
        min: number         # For integers/numbers
        max: number         # For integers/numbers
        required: boolean   # Must be present in call

deny_rules:
  - tool: string
    condition:              # Optional: match specific argument values
      arg_name: value
    reason: string          # Why this is denied
```

### Constraint Types

| Type | Pattern | Example |
|------|---------|---------|
| `string` | Regex pattern | `"^[A-Z][0-9]{5}$"` |
| `integer` | `min`, `max` | `{"min": 1, "max": 100}` |
| `boolean` | N/A | N/A |
| Enum | `enum: [...]` | `["LOW", "MEDIUM", "HIGH"]` |

## Architecture

```
zero_trust_mcp/
├── models.py              # Pydantic models (ToolCall, etc.)
├── decisions.py           # Decision & PolicyDeniedError
├── policy/
│   ├── engine.py          # PolicyEngine (core eval)
│   ├── loader.py          # YAML/JSON loading
│   └── schema.py          # Policy schema validation
├── audit/
│   └── logger.py          # Safe-by-default audit logging
└── enforcement/
    └── wrapper.py         # Enforcer class & execute wrapper
```

## API Reference

### `PolicyEngine`

```python
from zero_trust_mcp import PolicyEngine

engine = PolicyEngine.from_file("policy.yaml")
# or
engine = PolicyEngine.from_dict(policy_dict)

decision = engine.evaluate(tool_call)
# decision.allowed: bool
# decision.reason: str
# decision.policy_id: str
# decision.remediation: Optional[str]
```

### `ToolCall`

```python
from zero_trust_mcp import ToolCall

call = ToolCall(
    tool_name="get_user",
    arguments={"user_id": "EMP123456"},
    actor="user@example.com",      # optional
    request_id="req-12345"          # optional
)
```

### `Enforcer`

```python
from zero_trust_mcp import Enforcer
from zero_trust_mcp.audit import get_audit_logger

enforcer = Enforcer(engine, get_audit_logger())

result = enforcer.enforce(tool_call, tool_function)
# Raises PolicyDeniedError if denied
# Calls tool_function(**tool_call.arguments) if allowed
# Logs audit event either way
```

### Audit Logger

```python
from zero_trust_mcp.audit import get_audit_logger

logger = get_audit_logger()
logger.log(action="tool_call", tool_name="search", decision="allow", reason="...", actor="...")
# Output: JSON-formatted, redacts token/password/secret/api_key/authorization
```

## Examples

See `examples/` for working demos:
- `basic_policy_demo.py`: End-to-end example with search, get_user, create_ticket
- `policy.yaml`: Example policy file

Run:
```bash
cd examples
python basic_policy_demo.py
```

## Audit Log Format

All decisions are logged as JSON with these fields:

```json
{
  "timestamp": "2025-12-19T10:30:45.123456Z",
  "action": "tool_call",
  "tool_name": "search",
  "decision": "allow",
  "reason": "Matched allow rule",
  "policy_id": "customer_support_policy",
  "actor": "user@example.com",
  "request_id": "req-12345",
  "arguments_summary": {
    "keys": ["query"],
    "key_count": 1
  }
}
```

Sensitive fields (`token`, `password`, `secret`, `api_key`, `authorization`) are never logged.

## Development

Install with dev dependencies:

```bash
pip install -e ".[dev]"
```

Run tests:

```bash
pytest tests/
```

Run linting:

```bash
ruff check src/ tests/ examples/
ruff format src/ tests/ examples/
```

## Contributing

Contributions welcome! Please:
1. Add tests for new features
2. Run `ruff` formatter
3. Ensure tests pass
4. Update CHANGELOG.md

## License

MIT License. See LICENSE file.

## Security Policy

See SECURITY.md for security considerations and reporting guidelines.

---

**Ready to get started?** See the quickstart above or check out `examples/basic_policy_demo.py`.
