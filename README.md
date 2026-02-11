# Zero Trust MCP

**Zero Trust policy enforcement for MCP tool calls**

A lightweight Python library for enforcing zero-trust security policies on tool calls in Agent and MCP (Model Context Protocol) workflows.

## Overview

Zero Trust MCP provides:

- **Policy Engine**: Load security policies from YAML/JSON and evaluate tool call requests
- **Structured Decisions**: Clear allow/deny decisions with reasons and remediation guidance
- **Audit Logging**: Safe-by-default structured logging that redacts secrets and sensitive data
- **Type-Safe Models**: Pydantic-based validation of tool calls and policies
- **Enforcement Wrapper**: Simple decorator/wrapper to enforce policies around tool functions
- **Pipeline Architecture**: Composable layers for authorization, validation, rate limiting, attack detection, redaction, and auditing
- **Rate Limiting**: Token-bucket based rate limiting with configurable scopes (actor, tool, session, etc.)
- **Redaction**: Automatic redaction of sensitive fields (passwords, tokens, API keys, PII like emails/phones)
- **Attack Detection**: Detects potential injection/abuse patterns (SQL injection, path traversal, SSRF)
- **Validation Layer**: Enforces payload size constraints and argument validation

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

### Using with Virtual Environments

If you have a Python virtual environment, you can set up shell aliases for persistent access:

```bash
# Add to ~/.zshrc or ~/.bashrc
alias python=/path/to/venv/bin/python3
alias pip=/path/to/venv/bin/pip
```

Then reload your shell and use `python` normally from any directory.

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
from pathlib import Path
from zero_trust_mcp import PolicyEngine, Enforcer, ToolCall
from zero_trust_mcp.audit import get_audit_logger

# Load policy from file (use Path for compatibility across directories)
policy_path = Path(__file__).parent / "policy.yaml"
engine = PolicyEngine.from_file(policy_path)
logger = get_audit_logger()

# Create enforcer
enforcer = Enforcer(engine, logger)

# Define tool functions
def search(query: str) -> dict:
    return {"status": "ok", "results": [f"Result for {query}"]}

def get_user(user_id: str) -> dict:
    return {"status": "ok", "id": user_id, "name": "John Doe"}

# Enforce calls
try:
    # This is allowed
    call = ToolCall(
        tool_name="search", 
        arguments={"query": "urgent items"},
        actor="user@example.com",
        request_id="req-001"
    )
    result = enforcer.enforce(call, search)
    print(f"✓ ALLOWED: {result}")
    
    # This is allowed (valid employee ID)
    call = ToolCall(
        tool_name="get_user", 
        arguments={"user_id": "EMP123456"},
        actor="user@example.com",
        request_id="req-002"
    )
    result = enforcer.enforce(call, get_user)
    print(f"✓ ALLOWED: {result}")
    
    # This is DENIED (invalid employee ID - doesn't match pattern)
    call = ToolCall(
        tool_name="get_user", 
        arguments={"user_id": "INVALID"},
        actor="user@example.com",
        request_id="req-003"
    )
    result = enforcer.enforce(call, get_user)
    
except Exception as e:
    print(f"✗ DENIED: {e}")
    # Exception includes decision reason and policy violation details
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
├── enforcement/
│   └── wrapper.py         # Enforcer class & execute wrapper
├── pipeline/
│   ├── pipeline.py        # Pipeline orchestration
│   └── context.py         # CallContext for layer communication
├── layers/
│   ├── authorize.py       # Authorization layer (policy enforcement)
│   ├── validate.py        # Validation layer (argument size, etc.)
│   ├── rate_limit.py      # Rate limiting layer (token bucket)
│   ├── detect_attacks.py  # Attack detection layer (SQLi, path traversal, SSRF)
│   ├── redact.py          # Redaction layer (PII, secrets)
│   └── audit.py           # Audit logging layer
├── rate_limit.py          # InMemoryRateLimiter implementation
└── redaction.py           # Redaction utilities & patterns
```

## Pipeline & Layers

Zero Trust MCP uses a **composable pipeline architecture** where each security concern is handled by a dedicated layer:

### Layer Types

1. **Authorization Layer** (`authorize_layer`)
   - Evaluates tool call against policy rules
   - Makes allow/deny decision based on constraints
   - Raises `PolicyDeniedError` if denied

2. **Validation Layer** (`validate_layer`)
   - Enforces payload size constraints
   - Validates argument structure and types
   - Prevents oversized or malformed requests

3. **Rate Limiting Layer** (`rate_limit_layer`)
   - Token-bucket based rate limiting
   - Configurable scopes: `actor`, `tool`, `session`, `actor+tool`, `global`
   - Includes burst support and per-minute limits

4. **Attack Detection Layer** (`detect_attacks_layer`)
   - Detects SQL injection patterns
   - Detects path traversal attempts
   - Detects SSRF attacks
   - Can log or deny on detection

5. **Redaction Layer** (`redact_layer`)
   - Redacts sensitive field names (password, token, secret, api_key, authorization)
   - Redacts PII patterns (emails, phone numbers)
   - Enforces string length limits
   - Safe-by-default, never logs secrets

6. **Audit Layer** (`audit_layer`)
   - Logs all decisions and tool calls
   - Structured JSON output with metadata
   - Tracks latency, results, and arguments
   - Works with safe redaction

### Using Pipeline

```python
from zero_trust_mcp import PolicyEngine
from zero_trust_mcp.audit import get_audit_logger
from zero_trust_mcp.layers import authorize_layer, audit_layer, rate_limit_layer, redact_layer
from zero_trust_mcp.pipeline import Pipeline
from zero_trust_mcp.policy.schema import RateLimitConfig, RedactConfig

# Load policy
engine = PolicyEngine.from_file("policy.yaml")
logger = get_audit_logger()

# Create pipeline with layers in order
pipeline = Pipeline(
    engine=engine,
    layers=[
        authorize_layer(engine),
        rate_limit_layer(
            "customer_support_policy",
            RateLimitConfig(
                enabled=True,
                scope="actor",
                limit_per_minute=100,
                burst=10
            )
        ),
        redact_layer(RedactConfig(enabled=True, pii_emails=True)),
        audit_layer(logger, None),
    ]
)

# Execute with pipeline
result = pipeline.execute(tool_call, tool_function)
```

## API Reference

### PolicyEngine

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

### ToolCall

```python
from zero_trust_mcp import ToolCall

call = ToolCall(
    tool_name="get_user",
    arguments={"user_id": "EMP123456"},
    actor="user@example.com",      # optional
    request_id="req-12345"          # optional
)
```

### Enforcer

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

### Rate Limiting

```python
from zero_trust_mcp.rate_limit import InMemoryRateLimiter

limiter = InMemoryRateLimiter()

# Allow max 100 requests per minute with burst of 10
ok, meta = limiter.allow(
    key="actor:user@example.com",
    limit_per_minute=100,
    burst=10
)

# Returns:
# ok: bool (True if allowed)
# meta: {"limit": 100, "burst": 10, "remaining": N}
```

### Redaction

```python
from zero_trust_mcp.redaction import redact_value

data = {
    "name": "John",
    "password": "secret123",
    "email": "john@example.com"
}

redacted = redact_value(
    data,
    deny_keys=["password", "token", "secret", "api_key"],
    pii_emails=True,
    pii_phones=True,
    max_string_len=2048
)

# Returns:
# {
#     "name": "John",
#     "password": "[REDACTED]",
#     "email": "[REDACTED_EMAIL]"
# }
```

## Examples

See `examples/` for working demos:
- `basic_policy_demo.py`: Comprehensive end-to-end example with 7 test cases (search, get_user, create_ticket, delete_user, and edge cases)
- `policy_demo.py`: Simple minimal example showing a hello function with policy enforcement
- `policy.yaml`: Example policy file demonstrating allow/deny rules with constraints

### Running Examples

All examples can be run from any directory using:

```bash
# From project root
python examples/basic_policy_demo.py
python examples/policy_demo.py

# From examples directory  
cd examples
python basic_policy_demo.py
python policy_demo.py
```

Both examples use relative paths (`Path(__file__).parent / "policy.yaml"`) to locate the policy file, so they work from any directory.

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

## Security Considerations

zero-trust-mcp enforces policy-based validation and authorization at the tool invocation boundary. It does not replace downstream system hardening, authentication, or network controls. Users should ensure that external tools implement appropriate security practices independently of this library.

## Contributing

Contributions welcome! Please:
1. Add tests for new features
2. Run `ruff` formatter
3. Ensure tests pass
4. Update CHANGELOG.md

## Citation

If you use this work, please cite:

Rajesh Kumar Sampath Kumar (2026).  
Zero-Trust MCP (v0.1.4).
[![DOI](https://zenodo.org/badge/1119736858.svg)](https://doi.org/10.5281/zenodo.18614628)
Zenodo. https://doi.org/10.5281/zenodo.18614628

## License

MIT License. See LICENSE file.

## Security Policy

See SECURITY.md for security considerations and reporting guidelines.

---

**Ready to get started?** See the quickstart above or check out `examples/basic_policy_demo.py`.
