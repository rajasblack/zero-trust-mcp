# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-12-19

### Added

- Initial release of Zero Trust MCP
- **PolicyEngine**: Load policies from YAML/JSON and evaluate tool calls
  - Deny-by-default security model
  - Allow rules with optional argument constraints
  - Deny rules with optional conditions
  - Support for constraint types: string (regex), integer (min/max), boolean, enum
- **Decision**: Structured decision object with allow/deny, reason, policy_id, remediation
- **ToolCall**: Pydantic model for type-safe tool call representation
  - Fields: tool_name, arguments, actor, request_id
- **Audit Logger**: Safe-by-default structured JSON logging
  - Redaction of sensitive fields: token, password, secret, api_key, authorization
  - Argument key summary (not full values)
  - Timestamp and request tracking
- **Enforcer**: Wrapper class for enforcing policies
  - `enforce(tool_call, tool_fn)` method
  - Raises `PolicyDeniedError` on policy violations
  - Logs all decisions (allow/deny)
- **Policy Loader**: Support for YAML and JSON policy formats
- **Examples**: Basic demo showing search, get_user, create_ticket enforcement
- **Tests**: Initial test suite for policy engine evaluation
- **CI/CD**: GitHub Actions workflow for Python 3.10+ testing and linting
- **Documentation**: README, SECURITY.md, CHANGELOG.md

### Future Plans

- Extended constraint types (arrays, nested objects)
- Async/await support for tool enforcement
- Policy hot-reloading
- Integration examples with LangChain, LangGraph, AutoGen
- Web-based policy management UI
- gRPC/REST API for remote policy evaluation

---

[0.1.0]: https://github.com/rajasblack/zero-trust-mcp/releases/tag/v0.1.0
