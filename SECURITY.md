# Security Policy

## Reporting Security Vulnerabilities

**Please do not open public GitHub issues for security vulnerabilities.**

If you discover a security vulnerability in Zero Trust MCP, please contact me.

Include:
- Description of the vulnerability
- Steps to reproduce (if applicable)
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 48 hours and keep you updated on progress toward a fix.

## Security Considerations

### What Zero Trust MCP Does

- Enforces access control policies on tool calls
- Validates arguments against defined constraints
- Provides audit logging for compliance
- Defaults to deny (secure by default)

### What Zero Trust MCP Does NOT Do

- Sanitize arguments (validation only, no transformation)
- Provide encryption or authentication
- Handle secret management (assumes secrets are managed upstream)
- Protect against all injection attacks (defense in depth recommended)

### Best Practices

1. **Pair with defense in depth**: Use Zero Trust MCP alongside:
   - Input validation in your tool implementations
   - Rate limiting and DDoS protection
   - Network segmentation
   - Principle of least privilege for service accounts

2. **Policy management**:
   - Keep policies in version control
   - Review policy changes in code review
   - Use semantic versioning for policy updates
   - Test policies in staging before production

3. **Audit logs**:
   - Regularly review audit logs for suspicious patterns
   - Integrate with SIEM/log aggregation systems
   - Set alerts for repeated denials
   - Retain logs per your compliance requirements

4. **Dependency security**:
   - Keep `pydantic`, `pyyaml` updated
   - Use `pip-audit` or similar tools
   - Pin versions in production

### Limitations

- **Not a sandbox**: Does not prevent code-level attacks if the tool function itself is compromised
- **Policy bypass**: Policies are only as good as their definition; vague rules can be exploited
- **Argument mutation**: Does not track if tool implementations mutate arguments
- **Async support**: Designed for synchronous enforcement; async patterns require external coordination

### Threat Model

Zero Trust MCP mitigates these threats:

| Threat | Mitigation |
|--------|-----------|
| Privilege escalation via arguments | Argument constraint validation |
| Data exfiltration via tool selection | Deny-by-default tool allowlisting |
| Injection attacks | Regex/pattern matching on string args |
| Runaway agent loops | Rate limiting + audit (external) |
| Unauthorized callers | Optional actor field + audit trail |

---

For questions or to report non-security issues, use GitHub Issues.
