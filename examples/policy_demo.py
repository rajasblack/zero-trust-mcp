from pathlib import Path

from zero_trust_mcp import Enforcer, PolicyEngine, ToolCall
from zero_trust_mcp.audit.logger import get_audit_logger

policy_path = Path(__file__).parent / "policy.yaml"
engine = PolicyEngine.from_file(policy_path)
enforcer = Enforcer(engine, get_audit_logger())

def hello(name: str):
    return {"msg": f"hi {name}"}

print(enforcer.enforce(ToolCall(tool_name="hello", arguments={"name": "Ada"}, actor="support"), hello))
