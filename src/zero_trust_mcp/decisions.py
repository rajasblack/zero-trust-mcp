"""
Decisions and exceptions for policy evaluation.
"""

from dataclasses import dataclass


@dataclass
class Decision:
    """
    Represents a policy evaluation decision.

    Attributes:
        allowed: Whether the tool call is allowed
        reason: Human-readable reason for the decision
        policy_id: Identifier of the policy that made this decision
        remediation: Optional guidance on how to remediate (for denied calls)
        layer: Optional layer that made the decision
    """

    allowed: bool
    reason: str
    policy_id: str
    remediation: str | None = None
    layer: str | None = None

    def __str__(self) -> str:
        """Return string representation."""
        decision_str = "ALLOWED" if self.allowed else "DENIED"
        result = f"{decision_str}: {self.reason} (policy={self.policy_id})"
        if self.remediation:
            result += f"\nRemediation: {self.remediation}"
        return result


class PolicyDeniedError(Exception):
    """
    Exception raised when a policy denies a tool call.

    Attributes:
        decision: The Decision object that led to this exception
        message: Error message
    """

    def __init__(self, decision: Decision) -> None:
        """
        Initialize PolicyDeniedError.

        Args:
            decision: The Decision object with denial details
        """
        self.decision = decision
        message = f"Policy denied: {decision.reason} (policy={decision.policy_id})"
        super().__init__(message)

    def __str__(self) -> str:
        """Return the decision string."""
        return str(self.decision)
