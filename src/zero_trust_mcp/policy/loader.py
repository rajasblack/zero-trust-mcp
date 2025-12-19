"""
Policy loader for YAML and JSON files.
"""

import json
from pathlib import Path
from typing import Any

import yaml

from zero_trust_mcp.policy.schema import PolicySchema


class PolicyLoader:
    """
    Load policies from YAML or JSON files.
    """

    @staticmethod
    def load_file(path: str | Path) -> dict[str, Any]:
        """
        Load policy from a file (YAML or JSON).

        Args:
            path: Path to policy file (.yaml, .yml, or .json)

        Returns:
            Parsed policy dictionary

        Raises:
            FileNotFoundError: If file does not exist
            ValueError: If file format is not supported
            yaml.YAMLError: If YAML parsing fails
            json.JSONDecodeError: If JSON parsing fails
        """
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        if path.suffix in (".yaml", ".yml"):
            with open(path) as f:
                return yaml.safe_load(f) or {}

        elif path.suffix == ".json":
            with open(path) as f:
                return json.load(f)

        else:
            raise ValueError(f"Unsupported file format: {path.suffix}")

    @staticmethod
    def validate(policy_dict: dict[str, Any]) -> PolicySchema:
        """
        Validate a policy dictionary against the schema.

        Args:
            policy_dict: Raw policy dictionary

        Returns:
            Validated PolicySchema object

        Raises:
            ValueError: If validation fails
        """
        try:
            return PolicySchema(**policy_dict)
        except Exception as e:
            raise ValueError(f"Policy validation failed: {e}") from e
