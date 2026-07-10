from copy import deepcopy
from pathlib import Path

import yaml 

CONFIG_FILE_NAME = "commitgate.yaml"

DEFAULT_CONFIG = {
    "enabled": True,
    "ai": {
        "enabled": True,
        "provider": "deepseek",
        "timeout": 20,
    },
    "policy": {
        "block_severity": "high",
    },
    "reporting": {
        "min_severity": "medium",
        "fields": {
            "source": True,
            "category": True,
            # "severity": True,
            # "file": True,
            # "location": True,
            "description": True,
            "suggestions": True,
        },
    },
}

DEFAULT_CONFIG_YAML = """\
# Enable or disable CommitGate for this repository.
enabled: true

ai:
  # Enable AI-powered security review.
  enabled: true

  # AI provider to use.
  # Option 1: (AI_KEY in .env): openai, gemini, deepseek, kimi, groq (Tip: groq offers a free API key - at https://console.groq.com)
  # Option 2: local agent login (no API key): claude-cli, codex-cli, agy-cli
  provider: deepseek

  # Maximum time (seconds) allowed for AI review.
  timeout: 20

policy:
  # Findings at or above this severity block the commit/push.
  # Options: low, medium, high, critical
  block_severity: high

reporting:
  # Minimum severity shown in CommitGate output.
  # Must be <= block_severity, so a blocking finding is never hidden
  # Options: low, medium, high, critical
  # Example: medium shows medium, high, and critical findings, but hides low findings.
  # Raising this also speeds up the AI review (fewer findings to generate).
  min_severity: medium

  # Control which optional fields are displayed for each finding.
  # Turning off description and suggestions also speeds up the AI review.
  fields:
    source: true
    category: true
    description: true
    suggestions: true
"""

# VALID INPUTS FOR VALIDATION
VALID_PROVIDERS = [
    "openai", "gemini", "deepseek", "kimi", "groq",
    "claude-cli", "codex-cli", "agy-cli",
]
VALID_SEVERITIES = ["low", "medium", "high", "critical"]
VALID_REPORTING_FIELDS = [
    "source",
    "category",
    "description",
    "suggestions",
]

SEVERITY_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

def get_config_path() -> Path:
    """
    Return the expected path of the CommitGate config file.

    For now, CommitGate expects the config file to live in the repository root.
    """
    return Path(CONFIG_FILE_NAME)

def create_default_config(overwrite: bool = True) -> Path:
    """
    Create a default commitgate.yaml file if one does not already exist.

    Args:
        overwrite: If true, replace an existing config file with defaults.

    Returns:
        Path to the config file.
    """
    path = get_config_path()

    if path.exists() and not overwrite:
        return path
    
    path.write_text(DEFAULT_CONFIG_YAML, encoding="utf-8")
    return path

def load_config() -> dict:
    """
    Load CommitGate's configuration.

    If commitgate.yaml does not exist, or is empty, the default
    configuration is returned.

    Returns:
        A complete configuration dictionary.
    """
    path = get_config_path()

    if not path.exists():
        config = deepcopy(DEFAULT_CONFIG)
    else:
        with open(path, "r", encoding="utf-8") as f:
            user_config = yaml.safe_load(f) 
        
        if not user_config:
            config = deepcopy(DEFAULT_CONFIG)
        elif not isinstance(user_config, dict):
            raise ValueError("commitgate.yaml must contain a YAML dictionary")
        else:
            config = merge_with_defaults(user_config)
    
    validate_config(config)
    return config

def merge_dicts(default_dict: dict, user_dict: dict) -> dict:
    """
    Helper function: Recursive dictionary merge
    """
    result = deepcopy(default_dict)

    for key, value in user_dict.items():
        # if the current subfield is also a dictionary, then we call the merge function
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result

def merge_with_defaults(user_config: dict) -> dict:
    """
    Merge a user config dictionary with CommitGate's default config.

    This allows users to edit only some values while CommitGate keeps safe
    defaults for missing fields.

    Args:
        user_config: Configuration loaded from commitgate.yaml.

    Returns:
        A complete configuration dictionary.
    """
    return merge_dicts(DEFAULT_CONFIG, user_config)

def validate_config(config: dict) -> None:
    if not isinstance(config["enabled"], bool):
        raise ValueError("enabled must be true or false")
    
    if not isinstance(config.get("policy"), dict):
        raise ValueError("policy must be a dictionary")

    if not isinstance(config.get("reporting"), dict):
        raise ValueError("reporting must be a dictionary")
    
    if not isinstance(config["ai"]["enabled"], bool):
        raise ValueError("ai.enabled must be true or false")
    
    if config["ai"]["provider"] not in VALID_PROVIDERS:
        raise ValueError(f"ai.provider must be one of: {', '.join(VALID_PROVIDERS)}")
    
    if not isinstance(config["ai"]["timeout"], int) or config["ai"]["timeout"] <= 0:
        raise ValueError("ai.timeout must be a positive integer")
    
    if config["policy"]["block_severity"] not in VALID_SEVERITIES:
        raise ValueError(f"policy.block_severity must be one of: {', '.join(VALID_SEVERITIES)}")
    
    if config["reporting"]["min_severity"] not in VALID_SEVERITIES:
        raise ValueError(f"reporting.min_severity must be one of: {', '.join(VALID_SEVERITIES)}")
    
    block_severity = config["policy"]["block_severity"]
    min_severity = config["reporting"]["min_severity"]

    if SEVERITY_ORDER[min_severity] > SEVERITY_ORDER[block_severity]:
        raise ValueError("reporting.min_severity must be equal to or lower than policy.block_severity, otherwise blocking findings could be hidden")
    
    fields = config["reporting"]["fields"]

    if not isinstance(fields, dict):
        raise ValueError("reporting.fields must be a dictionary")

    for field_name, enabled in fields.items():
        if field_name not in VALID_REPORTING_FIELDS:
            raise ValueError(f"Unknown reporting field: reporting.fields.{field_name}")
        
        if not isinstance(enabled, bool):
            raise ValueError(f"reporting.fields.{field_name} must be true or false")
