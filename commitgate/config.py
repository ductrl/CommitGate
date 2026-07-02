from copy import deepcopy
from pathlib import Path

import yaml 

CONFIG_FILE_NAME = "commitgate.yaml"

DEFAULT_CONFIG = {
    "ai": {
        "enabled": True,
        "provider": "deepseek",
        "timeout": 20,
    },
    "policy": {
        "block_severity": "high",
    },
    "reporting": {
        "show_suggestions": True,
    },
}

def get_config_path() -> Path:
    """
    Return the expected path of the CommitGate config file.

    For now, CommitGate expects the config file to live in the repository root.
    """
    return Path(CONFIG_FILE_NAME)

def create_default_config() -> Path:
    """
    Create a default commitgate.yaml file if one does not already exist.

    Returns:
        Path to the config file.

    Notes:
        This function does not overwrite an existing config file.
    """
    path = get_config_path()

    if path.exists():
        return path
    
    with open(path, "w", encoding="utf-8") as f:
        # One-line discoverability hint, then the defaults. DEFAULT_CONFIG stays the single
        # source of truth for the values; the comment only names the provider options.
        f.write("# ai.provider: openai / deepseek / gemini / groq (need AI_KEY), or a local CLI "
                "with no key -- claude-cli (Claude Code) / codex-cli (Codex)\n")
        yaml.safe_dump(DEFAULT_CONFIG, f, sort_keys=False)

    return path

def load_config() -> dict:
    """
    Create a default commitgate.yaml file if one does not already exist.

    Returns:
        Path to the config file.

    Notes:
        This function does not overwrite an existing config file.
    """
    path = get_config_path()

    if not path.exists():
        return deepcopy(DEFAULT_CONFIG)
    
    with open(path, "r", encoding="utf-8") as f:
        user_config = yaml.safe_load(f) 
    
    if not user_config:
        return deepcopy(DEFAULT_CONFIG)
    
    if not isinstance(user_config, dict):
        raise ValueError("commitgate.yaml must contain a YAML dictionary")
    
    return merge_with_defaults(user_config=user_config)

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
    config = deepcopy(DEFAULT_CONFIG)

    for section, values in user_config.items():
        if isinstance(values, dict) and section in config:
            config[section] = {
                **config[section],
                **values,
            }
        else:
            config[section] = values

    return config