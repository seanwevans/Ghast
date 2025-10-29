"""
config.py - Configuration management for ghast

This module handles loading, validating, and managing configuration for the ghast tool.
"""

import copy
import os
import yaml
from typing import Any, Dict, Optional, List, cast

from .scanner import Severity

DEFAULT_CONFIG = {
    "check_timeout": True,
    "check_shell": True,
    "check_deprecated": True,
    "check_runs_on": True,
    "check_workflow_name": True,
    "check_continue_on_error": True,
    "check_tokens": True,
    "check_inline_bash": True,
    "check_reusable_inputs": True,
    "check_ppe_vulnerabilities": True,
    "check_command_injection": True,
    "check_env_injection": True,
    "severity_thresholds": {
        "check_timeout": Severity.LOW,
        "check_shell": Severity.LOW,
        "check_deprecated": Severity.MEDIUM,
        "check_runs_on": Severity.MEDIUM,
        "check_workflow_name": Severity.LOW,
        "check_continue_on_error": Severity.MEDIUM,
        "check_tokens": Severity.HIGH,
        "check_inline_bash": Severity.LOW,
        "check_reusable_inputs": Severity.MEDIUM,
        "check_ppe_vulnerabilities": Severity.CRITICAL,
        "check_command_injection": Severity.HIGH,
        "check_env_injection": Severity.HIGH,
    },
    "auto_fix": {
        "enabled": True,
        "rules": {
            "check_timeout": True,
            "check_shell": True,
            "check_deprecated": True,
            "check_workflow_name": True,
            "check_runs_on": False,  # Unsafe to auto-fix runner settings
            "check_continue_on_error": False,  # Unsafe to auto-fix
            "check_tokens": False,  # Unsafe to auto-fix tokens
            "check_inline_bash": True,
            "check_reusable_inputs": False,  # Requires understanding of workflow structure
            "check_ppe_vulnerabilities": False,  # Too complex for auto-fix
            "check_command_injection": False,  # Too complex for auto-fix
            "check_env_injection": False,  # Too complex for auto-fix
        },
    },
    "default_timeout_minutes": 15,
    "default_action_versions": {
        "actions/checkout@v1": "actions/checkout@v3",
        "actions/checkout@v2": "actions/checkout@v3",
        "actions/setup-python@v1": "actions/setup-python@v4",
        "actions/setup-python@v2": "actions/setup-python@v4",
        "actions/setup-node@v1": "actions/setup-node@v3",
        "actions/setup-node@v2": "actions/setup-node@v3",
        "actions/cache@v1": "actions/cache@v3",
        "actions/cache@v2": "actions/cache@v3",
    },
    "report": {
        "include_remediation": True,
        "show_context": True,
        "color_output": True,
        "verbose": False,
        "summary": True,
    },
}


class ConfigurationError(Exception):
    """Exception raised for configuration errors"""

    pass


def get_config_paths() -> List[str]:
    """
    Get list of possible config file locations in priority order

    Returns:
        List of config file paths to check
    """
    paths = []

    paths.append(os.path.join(os.getcwd(), "ghast.yml"))
    paths.append(os.path.join(os.getcwd(), "ghast.yaml"))
    paths.append(os.path.join(os.getcwd(), ".ghast.yml"))
    paths.append(os.path.join(os.getcwd(), ".ghast.yaml"))

    home_dir = os.path.expanduser("~")
    paths.append(os.path.join(home_dir, ".ghast.yml"))
    paths.append(os.path.join(home_dir, ".ghast.yaml"))
    paths.append(os.path.join(home_dir, ".config", "ghast", "config.yml"))
    paths.append(os.path.join(home_dir, ".config", "ghast", "config.yaml"))

    if os.name == "posix":
        paths.append("/etc/ghast/config.yml")
        paths.append("/etc/ghast/config.yaml")

    return paths


def merge_configs(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge two config dictionaries

    Args:
        base: Base configuration
        override: Configuration to override base

    Returns:
        Merged configuration dictionary
    """
    result = base.copy()

    for key, override_value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(override_value, dict):

            result[key] = merge_configs(result[key], override_value)
        else:

            result[key] = override_value

    return result


def _serialize_enums(obj: Any) -> Any:
    """Recursively convert Enum values to their underlying value for YAML output."""
    if isinstance(obj, dict):
        return {k: _serialize_enums(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize_enums(v) for v in obj]
    if isinstance(obj, Severity):
        return obj.value
    return obj


def _validate_severity_thresholds(config: Dict[str, Any]) -> None:
    """Validate severity threshold configuration."""

    if "severity_thresholds" in config:
        if not isinstance(config["severity_thresholds"], dict):
            raise ConfigurationError("'severity_thresholds' must be a dictionary")

        for rule, severity in list(config["severity_thresholds"].items()):
            try:
                config["severity_thresholds"][rule] = Severity(severity)
            except Exception:
                valid = ", ".join(level.value for level in Severity)
                raise ConfigurationError(
                    f"Invalid severity '{severity}' for rule '{rule}'. Must be one of: {valid}"
                )


def _validate_auto_fix(config: Dict[str, Any]) -> None:
    """Validate auto-fix configuration"""

    if "auto_fix" in config:
        if not isinstance(config["auto_fix"], dict):
            raise ConfigurationError("'auto_fix' must be a dictionary")

        if "enabled" in config["auto_fix"] and not isinstance(config["auto_fix"]["enabled"], bool):
            raise ConfigurationError("'auto_fix.enabled' must be a boolean")

        if "rules" in config["auto_fix"]:
            if not isinstance(config["auto_fix"]["rules"], dict):
                raise ConfigurationError("'auto_fix.rules' must be a dictionary")

            for rule, enabled in config["auto_fix"]["rules"].items():
                if not isinstance(enabled, bool):
                    raise ConfigurationError(f"'auto_fix.rules.{rule}' must be a boolean")


def _validate_defaults(config: Dict[str, Any]) -> None:
    """Validate default configuration values"""

    if "default_timeout_minutes" in config:
        try:
            timeout = int(config["default_timeout_minutes"])
            if timeout <= 0:
                raise ConfigurationError("'default_timeout_minutes' must be a positive integer")
        except ValueError:
            raise ConfigurationError("'default_timeout_minutes' must be a positive integer")

    if "default_action_versions" in config:
        if not isinstance(config["default_action_versions"], dict):
            raise ConfigurationError("'default_action_versions' must be a dictionary")


def validate_config(config: Dict[str, Any]) -> None:
    """Validate configuration structure and values"""

    allowed_sections = {
        "severity_thresholds",
        "auto_fix",
        "report",
        "default_timeout_minutes",
        "default_action_versions",
    }

    # Check for unknown top-level keys in the provided config
    for key in config.keys():
        if key not in DEFAULT_CONFIG and key not in allowed_sections:
            raise ConfigurationError(f"Unknown configuration option '{key}'")

    for rule_key in DEFAULT_CONFIG.keys():
        if (
            rule_key != "severity_thresholds"
            and rule_key != "auto_fix"
            and rule_key != "report"
            and rule_key != "default_timeout_minutes"
            and rule_key != "default_action_versions"
        ):
            if rule_key in config and not isinstance(config[rule_key], bool):
                raise ConfigurationError(f"Rule '{rule_key}' must be a boolean (true/false)")

    _validate_severity_thresholds(config)
    _validate_auto_fix(config)
    _validate_defaults(config)


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from file or use defaults

    Args:
        config_path: Path to configuration file, or None to auto-detect

    Returns:
        Loaded configuration dictionary

    Raises:
        ConfigurationError: If configuration file is invalid
    """
    config = copy.deepcopy(DEFAULT_CONFIG)

    if config_path:
        if not os.path.exists(config_path):
            raise ConfigurationError(f"Configuration file not found: {config_path}")

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f)

            if user_config:

                validate_config(user_config)
                config = merge_configs(config, user_config)
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Error parsing YAML configuration: {e}")
        except Exception as e:
            raise ConfigurationError(f"Error loading configuration: {e}")
    else:

        for path in get_config_paths():
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        user_config = yaml.safe_load(f)

                    if user_config:

                        validate_config(user_config)
                        config = merge_configs(config, user_config)
                        break
                except Exception:

                    pass

    return config


def save_config(config: Dict[str, Any], config_path: str) -> None:
    """
    Save configuration to file

    Args:
        config: Configuration dictionary to save
        config_path: Path to save configuration to

    Raises:
        ConfigurationError: If configuration cannot be saved
    """
    try:

        os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)

        with open(config_path, "w") as f:
            yaml.dump(_serialize_enums(config), f, default_flow_style=False, sort_keys=False)

    except Exception as e:
        raise ConfigurationError(f"Error saving configuration: {e}")


def generate_default_config(output_path: Optional[str] = None) -> str:
    """
    Generate default configuration YAML

    Args:
        output_path: Path to save default configuration to, or None to return as string

    Returns:
        Default configuration YAML if output_path is None

    Raises:
        ConfigurationError: If configuration cannot be saved
    """
    default_config_yaml = cast(
        str,
        yaml.dump(_serialize_enums(DEFAULT_CONFIG), default_flow_style=False, sort_keys=False),
    )

    if output_path:
        try:

            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(default_config_yaml)
        except Exception as e:
            raise ConfigurationError(f"Error saving default configuration: {e}")

    return default_config_yaml


def disable_rules(config: Dict[str, Any], rules: List[str]) -> Dict[str, Any]:
    """
    Disable specific rules in a configuration

    Args:
        config: Configuration dictionary
        rules: List of rule IDs to disable

    Returns:
        Updated configuration dictionary
    """
    updated_config = config.copy()

    for rule in rules:
        if rule in updated_config:
            updated_config[rule] = False

    return updated_config
