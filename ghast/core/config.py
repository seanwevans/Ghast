"""
config.py - Configuration management for ghast

This module handles loading, validating, and managing configuration for the ghast tool.
"""

import difflib
import os
import sys
import yaml
from typing import Any, Dict, Optional, List, cast

from .scanner import Severity, normalize_severity


def _registry() -> Any:
    """Import the rule registry lazily.

    ``ghast.rules`` imports ``ghast.core`` for Finding, so importing it at
    module scope here would be circular.
    """
    from ..rules import registry

    return registry


def build_default_config() -> Dict[str, Any]:
    """Build the default configuration from the rule registry."""
    return cast(Dict[str, Any], _registry().build_default_config())


def __getattr__(name: str) -> Any:
    """Expose DEFAULT_CONFIG without importing the registry at module scope."""
    if name == "DEFAULT_CONFIG":
        return build_default_config()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _report_warnings(warnings: List[str], source: str) -> None:
    """Surface config warnings on stderr.

    A key that loads but does nothing is the failure mode this module exists to
    remove, so it must not be silent.
    """
    for warning in warnings:
        print(f"warning: {source}: {warning}", file=sys.stderr)


#: Sections that are not per-rule toggles.
CONFIG_SECTIONS = {
    "severity_thresholds",
    "auto_fix",
    "report",
    "default_timeout_minutes",
    "default_action_versions",
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
                config["severity_thresholds"][rule] = normalize_severity(severity)
            except ValueError:
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


def validate_config(config: Dict[str, Any]) -> List[str]:
    """Validate configuration structure and values.

    Args:
        config: The user-supplied configuration.

    Returns:
        Human-readable warnings for keys that load but do not do anything,
        so a typo or a retired option is visible rather than silent.

    Raises:
        ConfigurationError: If a key names no known rule or a value is invalid.
    """
    registry = _registry()
    rule_ids = set(registry.all_rule_ids())
    retired = registry.RETIRED_CONFIG_KEYS
    warnings: List[str] = []

    suggestable = sorted(rule_ids | CONFIG_SECTIONS)

    for key in config.keys():
        if key in CONFIG_SECTIONS:
            continue

        if key in retired:
            warnings.append(
                f"Configuration option '{key}' refers to a rule that does not exist "
                "and has no effect. It can be removed."
            )
            continue

        rule_id = registry.canonical_rule_id(key, rule_ids)

        if rule_id is None:
            suggestions = difflib.get_close_matches(key, suggestable, n=3, cutoff=0.5)

            message = f"Unknown configuration option '{key}'."
            if suggestions:
                message += f" Did you mean: {', '.join(suggestions)}?"
            message += " Run 'ghast rules' to list every rule id."

            raise ConfigurationError(message)

        if rule_id != key:
            warnings.append(
                f"Configuration option '{key}' is a legacy name for rule '{rule_id}'. "
                f"Rename it to '{rule_id}'."
            )

        if not isinstance(config[key], bool):
            raise ConfigurationError(f"Rule '{key}' must be a boolean (true/false)")

    warnings.extend(_validate_rule_section(config, "severity_thresholds", rule_ids, retired))
    warnings.extend(
        _validate_rule_section(config.get("auto_fix", {}), "rules", rule_ids, retired, "auto_fix.")
    )

    _validate_severity_thresholds(config)
    _validate_auto_fix(config)
    _validate_defaults(config)

    return warnings


def _validate_rule_section(
    container: Any,
    section: str,
    rule_ids: set,
    retired: set,
    prefix: str = "",
) -> List[str]:
    """Check the rule names used inside a nested config section."""
    if not isinstance(container, dict):
        return []

    values = container.get(section)
    if not isinstance(values, dict):
        return []

    registry = _registry()
    warnings: List[str] = []

    for key in values:
        if key in retired:
            warnings.append(
                f"'{prefix}{section}.{key}' refers to a rule that does not exist "
                "and has no effect."
            )
            continue

        rule_id = registry.canonical_rule_id(key, rule_ids)

        if rule_id is None:
            raise ConfigurationError(
                f"Unknown rule '{key}' in '{prefix}{section}'. "
                "Run 'ghast rules' to list every rule id."
            )

        if rule_id != key:
            warnings.append(
                f"'{prefix}{section}.{key}' is a legacy name for rule '{rule_id}'. "
                f"Rename it to '{rule_id}'."
            )

    return warnings


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
    config = build_default_config()

    if config_path:
        if not os.path.exists(config_path):
            raise ConfigurationError(f"Configuration file not found: {config_path}")

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f)

            if user_config:

                _report_warnings(validate_config(user_config), config_path)
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
                except OSError:
                    # Skip unreadable files and continue searching
                    continue
                except yaml.YAMLError as e:
                    raise ConfigurationError(
                        f"Error parsing YAML configuration in {path}: {e}"
                    ) from e

                if not user_config:
                    # Empty files are ignored so discovery can continue
                    continue

                try:
                    _report_warnings(validate_config(user_config), path)
                except ConfigurationError:
                    raise
                except Exception as e:
                    raise ConfigurationError(
                        f"Error validating configuration in {path}: {e}"
                    ) from e

                config = merge_configs(config, user_config)
                break

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
        yaml.dump(
            _serialize_enums(build_default_config()), default_flow_style=False, sort_keys=False
        ),
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
    registry = _registry()
    rule_ids = set(registry.all_rule_ids())

    for rule in rules:
        # Previously this only disabled keys already present in the config, so
        # disabling a rule the caller had not already named did nothing at all.
        # Unresolvable names are left out; callers validate them up front.
        rule_id = registry.canonical_rule_id(rule, rule_ids)
        if rule_id is not None:
            updated_config[rule_id] = False

    return updated_config


def unknown_rule_names(rules: List[str]) -> List[str]:
    """Return the names in ``rules`` that do not resolve to a known rule."""
    registry = _registry()
    rule_ids = set(registry.all_rule_ids())
    return [rule for rule in rules if registry.canonical_rule_id(rule, rule_ids) is None]
