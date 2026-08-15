"""
test_config.py - Tests for the configuration module
"""

import os
import pytest
import tempfile
import yaml
from pathlib import Path

from ghast.core.config import (
    load_config,
    generate_default_config,
    save_config,
    merge_configs,
    validate_config,
    ConfigurationError,
    DEFAULT_CONFIG,
    disable_rules,
    _validate_severity_thresholds,
    _validate_auto_fix,
    _validate_defaults,
)
from ghast.core.scanner import Severity


def test_default_config():
    """Test that DEFAULT_CONFIG contains expected keys."""
    assert "timeout" in DEFAULT_CONFIG
    assert "shell_specification" in DEFAULT_CONFIG
    assert "deprecated_actions" in DEFAULT_CONFIG
    assert "severity_thresholds" in DEFAULT_CONFIG
    assert "auto_fix" in DEFAULT_CONFIG
    assert "default_timeout_minutes" in DEFAULT_CONFIG
    assert "default_action_versions" in DEFAULT_CONFIG


def test_load_config_default():
    """Test loading config with no file specified."""
    config = load_config()
    assert config is not None
    assert isinstance(config, dict)
    assert "timeout" in config


def test_load_config_with_path(temp_dir):
    """Test loading config from specified path."""

    config_path = os.path.join(temp_dir, "ghast.yml")
    test_config = {
        "timeout": False,
        "shell_specification": True,
        "severity_thresholds": {"deprecated_actions": "HIGH"},
    }

    with open(config_path, "w") as f:
        yaml.dump(test_config, f)

    config = load_config(config_path)

    assert config["timeout"] is False
    assert config["shell_specification"] is True
    assert config["severity_thresholds"]["deprecated_actions"] == "HIGH"

    assert "default_timeout_minutes" in config


def test_load_config_nonexistent():
    """Test error handling when config file doesn't exist."""
    with pytest.raises(ConfigurationError):
        load_config("/path/to/nonexistent/config.yml")


def test_load_config_invalid_yaml(temp_dir):
    """Test error handling for invalid YAML."""
    config_path = os.path.join(temp_dir, "invalid.yml")
    with open(config_path, "w") as f:
        f.write("This is not valid YAML: [unclosed bracket")

    with pytest.raises(ConfigurationError):
        load_config(config_path)


def test_auto_discovery_invalid_yaml_raises(monkeypatch, temp_dir):
    """Ensure auto-discovered configs with invalid YAML raise an error."""

    config_path = os.path.join(temp_dir, "ghast.yml")
    with open(config_path, "w") as f:
        f.write("invalid: [yaml")

    monkeypatch.setattr("ghast.core.config.get_config_paths", lambda: [config_path])

    with pytest.raises(ConfigurationError):
        load_config()


def test_auto_discovery_invalid_config_raises(monkeypatch, temp_dir):
    """Ensure auto-discovered configs with validation errors are not ignored."""

    config_path = os.path.join(temp_dir, "ghast.yml")
    with open(config_path, "w") as f:
        yaml.dump({"unknown_option": True}, f)

    monkeypatch.setattr("ghast.core.config.get_config_paths", lambda: [config_path])

    with pytest.raises(ConfigurationError):
        load_config()


def test_validate_config_valid():
    """Test config validation with valid config."""
    valid_config = {
        "timeout": True,
        "shell_specification": False,
        "severity_thresholds": {"timeout": "MEDIUM", "shell_specification": "HIGH"},
        "auto_fix": {"enabled": True, "rules": {"timeout": True}},
        "default_timeout_minutes": 10,
    }

    validate_config(valid_config)


def test_validate_config_invalid_rule_type():
    """Test config validation with invalid rule type."""
    invalid_config = {"timeout": "not_a_boolean"}

    with pytest.raises(ConfigurationError):
        validate_config(invalid_config)


def test_validate_config_invalid_severity():
    """Test config validation with invalid severity level."""
    invalid_config = {"severity_thresholds": {"timeout": "SUPER_HIGH"}}  # Invalid severity

    with pytest.raises(ConfigurationError):
        validate_config(invalid_config)


def test_validate_config_invalid_auto_fix():
    """Test config validation with invalid auto_fix structure."""
    invalid_config = {"auto_fix": "not_a_dict"}

    with pytest.raises(ConfigurationError):
        validate_config(invalid_config)


def test_validate_config_invalid_timeout():
    """Test config validation with invalid timeout value."""
    invalid_config = {"default_timeout_minutes": -5}  # Invalid timeout

    with pytest.raises(ConfigurationError):
        validate_config(invalid_config)


def test_validate_config_unknown_key():
    """Test that unknown config keys raise ConfigurationError."""
    invalid_config = {"unknown_key": True}

    with pytest.raises(ConfigurationError):
        validate_config(invalid_config)


def test_validate_config_unknown_key_with_suggestion():
    """Test unknown key error includes likely intended keys."""
    invalid_config = {"timeot": True}

    with pytest.raises(ConfigurationError, match=r"Did you mean: .*timeout"):
        validate_config(invalid_config)


def test_validate_config_unknown_key_without_suggestion():
    """Test unknown key error still references sample config when no suggestions exist."""
    invalid_config = {"zzzzzzzzzz": True}

    with pytest.raises(ConfigurationError, match="ghast rules"):
        validate_config(invalid_config)


def test_merge_configs():
    """Test merging configurations."""
    base_config = {
        "timeout": True,
        "shell_specification": True,
        "severity_thresholds": {"timeout": "LOW", "shell_specification": "LOW"},
        "simple_key": "base_value",
    }

    override_config = {
        "timeout": False,
        "severity_thresholds": {"timeout": "HIGH"},
        "new_key": "new_value",
        "simple_key": "override_value",
    }

    merged = merge_configs(base_config, override_config)

    assert merged["timeout"] is False
    assert merged["severity_thresholds"]["timeout"] == "HIGH"
    assert merged["simple_key"] == "override_value"

    assert merged["shell_specification"] is True
    assert merged["severity_thresholds"]["shell_specification"] == "LOW"

    assert merged["new_key"] == "new_value"


def test_generate_default_config():
    """Test generating default config."""
    config_str = generate_default_config()

    config = yaml.safe_load(config_str)
    assert config is not None
    assert "timeout" in config
    assert "severity_thresholds" in config
    assert "auto_fix" in config


def test_validate_severity_thresholds_helper():
    """Test helper for validating severity thresholds."""
    valid = {"severity_thresholds": {"timeout": "HIGH"}}
    _validate_severity_thresholds(valid)
    assert valid["severity_thresholds"]["timeout"] == "HIGH"

    mixed_case = {"severity_thresholds": {"timeout": "mEdIuM"}}
    _validate_severity_thresholds(mixed_case)
    assert mixed_case["severity_thresholds"]["timeout"] == "MEDIUM"

    invalid = {"severity_thresholds": {"timeout": "INVALID"}}
    with pytest.raises(ConfigurationError):
        _validate_severity_thresholds(invalid)


def test_validate_auto_fix_helper():
    """Test helper for validating auto_fix section."""
    valid = {"auto_fix": {"enabled": True, "rules": {"timeout": False}}}
    _validate_auto_fix(valid)

    invalid = {"auto_fix": {"rules": {"timeout": "yes"}}}
    with pytest.raises(ConfigurationError):
        _validate_auto_fix(invalid)


def test_validate_defaults_helper():
    """Test helper for validating default values."""
    valid = {"default_timeout_minutes": 5, "default_action_versions": {}}
    _validate_defaults(valid)

    invalid = {"default_timeout_minutes": -1}
    with pytest.raises(ConfigurationError):
        _validate_defaults(invalid)


def test_load_config_returns_deep_copy():
    """Mutating a loaded config should not affect DEFAULT_CONFIG."""
    config = load_config()

    config["auto_fix"]["rules"]["timeout"] = False
    config["severity_thresholds"]["timeout"] = Severity.CRITICAL

    assert DEFAULT_CONFIG["auto_fix"]["rules"]["timeout"] is True
    assert DEFAULT_CONFIG["severity_thresholds"]["timeout"] == Severity.LOW.value


def test_generate_default_config_to_file(temp_dir):
    """Test generating default config to a file."""
    output_path = os.path.join(temp_dir, "output_config.yml")
    generate_default_config(output_path)

    assert os.path.exists(output_path)

    with open(output_path, "r") as f:
        config = yaml.safe_load(f)

    assert config is not None
    assert "timeout" in config


def test_save_config(temp_dir):
    """Test saving config to file."""
    output_path = os.path.join(temp_dir, "saved_config.yml")
    config = {
        "timeout": False,
        "shell_specification": True,
        "severity_thresholds": {"deprecated_actions": "HIGH"},
    }

    save_config(config, output_path)

    assert os.path.exists(output_path)

    with open(output_path, "r") as f:
        loaded_config = yaml.safe_load(f)

    assert loaded_config["timeout"] is False
    assert loaded_config["shell_specification"] is True
    assert loaded_config["severity_thresholds"]["deprecated_actions"] == "HIGH"


def test_save_config_nonexistent_dir(temp_dir):
    """Test saving config to a non-existent directory."""

    output_path = os.path.join(temp_dir, "nonexistent", "saved_config.yml")
    config = {"timeout": False}

    save_config(config, output_path)

    assert os.path.exists(output_path)


def test_disable_rules():
    """Test disabling specific rules."""
    config = {"timeout": True, "shell_specification": True, "deprecated_actions": True}

    updated = disable_rules(config, ["timeout", "shell_specification"])

    assert config["timeout"] is True
    assert config["shell_specification"] is True

    assert updated["timeout"] is False
    assert updated["shell_specification"] is False
    assert updated["deprecated_actions"] is True


def test_disable_nonexistent_rules():
    """Test disabling rules that don't exist in the config."""
    config = {"timeout": True}

    updated = disable_rules(config, ["nonexistent_rule"])

    assert updated["timeout"] is True
    assert "nonexistent_rule" not in updated
