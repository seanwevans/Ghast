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
    assert "check_timeout" in DEFAULT_CONFIG
    assert "check_shell" in DEFAULT_CONFIG
    assert "check_deprecated" in DEFAULT_CONFIG
    assert "severity_thresholds" in DEFAULT_CONFIG
    assert "auto_fix" in DEFAULT_CONFIG
    assert "default_timeout_minutes" in DEFAULT_CONFIG
    assert "default_action_versions" in DEFAULT_CONFIG


def test_load_config_default():
    """Test loading config with no file specified."""
    config = load_config()
    assert config is not None
    assert isinstance(config, dict)
    assert "check_timeout" in config


def test_load_config_with_path(temp_dir):
    """Test loading config from specified path."""

    config_path = os.path.join(temp_dir, "ghast.yml")
    test_config = {
        "check_timeout": False,
        "check_shell": True,
        "severity_thresholds": {"check_deprecated": "HIGH"},
    }

    with open(config_path, "w") as f:
        yaml.dump(test_config, f)

    config = load_config(config_path)

    assert config["check_timeout"] is False
    assert config["check_shell"] is True
    assert config["severity_thresholds"]["check_deprecated"] == Severity.HIGH

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
        "check_timeout": True,
        "check_shell": False,
        "severity_thresholds": {"check_timeout": "MEDIUM", "check_shell": "HIGH"},
        "auto_fix": {"enabled": True, "rules": {"check_timeout": True}},
        "default_timeout_minutes": 10,
    }

    validate_config(valid_config)


def test_validate_config_invalid_rule_type():
    """Test config validation with invalid rule type."""
    invalid_config = {"check_timeout": "not_a_boolean"}

    with pytest.raises(ConfigurationError):
        validate_config(invalid_config)


def test_validate_config_invalid_severity():
    """Test config validation with invalid severity level."""
    invalid_config = {"severity_thresholds": {"check_timeout": "SUPER_HIGH"}}  # Invalid severity

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


def test_merge_configs():
    """Test merging configurations."""
    base_config = {
        "check_timeout": True,
        "check_shell": True,
        "severity_thresholds": {"check_timeout": "LOW", "check_shell": "LOW"},
        "simple_key": "base_value",
    }

    override_config = {
        "check_timeout": False,
        "severity_thresholds": {"check_timeout": "HIGH"},
        "new_key": "new_value",
        "simple_key": "override_value",
    }

    merged = merge_configs(base_config, override_config)

    assert merged["check_timeout"] is False
    assert merged["severity_thresholds"]["check_timeout"] == "HIGH"
    assert merged["simple_key"] == "override_value"

    assert merged["check_shell"] is True
    assert merged["severity_thresholds"]["check_shell"] == "LOW"

    assert merged["new_key"] == "new_value"


def test_generate_default_config():
    """Test generating default config."""
    config_str = generate_default_config()

    config = yaml.safe_load(config_str)
    assert config is not None
    assert "check_timeout" in config
    assert "severity_thresholds" in config
    assert "auto_fix" in config


def test_validate_severity_thresholds_helper():
    """Test helper for validating severity thresholds."""
    valid = {"severity_thresholds": {"check_timeout": "HIGH"}}
    _validate_severity_thresholds(valid)

    invalid = {"severity_thresholds": {"check_timeout": "INVALID"}}
    with pytest.raises(ConfigurationError):
        _validate_severity_thresholds(invalid)


def test_validate_auto_fix_helper():
    """Test helper for validating auto_fix section."""
    valid = {"auto_fix": {"enabled": True, "rules": {"check_timeout": False}}}
    _validate_auto_fix(valid)

    invalid = {"auto_fix": {"rules": {"check_timeout": "yes"}}}
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

    config["auto_fix"]["rules"]["check_timeout"] = False
    config["severity_thresholds"]["check_timeout"] = Severity.CRITICAL

    assert DEFAULT_CONFIG["auto_fix"]["rules"]["check_timeout"] is True
    assert DEFAULT_CONFIG["severity_thresholds"]["check_timeout"] == Severity.LOW


def test_generate_default_config_to_file(temp_dir):
    """Test generating default config to a file."""
    output_path = os.path.join(temp_dir, "output_config.yml")
    generate_default_config(output_path)

    assert os.path.exists(output_path)

    with open(output_path, "r") as f:
        config = yaml.safe_load(f)

    assert config is not None
    assert "check_timeout" in config


def test_save_config(temp_dir):
    """Test saving config to file."""
    output_path = os.path.join(temp_dir, "saved_config.yml")
    config = {
        "check_timeout": False,
        "check_shell": True,
        "severity_thresholds": {"check_deprecated": "HIGH"},
    }

    save_config(config, output_path)

    assert os.path.exists(output_path)

    with open(output_path, "r") as f:
        loaded_config = yaml.safe_load(f)

    assert loaded_config["check_timeout"] is False
    assert loaded_config["check_shell"] is True
    assert loaded_config["severity_thresholds"]["check_deprecated"] == "HIGH"


def test_save_config_nonexistent_dir(temp_dir):
    """Test saving config to a non-existent directory."""

    output_path = os.path.join(temp_dir, "nonexistent", "saved_config.yml")
    config = {"check_timeout": False}

    save_config(config, output_path)

    assert os.path.exists(output_path)


def test_disable_rules():
    """Test disabling specific rules."""
    config = {"check_timeout": True, "check_shell": True, "check_deprecated": True}

    updated = disable_rules(config, ["check_timeout", "check_shell"])

    assert config["check_timeout"] is True
    assert config["check_shell"] is True

    assert updated["check_timeout"] is False
    assert updated["check_shell"] is False
    assert updated["check_deprecated"] is True


def test_disable_nonexistent_rules():
    """Test disabling rules that don't exist in the config."""
    config = {"check_timeout": True}

    updated = disable_rules(config, ["nonexistent_rule"])

    assert updated["check_timeout"] is True
    assert "nonexistent_rule" not in updated
