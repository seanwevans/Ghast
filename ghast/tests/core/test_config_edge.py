"""
test_config_edge.py - Edge-case coverage for configuration management

Covers enum/list serialization, the validation error branches, config auto
discovery (empty/unreadable/invalid/valid files), and save/generate failures.
"""

import os

import pytest
import yaml

from ghast.core import config as config_module
from ghast.core.config import (
    ConfigurationError,
    _serialize_enums,
    generate_default_config,
    load_config,
    save_config,
    validate_config,
)
from ghast.core.scanner import Severity


def test_serialize_enums_handles_lists_and_enums():
    obj = {"levels": [Severity.LOW, Severity.HIGH], "nested": {"sev": Severity.CRITICAL}}
    result = _serialize_enums(obj)
    assert result == {"levels": ["LOW", "HIGH"], "nested": {"sev": "CRITICAL"}}


def test_validate_severity_thresholds_not_dict():
    with pytest.raises(ConfigurationError, match="severity_thresholds"):
        validate_config({"severity_thresholds": "not-a-dict"})


def test_validate_auto_fix_enabled_not_bool():
    with pytest.raises(ConfigurationError, match="auto_fix.enabled"):
        validate_config({"auto_fix": {"enabled": "yes"}})


def test_validate_auto_fix_rules_not_dict():
    with pytest.raises(ConfigurationError, match="auto_fix.rules"):
        validate_config({"auto_fix": {"rules": "nope"}})


def test_validate_defaults_timeout_not_int():
    with pytest.raises(ConfigurationError, match="default_timeout_minutes"):
        validate_config({"default_timeout_minutes": "abc"})


def test_validate_defaults_action_versions_not_dict():
    with pytest.raises(ConfigurationError, match="default_action_versions"):
        validate_config({"default_action_versions": "nope"})


def test_load_config_explicit_path_invalid(tmp_path):
    bad = tmp_path / "ghast.yml"
    bad.write_text("totally_unknown_key: true\n")
    with pytest.raises(ConfigurationError, match="Error loading configuration"):
        load_config(str(bad))


def test_load_config_autodiscovery_skips_unreadable(monkeypatch, tmp_path):
    # A directory cannot be opened with open(..., "r") -> OSError -> skipped.
    a_dir = tmp_path / "ghast.yml"
    a_dir.mkdir()
    monkeypatch.setattr(config_module, "get_config_paths", lambda: [str(a_dir)])
    cfg = load_config()
    # Falls back to defaults.
    assert cfg["check_timeout"] is True


def test_load_config_autodiscovery_skips_empty(monkeypatch, tmp_path):
    empty = tmp_path / "ghast.yml"
    empty.write_text("")
    monkeypatch.setattr(config_module, "get_config_paths", lambda: [str(empty)])
    cfg = load_config()
    assert cfg["check_timeout"] is True


def test_load_config_autodiscovery_invalid_raises(monkeypatch, tmp_path):
    bad = tmp_path / "ghast.yml"
    bad.write_text("unknown_option: true\n")
    monkeypatch.setattr(config_module, "get_config_paths", lambda: [str(bad)])
    with pytest.raises(ConfigurationError, match="Unknown configuration option"):
        load_config()


def test_load_config_autodiscovery_unexpected_validation_error(monkeypatch, tmp_path):
    good = tmp_path / "ghast.yml"
    good.write_text("check_timeout: false\n")
    monkeypatch.setattr(config_module, "get_config_paths", lambda: [str(good)])

    def _boom(_cfg):
        raise ValueError("unexpected")

    monkeypatch.setattr(config_module, "validate_config", _boom)
    with pytest.raises(ConfigurationError, match="Error validating configuration"):
        load_config()


def test_load_config_autodiscovery_valid(monkeypatch, tmp_path):
    good = tmp_path / "ghast.yml"
    good.write_text("check_timeout: false\n")
    monkeypatch.setattr(config_module, "get_config_paths", lambda: [str(good)])
    cfg = load_config()
    assert cfg["check_timeout"] is False


def test_load_config_autodiscovery_yaml_error(monkeypatch, tmp_path):
    bad = tmp_path / "ghast.yml"
    bad.write_text("key: [unclosed\n")
    monkeypatch.setattr(config_module, "get_config_paths", lambda: [str(bad)])
    with pytest.raises(ConfigurationError, match="Error parsing YAML"):
        load_config()


def test_save_config_failure(monkeypatch, tmp_path):
    def _boom(*args, **kwargs):
        raise RuntimeError("dump failed")

    monkeypatch.setattr(config_module.yaml, "dump", _boom)
    with pytest.raises(ConfigurationError, match="Error saving configuration"):
        save_config({"check_timeout": True}, str(tmp_path / "out.yml"))


def test_generate_default_config_write_failure(monkeypatch, tmp_path):
    target = tmp_path / "default.yml"

    real_open = open

    def _boom(path, *args, **kwargs):
        if str(path) == str(target):
            raise OSError("cannot write")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", _boom)
    with pytest.raises(ConfigurationError, match="Error saving default configuration"):
        generate_default_config(str(target))
