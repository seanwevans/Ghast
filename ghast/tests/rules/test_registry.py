"""Tests that rule identity stays consistent across the codebase.

Rule identity used to be spelled three ways — the rule's own ``rule_id``, the
config key that was supposed to toggle it, and the id reported on findings.
Nothing checked they agreed, so seven of twelve rules could not be configured
at all and two config keys named rules that had never been written.

These tests close that gap: every rule must have a working toggle, and every
config key must name a rule that exists.
"""

import pytest

from ghast.core.config import (
    ConfigurationError,
    build_default_config,
    disable_rules,
    unknown_rule_names,
    validate_config,
)
from ghast.core.fixer import Fixer
from ghast.rules.engine import RuleEngine
from ghast.rules.registry import (
    LEGACY_CONFIG_ALIASES,
    RETIRED_CONFIG_KEYS,
    all_rule_ids,
    build_default_rules,
    canonical_rule_id,
    fixable_rule_ids,
)

RULE_IDS = all_rule_ids()


# --- every rule is reachable from configuration -------------------------------


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_every_rule_can_be_disabled_by_its_id(rule_id):
    engine = RuleEngine(config={rule_id: False})
    rule = engine.get_rule_by_id(rule_id)

    assert rule is not None
    assert rule.enabled is False


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_every_rule_can_be_enabled_by_its_id(rule_id):
    """Includes rules that ship disabled, which previously could not be turned on."""
    engine = RuleEngine(config={rule_id: True})
    rule = engine.get_rule_by_id(rule_id)

    assert rule is not None
    assert rule.enabled is True


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_every_rule_severity_is_configurable(rule_id):
    engine = RuleEngine(config={"severity_thresholds": {rule_id: "CRITICAL"}})

    assert engine.get_rule_by_id(rule_id).severity == "CRITICAL"


def test_environment_injection_ships_disabled_but_is_reachable():
    """It was hardcoded off in __init__ where no config key could reach it."""
    assert RuleEngine().get_rule_by_id("environment_injection").enabled is False
    assert (
        RuleEngine(config={"environment_injection": True})
        .get_rule_by_id("environment_injection")
        .enabled
        is True
    )


# --- the config vocabulary matches the rule set -------------------------------


def test_default_config_toggles_exactly_the_registered_rules():
    config = build_default_config()
    toggles = {key for key, value in config.items() if isinstance(value, bool)}

    assert toggles == set(RULE_IDS)


def test_default_config_defaults_match_rule_defaults():
    config = build_default_config()

    for rule in build_default_rules():
        assert config[rule.rule_id] is rule.enabled
        assert config["severity_thresholds"][rule.rule_id] == rule.severity


def test_every_severity_threshold_key_names_a_real_rule():
    assert set(build_default_config()["severity_thresholds"]) == set(RULE_IDS)


def test_every_auto_fix_key_names_a_real_rule():
    assert set(build_default_config()["auto_fix"]["rules"]) == set(RULE_IDS)


def test_auto_fix_defaults_track_which_rules_implement_fix():
    auto_fix = build_default_config()["auto_fix"]["rules"]
    enabled = {rule_id for rule_id, on in auto_fix.items() if on}

    assert enabled == set(fixable_rule_ids())


def test_generated_config_validates_cleanly():
    """The config ghast generates must be one ghast accepts, with no warnings."""
    config = build_default_config()

    assert validate_config(config) == []


# --- legacy names keep working, loudly ---------------------------------------


@pytest.mark.parametrize("legacy,rule_id", sorted(LEGACY_CONFIG_ALIASES.items()))
def test_legacy_alias_resolves_to_its_rule(legacy, rule_id):
    assert rule_id in RULE_IDS
    assert canonical_rule_id(legacy) == rule_id


@pytest.mark.parametrize("legacy,rule_id", sorted(LEGACY_CONFIG_ALIASES.items()))
def test_legacy_alias_actually_disables_the_rule(legacy, rule_id):
    """`check_tokens: false` was accepted and silently did nothing."""
    engine = RuleEngine(config={legacy: False})

    assert engine.get_rule_by_id(rule_id).enabled is False


@pytest.mark.parametrize("legacy", sorted(LEGACY_CONFIG_ALIASES))
def test_legacy_alias_warns_but_loads(legacy):
    warnings = validate_config({legacy: False})

    assert any("legacy name" in warning for warning in warnings)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_check_prefixed_canonical_id_is_accepted(rule_id):
    """Findings were reported as `check_<id>`, so people wrote that in configs."""
    assert canonical_rule_id(f"check_{rule_id}") == rule_id


@pytest.mark.parametrize("retired", sorted(RETIRED_CONFIG_KEYS))
def test_retired_keys_load_with_a_warning(retired):
    """These named rules that were never implemented."""
    warnings = validate_config({retired: True})

    assert any("does not exist" in warning for warning in warnings)


def test_retired_key_names_no_rule():
    for retired in RETIRED_CONFIG_KEYS:
        assert canonical_rule_id(retired) is None


def test_unknown_key_is_rejected_with_a_suggestion():
    with pytest.raises(ConfigurationError, match="Did you mean: .*timeout"):
        validate_config({"timeot": True})


def test_unknown_key_in_severity_thresholds_is_rejected():
    with pytest.raises(ConfigurationError, match="Unknown rule 'nope'"):
        validate_config({"severity_thresholds": {"nope": "HIGH"}})


def test_unknown_key_in_auto_fix_is_rejected():
    with pytest.raises(ConfigurationError, match="Unknown rule 'nope'"):
        validate_config({"auto_fix": {"rules": {"nope": True}}})


def test_severity_threshold_legacy_alias_warns():
    warnings = validate_config({"severity_thresholds": {"check_tokens": "HIGH"}})

    assert any("legacy name" in warning for warning in warnings)


def test_retired_key_in_nested_section_warns():
    warnings = validate_config({"auto_fix": {"rules": {"check_runs_on": True}}})

    assert any("does not exist" in warning for warning in warnings)


def test_non_dict_sections_are_ignored_by_rule_name_checks():
    assert validate_config({"auto_fix": {"enabled": True}}) == []


# --- disable_rules ------------------------------------------------------------


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_disable_rules_adds_missing_keys(rule_id):
    """It previously only touched keys the caller had already written."""
    assert disable_rules({}, [rule_id]) == {rule_id: False}


def test_disable_rules_normalizes_legacy_names():
    assert disable_rules({}, ["check_tokens"]) == {"token_security": False}


def test_disable_rules_ignores_unknown_names():
    assert disable_rules({}, ["nope"]) == {}


def test_unknown_rule_names_reports_only_unresolvable():
    assert unknown_rule_names(["timeout", "check_tokens", "nope"]) == ["nope"]


# --- the fixer registry agrees with the rules ---------------------------------


def test_every_fixer_key_names_a_real_rule():
    """`check_shell` and `check_deprecated` were registered here, but no
    finding ever carried those ids, so those two fixers never ran."""
    assert set(Fixer({}).fixers).issubset(set(RULE_IDS))


def test_fixer_covers_the_rules_it_claims():
    fixer_keys = set(Fixer({}).fixers)

    assert {"timeout", "shell_specification", "deprecated_actions", "workflow_name"} <= fixer_keys


# --- findings report the canonical id ----------------------------------------


def test_findings_use_bare_rule_ids(insecure_workflow_file):
    from ghast.core import WorkflowScanner

    findings = WorkflowScanner().scan_file(insecure_workflow_file)

    assert findings
    for finding in findings:
        base = finding.rule_id.split(".", 1)[-1]
        assert base in RULE_IDS, f"finding reports unknown rule id {finding.rule_id!r}"
