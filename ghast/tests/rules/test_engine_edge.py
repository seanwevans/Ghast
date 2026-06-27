"""
test_engine_edge.py - Edge-case coverage for the rule engine

Covers short-rule-id config resolution, enable/disable of unknown rules, and
the fix-application branches (unknown rule, interactive confirm/decline, fix
returning False, and exceptions raised during fix).
"""

import click
import pytest

from ghast.core import Finding
from ghast.rules import Rule, RuleEngine


class _FixRule(Rule):
    """A rule whose fix behaviour is configurable for testing."""

    def __init__(self, rule_id="fixme", behaviour="ok"):
        super().__init__(
            rule_id=rule_id,
            severity="LOW",
            description="d",
            remediation="r",
            category="test",
        )
        self.can_fix = True
        self.behaviour = behaviour

    def check(self, workflow, file_path):
        return []

    def fix(self, workflow, finding):
        if self.behaviour == "raise":
            raise RuntimeError("boom")
        if self.behaviour == "false":
            return False
        return True


def _finding(rule_id="fixme"):
    return Finding(
        rule_id=rule_id,
        severity="LOW",
        message="needs fixing",
        file_path="wf.yml",
        can_fix=True,
    )


def test_apply_config_exact_rule_id_disables():
    engine = RuleEngine(config={"timeout": False})
    assert engine.get_rule_by_id("timeout").enabled is False


def test_apply_config_short_with_check_disables():
    # short_with_check = "check_deprecated" for rule "deprecated_actions"
    engine = RuleEngine(config={"check_deprecated": False})
    assert engine.get_rule_by_id("deprecated_actions").enabled is False


def test_apply_config_exact_rule_id_severity():
    engine = RuleEngine(config={"severity_thresholds": {"timeout": "HIGH"}})
    assert engine.get_rule_by_id("timeout").severity == "HIGH"


def test_apply_config_short_rule_id_disables():
    # "deprecated_actions" -> short id "deprecated"
    engine = RuleEngine(config={"deprecated": False})
    rule = engine.get_rule_by_id("deprecated_actions")
    assert rule is not None
    assert rule.enabled is False


def test_apply_config_short_rule_id_severity():
    engine = RuleEngine(config={"severity_thresholds": {"deprecated": "CRITICAL"}})
    rule = engine.get_rule_by_id("deprecated_actions")
    assert rule.severity == "CRITICAL"


def test_enable_rule_unknown_returns_false():
    engine = RuleEngine()
    assert engine.enable_rule("does-not-exist") is False


def test_disable_rule_unknown_returns_false():
    engine = RuleEngine()
    assert engine.disable_rule("does-not-exist") is False


def test_fix_findings_skips_unknown_rule():
    engine = RuleEngine()
    result = engine.fix_findings({}, [_finding("unknown_rule_xyz")])
    assert result["fixes_applied"] == 0
    assert result["fixes_skipped"] == 1


def test_fix_findings_interactive_confirm(monkeypatch):
    engine = RuleEngine()
    engine.register_rule(_FixRule(behaviour="ok"))
    monkeypatch.setattr(click, "confirm", lambda *a, **k: True)
    result = engine.fix_findings({}, [_finding()], interactive=True)
    assert result["fixes_applied"] == 1


def test_fix_findings_interactive_decline(monkeypatch):
    engine = RuleEngine()
    engine.register_rule(_FixRule(behaviour="ok"))
    monkeypatch.setattr(click, "confirm", lambda *a, **k: False)
    result = engine.fix_findings({}, [_finding()], interactive=True)
    assert result["fixes_applied"] == 0
    assert result["fixes_skipped"] == 1


def test_fix_findings_fix_returns_false():
    engine = RuleEngine()
    engine.register_rule(_FixRule(behaviour="false"))
    result = engine.fix_findings({}, [_finding()])
    assert result["fixes_applied"] == 0
    assert result["fixes_skipped"] == 1


def test_fix_findings_fix_raises(capsys):
    engine = RuleEngine()
    engine.register_rule(_FixRule(behaviour="raise"))
    result = engine.fix_findings({}, [_finding()])
    assert result["fixes_applied"] == 0
    assert result["fixes_skipped"] == 1
    assert "Error fixing" in capsys.readouterr().out
