"""
test_engine.py - Tests for the rule engine
"""

import pytest
import yaml
from typing import List

from ghast.rules import RuleEngine, Rule, create_rule_engine
from ghast.core import Finding
from ghast.core.scanner import Severity


class MockRule(Rule):
    """Mock rule for testing the rule engine."""

    def __init__(self, rule_id, severity="MEDIUM", enabled=True, can_fix=False):
        super().__init__(
            rule_id=rule_id,
            severity=severity,
            description=f"Test rule {rule_id}",
            remediation=f"Fix test rule {rule_id}",
            category="test",
        )
        self.enabled = enabled
        self.can_fix = can_fix
        self.checked = False
        self.fixed = False
        self.test_findings = []

    def check(self, workflow, file_path):
        self.checked = True
        return self.test_findings

    def fix(self, workflow, finding):
        self.fixed = True
        return True


def test_rule_engine_initialization():
    """Test rule engine initialization."""

    engine = RuleEngine()
    assert engine.rules
    assert len(engine.rules) > 0

    config = {"check_timeout": False, "severity_thresholds": {"check_deprecated": "HIGH"}}
    engine = RuleEngine(config=config)

    for rule in engine.rules:
        if rule.rule_id == "timeout":
            assert not rule.enabled
        if rule.rule_id == "deprecated_actions":
            assert rule.severity == "HIGH"


def test_create_rule_engine():
    """Test the factory function for creating rule engines."""

    engine = create_rule_engine()
    assert isinstance(engine, RuleEngine)
    assert engine.rules

    config = {"check_timeout": False}
    engine = create_rule_engine(config=config)

    timeout_rule = None
    for rule in engine.rules:
        if rule.rule_id == "timeout":
            timeout_rule = rule
            break

    assert timeout_rule is not None
    assert not timeout_rule.enabled


def test_register_rule():
    """Test registering a custom rule."""
    engine = RuleEngine()
    original_rule_count = len(engine.rules)

    mock_rule = MockRule("custom_rule")
    engine.register_rule(mock_rule)

    assert len(engine.rules) == original_rule_count + 1
    assert engine.get_rule_by_id("custom_rule") == mock_rule


def test_get_rule_by_id():
    """Test getting a rule by ID."""
    engine = RuleEngine()

    rule = engine.get_rule_by_id("timeout")
    assert rule is not None
    assert rule.rule_id == "timeout"

    rule = engine.get_rule_by_id("nonexistent")
    assert rule is None


def test_list_rules():
    """Test listing all rules."""
    engine = RuleEngine()
    rules_list = engine.list_rules()

    assert isinstance(rules_list, list)
    assert len(rules_list) > 0

    for rule_info in rules_list:
        assert "id" in rule_info
        assert "enabled" in rule_info
        assert "severity" in rule_info
        assert "description" in rule_info
        assert "category" in rule_info
        assert "can_fix" in rule_info


def test_enable_disable_rule():
    """Test enabling and disabling rules."""
    engine = RuleEngine()

    result = engine.disable_rule("timeout")
    assert result is True
    assert not engine.get_rule_by_id("timeout").enabled

    result = engine.enable_rule("timeout")
    assert result is True
    assert engine.get_rule_by_id("timeout").enabled

    result = engine.disable_rule("nonexistent")
    assert result is False


def test_scan_workflow(patchable_workflow_file):
    """Test scanning a workflow with all rules."""
    with open(patchable_workflow_file, "r") as f:
        workflow = yaml.safe_load(f)

    engine = RuleEngine()
    findings = engine.scan_workflow(workflow, patchable_workflow_file)

    assert len(findings) > 0
    assert all(isinstance(finding, Finding) for finding in findings)


def test_scan_workflow_with_severity_threshold(patchable_workflow_file):
    """Test scanning with severity threshold."""
    with open(patchable_workflow_file, "r") as f:
        workflow = yaml.safe_load(f)

    engine = RuleEngine()

    findings = engine.scan_workflow(workflow, patchable_workflow_file, severity_threshold="MEDIUM")

    assert all(finding.severity != "LOW" for finding in findings)


def test_scan_workflow_with_enum_severity_config(patchable_workflow_file):
    """Ensure enum severities in config are handled and filtering uses strings."""

    with open(patchable_workflow_file, "r") as f:
        workflow = yaml.safe_load(f)

    config = {"severity_thresholds": {"check_timeout": Severity.HIGH}}

    engine = RuleEngine(config=config)

    timeout_rule = engine.get_rule_by_id("timeout")
    assert timeout_rule is not None
    assert timeout_rule.severity == "HIGH"

    findings = engine.scan_workflow(
        workflow,
        patchable_workflow_file,
        severity_threshold="MEDIUM",
    )

    assert findings
    assert all(isinstance(finding.severity, str) for finding in findings)
    assert all(finding.severity != "LOW" for finding in findings)


def test_scan_workflow_with_rule_error():
    """Test handling of rule execution errors."""
    engine = RuleEngine()

    class ErrorRule(Rule):
        def __init__(self):
            super().__init__(
                rule_id="error_rule",
                severity="LOW",
                description="Rule that raises an error",
                remediation="Fix the error",
                category="test",
            )

        def check(self, workflow, file_path):
            raise ValueError("Test error")

    engine.register_rule(ErrorRule())

    findings = engine.scan_workflow({}, "test_file.yml")

    error_findings = [f for f in findings if f.rule_id.startswith("rule_error")]
    assert len(error_findings) > 0
    assert "error_rule" in error_findings[0].rule_id
    assert "Test error" in error_findings[0].message


def test_fix_findings():
    """Test fixing findings."""
    engine = RuleEngine()

    rule1 = MockRule("test_rule1", can_fix=True)
    rule2 = MockRule("test_rule2", can_fix=True)
    rule3 = MockRule("test_rule3", can_fix=False)

    engine.register_rule(rule1)
    engine.register_rule(rule2)
    engine.register_rule(rule3)

    findings = [
        Finding(
            rule_id="test_rule1",
            severity="LOW",
            message="Test finding 1",
            file_path="test.yml",
            can_fix=True,
        ),
        Finding(
            rule_id="test_rule2",
            severity="MEDIUM",
            message="Test finding 2",
            file_path="test.yml",
            can_fix=True,
        ),
        Finding(
            rule_id="test_rule3",
            severity="HIGH",
            message="Test finding 3",
            file_path="test.yml",
            can_fix=False,
        ),
    ]

    workflow = {"test": "workflow"}
    result = engine.fix_findings(workflow, findings)

    assert result["fixes_applied"] == 2
    assert result["fixes_skipped"] == 1

    assert rule1.fixed is True
    assert rule2.fixed is True
    assert rule3.fixed is False


def test_fix_findings_with_disabled_rules():
    """Test fixing findings with some rules disabled."""
    config = {
        "auto_fix": {
            "rules": {"test_rule1": False, "test_rule2": True}  # Disable fixing for this rule
        }
    }
    engine = RuleEngine(config=config)

    rule1 = MockRule("test_rule1", can_fix=True)
    rule2 = MockRule("test_rule2", can_fix=True)

    engine.register_rule(rule1)
    engine.register_rule(rule2)

    findings = [
        Finding(
            rule_id="test_rule1",
            severity="LOW",
            message="Test finding 1",
            file_path="test.yml",
            can_fix=True,
        ),
        Finding(
            rule_id="test_rule2",
            severity="MEDIUM",
            message="Test finding 2",
            file_path="test.yml",
            can_fix=True,
        ),
    ]

    workflow = {"test": "workflow"}
    result = engine.fix_findings(workflow, findings)

    assert result["fixes_applied"] == 1
    assert result["fixes_skipped"] == 1

    assert rule1.fixed is False
    assert rule2.fixed is True


def test_fix_findings_auto_fix_disabled(capsys):
    """Ensure global auto-fix toggle prevents rule engine fixes."""

    config = {"auto_fix": {"enabled": False}}
    engine = RuleEngine(config=config)

    rule1 = MockRule("test_rule1", can_fix=True)
    rule2 = MockRule("test_rule2", can_fix=True)

    engine.register_rule(rule1)
    engine.register_rule(rule2)

    findings = [
        Finding(
            rule_id="test_rule1",
            severity="LOW",
            message="Test finding 1",
            file_path="test.yml",
            can_fix=True,
        ),
        Finding(
            rule_id="test_rule2",
            severity="MEDIUM",
            message="Test finding 2",
            file_path="test.yml",
            can_fix=True,
        ),
        Finding(
            rule_id="test_rule3",
            severity="MEDIUM",
            message="Non-fixable finding",
            file_path="test.yml",
            can_fix=False,
        ),
    ]

    result = engine.fix_findings({}, findings)

    assert result["fixes_applied"] == 0
    assert result["fixes_skipped"] == len(findings)
    assert not rule1.fixed
    assert not rule2.fixed

    captured = capsys.readouterr()
    assert "Auto-fix disabled" in captured.out


def test_rule_inheritance():
    """Test rule inheritance and method overriding."""

    with pytest.raises(TypeError):
        Rule("abstract_rule", "LOW", "Abstract rule", "Fix it", "test")

    rule = MockRule("concrete_rule")
    assert rule.rule_id == "concrete_rule"
    assert rule.severity == "MEDIUM"
    assert "Test rule" in rule.description
    assert "Fix test rule" in rule.remediation
    assert rule.category == "test"

    findings = rule.check({}, "test.yml")
    assert rule.checked is True
    assert findings == []

    rule.test_findings = [
        Finding(
            rule_id="concrete_rule", severity="MEDIUM", message="Test finding", file_path="test.yml"
        )
    ]

    findings = rule.check({}, "test.yml")
    assert len(findings) == 1
    assert findings[0].rule_id == "concrete_rule"
