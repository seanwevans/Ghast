"""
test_base.py - Tests for the base rule classes and mixin helpers

These helper methods live on the base ``Rule`` mixin classes and are not always
exercised directly by the concrete rules, so they are tested here against small
purpose-built rule subclasses.
"""

import pytest

from ghast.rules.base import (
    JobRule,
    StepRule,
    TokenRule,
    WorkflowRule,
    _is_false,
    _is_true,
)


class _HelperRule(WorkflowRule, JobRule, TokenRule):
    """Concrete rule combining the workflow/job/trigger/token mixins."""

    def __init__(self):
        super().__init__(
            rule_id="helper",
            severity="HIGH",
            description="Helper rule for testing base mixins",
            remediation="No remediation",
        )

    def check(self, workflow, file_path):
        # Exercise the abstract base implementation via super().
        return super().check(workflow, file_path)


def test_is_false_and_is_true():
    assert _is_false(False) is True
    assert _is_false("false") is True
    assert _is_false("FALSE") is True
    assert _is_false(True) is False
    assert _is_false("yes") is False

    assert _is_true(True) is True
    assert _is_true("true") is True
    assert _is_true(False) is False
    assert _is_true("no") is False


def test_abstract_check_returns_none():
    rule = _HelperRule()
    # The base abstract implementation is a no-op returning None.
    assert rule.check({}, "wf.yml") is None


def test_default_fix_returns_false():
    rule = _HelperRule()
    finding = rule.create_finding(message="m", file_path="wf.yml")
    assert rule.fix({}, finding) is False


def test_create_finding_overrides():
    rule = _HelperRule()
    finding = rule.create_finding(
        message="msg",
        file_path="wf.yml",
        line_number=3,
        column=4,
        remediation="fix it",
        context={"k": "v"},
        can_fix=True,
        severity="LOW",
    )
    assert finding.rule_id == "helper"
    assert finding.severity == "LOW"
    assert finding.line_number == 3
    assert finding.column == 4
    assert finding.remediation == "fix it"
    assert finding.context == {"k": "v"}
    assert finding.can_fix is True


def test_check_job_timeout_triggers():
    rule = _HelperRule()
    job = {"steps": [{"run": "echo"} for _ in range(5)]}
    findings = rule.check_job_timeout("build", job, "wf.yml", min_steps=5)
    assert len(findings) == 1
    assert "no timeout-minutes" in findings[0].message


def test_check_job_timeout_ok_when_few_steps():
    rule = _HelperRule()
    job = {"steps": [{"run": "echo"}]}
    assert rule.check_job_timeout("build", job, "wf.yml", min_steps=5) == []


def test_check_job_timeout_ok_when_set():
    rule = _HelperRule()
    job = {"timeout-minutes": 10, "steps": [{"run": "echo"} for _ in range(6)]}
    assert rule.check_job_timeout("build", job, "wf.yml") == []


def test_check_hardcoded_tokens_detects():
    rule = _HelperRule()
    workflow = {"env": {"X": "token: 'abcdefghij1234567890'"}}
    findings = rule.check_hardcoded_tokens(workflow, "wf.yml")
    assert any("hardcoded token" in f.message.lower() for f in findings)


def test_check_hardcoded_tokens_skips_secrets_context():
    rule = _HelperRule()
    # The token-like value is preceded by 'secrets.' so it must be skipped.
    workflow = {"env": {"X": "secrets.GITHUB token: 'abcdefghij1234567890'"}}
    findings = rule.check_hardcoded_tokens(workflow, "wf.yml")
    assert findings == []


def test_check_hardcoded_tokens_tojson_secrets():
    rule = _HelperRule()
    workflow = {"env": {"X": "${{ toJson(secrets) }}"}}
    findings = rule.check_hardcoded_tokens(workflow, "wf.yml")
    assert any(f.severity == "CRITICAL" for f in findings)


def test_step_rule_is_importable():
    # StepRule mixin is covered elsewhere; ensure it remains importable.
    assert issubclass(StepRule, object)
