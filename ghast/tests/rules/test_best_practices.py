"""
test_best_practices.py - Tests for best practice rules
"""

import pytest
import yaml
import os
from pathlib import Path

from ghast.rules.best_practices import (
    TimeoutRule,
    ShellSpecificationRule,
    WorkflowNameRule,
    DeprecatedActionsRule,
    ContinueOnErrorRule,
    ReusableWorkflowRule,
)


def test_timeout_rule():
    """Test TimeoutRule for detecting missing timeouts."""
    rule = TimeoutRule()

    workflow_no_timeout = {
        "name": "No Timeout Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"run": "step 1"},
                    {"run": "step 2"},
                    {"run": "step 3"},
                    {"run": "step 4"},
                    {"run": "step 5"},
                    {"run": "step 6"},
                ],
            }
        },
    }

    findings = rule.check(workflow_no_timeout, "test.yml")
    assert len(findings) > 0
    assert any("timeout" in finding.message.lower() for finding in findings)
    assert all(finding.can_fix for finding in findings)

    workflow_with_timeout = {
        "name": "With Timeout Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "timeout-minutes": 10,
                "steps": [
                    {"run": "step 1"},
                    {"run": "step 2"},
                    {"run": "step 3"},
                    {"run": "step 4"},
                    {"run": "step 5"},
                    {"run": "step 6"},
                ],
            }
        },
    }

    findings = rule.check(workflow_with_timeout, "test.yml")
    assert not any("timeout" in finding.message.lower() for finding in findings)

    workflow = {
        "name": "Test Workflow",
        "jobs": {
            "build": {
                "steps": [
                    {"run": "step 1"},
                    {"run": "step 2"},
                    {"run": "step 3"},
                    {"run": "step 4"},
                    {"run": "step 5"},
                    {"run": "step 6"},
                ]
            }
        },
    }

    finding = rule.create_finding(
        message="Job 'build' has 6 steps but no timeout-minutes set",
        file_path="test.yml",
        can_fix=True,
    )

    fixed = rule.fix(workflow, finding)
    assert fixed is True
    assert workflow["jobs"]["build"]["timeout-minutes"] == 15


def test_shell_specification_rule():
    """Test ShellSpecificationRule for detecting missing shell specifications."""
    rule = ShellSpecificationRule()

    workflow_no_shell = {
        "name": "No Shell Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"run": "echo 'Single line'"},  # Single line doesn't need shell
                    {
                        "run": """
                        echo 'Line 1'
                        echo 'Line 2'
                        echo 'Line 3'
                        """  # Multiline needs shell
                    },
                ],
            }
        },
    }

    findings = rule.check(workflow_no_shell, "test.yml")
    assert len(findings) > 0
    assert any("shell" in finding.message.lower() for finding in findings)
    assert all(finding.can_fix for finding in findings)

    workflow_with_shell = {
        "name": "With Shell Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"run": "echo 'Single line'"},
                    {
                        "run": """
                        echo 'Line 1'
                        echo 'Line 2'
                        echo 'Line 3'
                        """,
                        "shell": "bash",
                    },
                ],
            }
        },
    }

    findings = rule.check(workflow_with_shell, "test.yml")
    assert not any("shell" in finding.message.lower() for finding in findings)

    workflow = {
        "name": "Test Workflow",
        "jobs": {
            "build": {
                "steps": [
                    {
                        "run": """
                        echo 'Line 1'
                        echo 'Line 2'
                        """
                    }
                ]
            }
        },
    }

    finding = rule.create_finding(
        message="Multiline script in job 'build' step 1 has no shell specified",
        file_path="test.yml",
        can_fix=True,
    )

    fixed = rule.fix(workflow, finding)
    assert fixed is True
    assert workflow["jobs"]["build"]["steps"][0]["shell"] == "bash"


def test_workflow_name_rule():
    """Test WorkflowNameRule for detecting missing workflow names."""
    rule = WorkflowNameRule()

    workflow_no_name = {
        "on": "push",
        "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo 'Hello'"}]}},
    }

    findings = rule.check(workflow_no_name, "test.yml")
    assert len(findings) > 0
    assert any("workflow name" in finding.message.lower() for finding in findings)
    assert all(finding.can_fix for finding in findings)

    workflow_with_name = {
        "name": "Test Workflow",
        "on": "push",
        "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo 'Hello'"}]}},
    }

    findings = rule.check(workflow_with_name, "test.yml")
    assert not any("workflow name" in finding.message.lower() for finding in findings)

    workflow = {"on": "push", "jobs": {"build": {"steps": [{"run": "echo 'Hello'"}]}}}

    finding = rule.create_finding(
        message="Missing workflow name (top-level 'name' field)",
        file_path="test_workflow.yml",
        can_fix=True,
    )

    fixed = rule.fix(workflow, finding)
    assert fixed is True
    assert "name" in workflow
    assert "Test Workflow" in workflow["name"]

    assert list(workflow.keys())[0] == "name"


def test_deprecated_actions_rule():
    """Test DeprecatedActionsRule for detecting deprecated actions."""
    rule = DeprecatedActionsRule()

    workflow_deprecated = {
        "name": "Deprecated Actions Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"uses": "actions/checkout@v1"},  # Deprecated
                    {"uses": "actions/setup-python@v1"},  # Deprecated
                ],
            }
        },
    }

    findings = rule.check(workflow_deprecated, "test.yml")
    assert len(findings) > 0
    assert any("deprecated action" in finding.message.lower() for finding in findings)
    assert any("actions/checkout@v1" in finding.message for finding in findings)
    assert any("actions/setup-python@v1" in finding.message for finding in findings)

    workflow_current = {
        "name": "Current Actions Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"uses": "actions/checkout@v3"},  # Current
                    {"uses": "actions/setup-python@v4"},  # Current
                ],
            }
        },
    }

    findings = rule.check(workflow_current, "test.yml")
    assert not any("deprecated action" in finding.message.lower() for finding in findings)

    workflow = {
        "name": "Test Workflow",
        "jobs": {"build": {"steps": [{"uses": "actions/checkout@v1"}]}},
    }

    finding = rule.create_finding(
        message="Deprecated action 'actions/checkout@v1' in job 'build' step 1",
        file_path="test.yml",
        can_fix=True,
        context={"deprecated": "actions/checkout@v1", "replacement": "actions/checkout@v3"},
    )

    fixed = rule.fix(workflow, finding)
    assert fixed is True
    assert workflow["jobs"]["build"]["steps"][0]["uses"] == "actions/checkout@v3"


def test_continue_on_error_rule():
    """Test ContinueOnErrorRule for detecting continue-on-error usage."""
    rule = ContinueOnErrorRule()

    workflow_with_continue = {
        "name": "Continue On Error Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "continue-on-error": True,
                "steps": [
                    {"run": "echo 'Step 1'"},
                    {"run": "echo 'Step 2'", "continue-on-error": True},
                ],
            }
        },
    }

    findings = rule.check(workflow_with_continue, "test.yml")
    assert len(findings) > 0
    assert any("continue-on-error: true" in finding.message.lower() for finding in findings)
    assert len(findings) == 2  # Should find both the job and step level issues

    workflow_without_continue = {
        "name": "No Continue On Error Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [{"run": "echo 'Step 1'"}, {"run": "echo 'Step 2'"}],
            }
        },
    }

    findings = rule.check(workflow_without_continue, "test.yml")
    assert not any("continue-on-error" in finding.message.lower() for finding in findings)


def test_reusable_workflow_rule():
    """Test ReusableWorkflowRule for detecting issues with reusable workflows."""
    rule = ReusableWorkflowRule()

    workflow_bad_reusable = {
        "name": "Bad Reusable Workflow",
        "on": "push",
        "jobs": {
            "call_workflow": {
                "uses": "owner/repo/.github/workflows/reusable.yml@main",
                "with": {"param1": "value1"},
            }
        },
    }

    findings = rule.check(workflow_bad_reusable, "test.yml")
    assert len(findings) > 0
    assert any("reusable workflow" in finding.message.lower() for finding in findings)
    assert any("without defining 'inputs'" in finding.message.lower() for finding in findings)

    workflow_good_reusable = {
        "name": "Good Reusable Workflow",
        "on": "push",
        "jobs": {
            "call_workflow": {
                "uses": "owner/repo/.github/workflows/reusable.yml@main",
                "with": {"param1": "value1"},
                "inputs": {"param1": {"required": True, "type": "string"}},
            }
        },
    }

    findings = rule.check(workflow_good_reusable, "test.yml")
    assert not any("reusable workflow" in finding.message.lower() for finding in findings)
