"""
test_security_rules.py - Tests for security-focused rules
"""

import pytest
import yaml
import tempfile
from pathlib import Path

from ghast.rules.security import (
    PermissionsRule,
    PoisonedPipelineExecutionRule,
    CommandInjectionRule,
    EnvironmentInjectionRule,
    TokenSecurityRule,
    ActionPinningRule,
)


def test_permissions_rule():
    """Test PermissionsRule for detecting missing permissions."""
    rule = PermissionsRule()

    workflow_no_permissions = {
        "name": "Test Workflow",
        "on": "push",
        "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo 'Hello'"}]}},
    }

    findings = rule.check(workflow_no_permissions, "test.yml")
    assert len(findings) > 0
    assert any("missing explicit permissions" in finding.message.lower() for finding in findings)

    workflow_with_permissions = {
        "name": "Test Workflow",
        "on": "push",
        "permissions": "read-all",
        "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo 'Hello'"}]}},
    }

    findings = rule.check(workflow_with_permissions, "test.yml")
    assert not any(
        "missing explicit permissions at workflow level" in finding.message.lower()
        for finding in findings
    )

    workflow_write_all = {
        "name": "Test Workflow",
        "on": "push",
        "permissions": "write-all",
        "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo 'Hello'"}]}},
    }

    findings = rule.check(workflow_write_all, "test.yml")
    assert any("overly permissive" in finding.message.lower() for finding in findings)

    workflow = {
        "name": "Test Workflow",
        "on": "push",
        "jobs": {"build": {"runs-on": "ubuntu-latest"}},
    }

    finding = rule.create_finding(
        message="Missing explicit permissions at workflow level", file_path="test.yml", can_fix=True
    )

    fixed = rule.fix(workflow, finding)
    assert fixed is True
    assert workflow["permissions"] == "read-all"


def test_poisoned_pipeline_execution_rule():
    """Test PoisonedPipelineExecutionRule for detecting PPE vulnerabilities."""
    rule = PoisonedPipelineExecutionRule()

    workflow_vulnerable = {
        "name": "Vulnerable Workflow",
        "on": "pull_request_target",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "uses": "actions/checkout@v3",
                        "with": {"ref": "${{ github.event.pull_request.head.ref }}"},
                    },
                    {"run": "echo 'Dangerous!'"},
                ],
            }
        },
    }

    findings = rule.check(workflow_vulnerable, "test.yml")
    assert len(findings) > 0
    assert any("poisoned pipeline execution" in finding.message.lower() for finding in findings)
    assert any(finding.severity == "CRITICAL" for finding in findings)

    workflow_safer = {
        "name": "Safer Workflow",
        "on": "pull_request_target",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [{"uses": "actions/checkout@v3"}, {"run": "echo 'Safer'"}],
            }
        },
    }

    findings = rule.check(workflow_safer, "test.yml")
    assert not any("poisoned pipeline execution" in finding.message.lower() for finding in findings)

    workflow_safe = {
        "name": "Safe Workflow",
        "on": "pull_request",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "uses": "actions/checkout@v3",
                        "with": {"ref": "${{ github.event.pull_request.head.ref }}"},
                    },
                    {"run": "echo 'Safe'"},
                ],
            }
        },
    }

    findings = rule.check(workflow_safe, "test.yml")
    assert not any("poisoned pipeline execution" in finding.message.lower() for finding in findings)


def test_command_injection_rule():
    """Test CommandInjectionRule for detecting command injection vulnerabilities."""
    rule = CommandInjectionRule()

    workflow_vulnerable = {
        "name": "Vulnerable Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"run": "echo ${{ github.event.issue.title }}"},
                    {"run": 'eval "${{ github.event.comment.body }}"'},
                    {"run": 'grep "${{ github.event.pull_request.title }}" file.txt'},
                ],
            }
        },
    }

    findings = rule.check(workflow_vulnerable, "test.yml")
    assert len(findings) > 0
    assert any("untrusted" in finding.message.lower() for finding in findings)
    assert any(finding.severity == "HIGH" for finding in findings)

    workflow_safe = {
        "name": "Safe Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"run": "echo 'Static string'"},
                    {"run": "echo ${{ github.sha }}"},  # Safe context
                    {"run": "echo ${{ github.repository }}"},  # Safe context
                ],
            }
        },
    }

    findings = rule.check(workflow_safe, "test.yml")
    assert not any("untrusted" in finding.message.lower() for finding in findings)


def test_environment_injection_rule():
    """Test EnvironmentInjectionRule for detecting environment variable injection."""
    rule = EnvironmentInjectionRule()

    workflow_vulnerable = {
        "name": "Vulnerable Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"uses": "actions/checkout@v3"},
                    {"run": "echo 'SOME_VAR=value' >> $GITHUB_ENV"},
                    {"run": "echo 'SOME_PATH=value' >> $GITHUB_PATH"},
                ],
            }
        },
    }

    findings = rule.check(workflow_vulnerable, "test.yml")
    assert len(findings) > 0
    assert any("github_env" in finding.message.lower() for finding in findings)
    assert any("github_path" in finding.message.lower() for finding in findings)

    workflow_safer = {
        "name": "Safer Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"run": "echo 'SOME_VAR=value' >> $GITHUB_ENV"},
                    {"run": "echo 'SOME_PATH=value' >> $GITHUB_PATH"},
                    {"uses": "actions/checkout@v3"},
                ],
            }
        },
    }

    findings = rule.check(workflow_safer, "test.yml")
    assert not any("github_env" in finding.message.lower() for finding in findings)
    assert not any("github_path" in finding.message.lower() for finding in findings)


def test_token_security_rule():
    """Test TokenSecurityRule for detecting hardcoded tokens and token leakage."""
    rule = TokenSecurityRule()

    workflow_vulnerable = {
        "name": "Vulnerable Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "run": "curl -H 'Authorization: token ghp_1234567890abcdefghijklmnopqrstuvwxyz' https://api.github.com"
                    },
                    {"run": "API_KEY='ak_12345678901234567890' python script.py"},
                    {"run": "echo '${{ toJson(secrets) }}' > all_secrets.json"},  # Very dangerous
                ],
            }
        },
    }

    findings = rule.check(workflow_vulnerable, "test.yml")
    assert len(findings) > 0
    assert any("hardcoded token" in finding.message.lower() for finding in findings)
    assert any("tojson(secrets)" in finding.message.lower() for finding in findings)
    assert any(finding.severity == "CRITICAL" for finding in findings)

    workflow_safe = {
        "name": "Safe Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "run": "curl -H 'Authorization: token ${{ secrets.GITHUB_TOKEN }}' https://api.github.com"
                    },
                    {"run": "API_KEY='${{ secrets.API_KEY }}' python script.py"},
                ],
            }
        },
    }

    findings = rule.check(workflow_safe, "test.yml")
    assert not any("hardcoded token" in finding.message.lower() for finding in findings)
    assert not any("tojson(secrets)" in finding.message.lower() for finding in findings)

    workflow = {
        "name": "Test Workflow",
        "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"uses": "actions/checkout@v3"}]}},
    }

    finding = rule.create_finding(
        message="actions/checkout in job 'build' step 1 does not disable credential persistence",
        file_path="test.yml",
        can_fix=True,
    )

    fixed = rule.fix(workflow, finding)
    assert fixed is True
    assert workflow["jobs"]["build"]["steps"][0]["with"]["persist-credentials"] is False


def test_action_pinning_rule():
    """Test ActionPinningRule for detecting unpinned actions."""
    rule = ActionPinningRule()

    workflow_unpinned = {
        "name": "Unpinned Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"uses": "actions/checkout@v3"},  # Not pinned to SHA
                    {"uses": "actions/setup-node@v3"},  # Not pinned to SHA
                    {"uses": "some-action@main"},  # Unstable reference
                ],
            }
        },
    }

    findings = rule.check(workflow_unpinned, "test.yml")
    assert len(findings) > 0
    assert any(
        "not pinned to a specific commit sha" in finding.message.lower() for finding in findings
    )
    assert any("unstable reference" in finding.message.lower() for finding in findings)

    workflow_pinned = {
        "name": "Pinned Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "uses": "actions/checkout@a12a3456b789c123d456e789f0123456a78901bc"  # Pinned to SHA
                    },
                    {
                        "uses": "actions/setup-node@a98765bcdef1234567890abcdef123456789012"  # Pinned to SHA
                    },
                ],
            }
        },
    }

    findings = rule.check(workflow_pinned, "test.yml")
    assert not any(
        "not pinned to a specific commit sha" in finding.message.lower() for finding in findings
    )
    assert not any("unstable reference" in finding.message.lower() for finding in findings)
