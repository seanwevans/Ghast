"""
test_fixer.py - Tests for the auto-remediation module
"""

import os
import pytest
import yaml
import shutil
from pathlib import Path

from ghast.core import Finding
from ghast.core.fixer import Fixer, fix_workflow_file, fix_repository


def test_fixer_initialization():
    """Test fixer initialization with various configurations."""

    fixer = Fixer({})
    assert fixer.interactive is False
    assert fixer.fixes_applied == 0
    assert fixer.fixes_skipped == 0
    assert hasattr(fixer, "fixers")

    config = {"auto_fix": {"rules": {"check_timeout": False, "check_shell": True}}}
    fixer = Fixer(config, interactive=True)
    assert fixer.interactive is True
    assert fixer.config == config


def test_fix_timeout(patchable_workflow_file):
    """Test fixing missing timeout-minutes."""
    with open(patchable_workflow_file, "r") as f:
        workflow = yaml.safe_load(f)

    finding = Finding(
        rule_id="check_timeout",
        severity="LOW",
        message="Job 'build' has 6 steps but no timeout-minutes set",
        file_path=patchable_workflow_file,
        remediation="Add 'timeout-minutes: 15' to job 'build'",
        can_fix=True,
    )

    fixer = Fixer({})
    fixed = fixer.fix_timeout(workflow, finding)

    assert fixed is True
    assert workflow["jobs"]["build"]["timeout-minutes"] == 15


def test_fix_shell(patchable_workflow_file):
    """Test fixing missing shell specification."""
    with open(patchable_workflow_file, "r") as f:
        workflow = yaml.safe_load(f)

    finding = Finding(
        rule_id="check_shell",
        severity="LOW",
        message="Multiline script in job 'build' step 2 has no shell specified",
        file_path=patchable_workflow_file,
        remediation="Add 'shell: bash' to this step",
        can_fix=True,
    )

    fixer = Fixer({})
    fixed = fixer.fix_shell(workflow, finding)

    assert fixed is True
    assert workflow["jobs"]["build"]["steps"][1]["shell"] == "bash"


def test_fix_shell_does_not_modify_other_steps(patchable_workflow_file):
    """Ensure only the targeted step receives a shell value."""
    with open(patchable_workflow_file, "r") as f:
        workflow = yaml.safe_load(f)

    steps = workflow["jobs"]["build"]["steps"]
    assert "shell" not in steps[2]

    finding = Finding(
        rule_id="check_shell",
        severity="LOW",
        message="Multiline script in job 'build' step 2 has no shell specified",
        file_path=patchable_workflow_file,
        remediation="Add 'shell: bash' to this step",
        can_fix=True,
    )

    fixer = Fixer({})
    fixed = fixer.fix_shell(workflow, finding)

    assert fixed is True
    assert steps[1]["shell"] == "bash"
    assert "shell" not in steps[2]


def test_fix_deprecated_actions(patchable_workflow_file):
    """Test fixing deprecated actions."""
    with open(patchable_workflow_file, "r") as f:
        workflow = yaml.safe_load(f)

    finding = Finding(
        rule_id="check_deprecated",
        severity="MEDIUM",
        message="Deprecated action 'actions/checkout@v1' in job 'build' step 0",
        file_path=patchable_workflow_file,
        remediation="Use actions/checkout@v3 or later",
        can_fix=True,
        context={"deprecated": "actions/checkout@v1", "replacement": "actions/checkout@v3"},
    )

    config = {"default_action_versions": {"actions/checkout@v1": "actions/checkout@v3"}}

    fixer = Fixer(config)
    fixed = fixer.fix_deprecated_actions(workflow, finding)

    assert fixed is True
    assert workflow["jobs"]["build"]["steps"][0]["uses"] == "actions/checkout@v3"


def test_fix_workflow_name(patchable_workflow_file):
    """Test fixing missing workflow name."""
    with open(patchable_workflow_file, "r") as f:
        workflow = yaml.safe_load(f)

    if "name" in workflow:
        del workflow["name"]

    finding = Finding(
        rule_id="check_workflow_name",
        severity="LOW",
        message="Missing workflow name (top-level 'name' field)",
        file_path=patchable_workflow_file,
        remediation="Add a 'name:' field at the top level of the workflow",
        can_fix=True,
    )

    fixer = Fixer({})
    fixed = fixer.fix_workflow_name(workflow, finding)

    assert fixed is True
    assert "name" in workflow
    assert isinstance(workflow["name"], str)

    assert "patchable" in workflow["name"].lower()

    assert list(workflow.keys())[0] == "name"


def test_fix_workflow_file(patchable_workflow_file, temp_dir):
    """Test fixing an entire workflow file."""

    test_file = os.path.join(temp_dir, "test_workflow.yml")
    shutil.copy2(patchable_workflow_file, test_file)

    findings = [
        Finding(
            rule_id="check_timeout",
            severity="LOW",
            message="Job 'build' has 6 steps but no timeout-minutes set",
            file_path=test_file,
            remediation="Add 'timeout-minutes: 15' to job 'build'",
            can_fix=True,
        ),
        Finding(
            rule_id="check_workflow_name",
            severity="LOW",
            message="Missing workflow name (top-level 'name' field)",
            file_path=test_file,
            remediation="Add a 'name:' field at the top level of the workflow",
            can_fix=True,
        ),
        Finding(
            rule_id="check_shell",
            severity="LOW",
            message="Multiline script in job 'build' step 2 has no shell specified",
            file_path=test_file,
            remediation="Add 'shell: bash' to this step",
            can_fix=True,
        ),
        Finding(
            rule_id="check_deprecated",
            severity="MEDIUM",
            message="Deprecated action 'actions/checkout@v1' in job 'build' step 0",
            file_path=test_file,
            remediation="Use actions/checkout@v3 or later",
            can_fix=True,
        ),
    ]

    config = {
        "auto_fix": {
            "enabled": True,
            "rules": {
                "check_timeout": True,
                "check_workflow_name": True,
                "check_shell": True,
                "check_deprecated": True,
            },
        },
        "default_action_versions": {"actions/checkout@v1": "actions/checkout@v3"},
    }

    fixes_applied, fixes_skipped = fix_workflow_file(test_file, findings, config)

    assert fixes_applied == 4
    assert fixes_skipped == 0

    with open(test_file, "r") as f:
        fixed_workflow = yaml.safe_load(f)

    assert "name" in fixed_workflow
    assert fixed_workflow["jobs"]["build"]["timeout-minutes"] == 15
    assert "shell" in fixed_workflow["jobs"]["build"]["steps"][2]
    assert fixed_workflow["jobs"]["build"]["steps"][0]["uses"] == "actions/checkout@v3"


def test_fix_workflow_file_disabled_rules(patchable_workflow_file, temp_dir):
    """Test fixing with disabled rules."""

    test_file = os.path.join(temp_dir, "disabled_test.yml")
    shutil.copy2(patchable_workflow_file, test_file)

    findings = [
        Finding(
            rule_id="check_timeout",
            severity="LOW",
            message="Job 'build' has 6 steps but no timeout-minutes set",
            file_path=test_file,
            remediation="Add 'timeout-minutes: 15' to job 'build'",
            can_fix=True,
        ),
        Finding(
            rule_id="check_workflow_name",
            severity="LOW",
            message="Missing workflow name (top-level 'name' field)",
            file_path=test_file,
            remediation="Add a 'name:' field at the top level of the workflow",
            can_fix=True,
        ),
    ]

    config = {
        "auto_fix": {
            "enabled": True,
            "rules": {"check_timeout": False, "check_workflow_name": True},  # Disabled
        }
    }

    fixes_applied, fixes_skipped = fix_workflow_file(test_file, findings, config)

    assert fixes_applied == 1
    assert fixes_skipped == 1

    with open(test_file, "r") as f:
        fixed_workflow = yaml.safe_load(f)

    assert "name" in fixed_workflow
    assert "timeout-minutes" not in fixed_workflow["jobs"]["build"]


def test_fix_workflow_file_auto_fix_disabled(patchable_workflow_file, temp_dir, capsys):
    """Ensure no fixes are applied when global auto-fix is disabled."""

    test_file = os.path.join(temp_dir, "auto_fix_disabled.yml")
    shutil.copy2(patchable_workflow_file, test_file)

    findings = [
        Finding(
            rule_id="check_timeout",
            severity="LOW",
            message="Job 'build' has 6 steps but no timeout-minutes set",
            file_path=test_file,
            remediation="Add 'timeout-minutes: 15' to job 'build'",
            can_fix=True,
        ),
        Finding(
            rule_id="check_workflow_name",
            severity="LOW",
            message="Missing workflow name (top-level 'name' field)",
            file_path=test_file,
            remediation="Add a 'name:' field at the top level of the workflow",
            can_fix=True,
        ),
    ]

    config = {"auto_fix": {"enabled": False}}

    fixes_applied, fixes_skipped = fix_workflow_file(test_file, findings, config)

    assert fixes_applied == 0
    assert fixes_skipped == len(findings)

    captured = capsys.readouterr()
    assert "Auto-fix disabled" in captured.out
    assert not os.path.exists(f"{test_file}.bak")

    with open(test_file, "r") as fixed, open(patchable_workflow_file, "r") as original:
        assert fixed.read() == original.read()


def test_fix_repository(mock_repo):
    """Test fixing an entire repository."""

    workflows_dir = Path(mock_repo) / ".github" / "workflows"
    workflow_files = list(workflows_dir.glob("*.yml"))

    findings_by_file = {}

    for file_path in workflow_files:

        findings_by_file[str(file_path)] = [
            Finding(
                rule_id="check_workflow_name",
                severity="LOW",
                message="Missing workflow name (top-level 'name' field)",
                file_path=str(file_path),
                remediation="Add a 'name:' field at the top level of the workflow",
                can_fix=True,
            )
        ]

    config = {"auto_fix": {"enabled": True, "rules": {"check_workflow_name": True}}}

    fixes_applied, fixes_skipped = fix_repository(mock_repo, findings_by_file, config)

    assert fixes_applied == len(workflow_files)

    for file_path in workflow_files:
        with open(file_path, "r") as f:
            fixed_workflow = yaml.safe_load(f)
        assert "name" in fixed_workflow


def test_fix_nonexistent_file(temp_dir):
    """Test handling of non-existent file."""
    nonexistent_file = os.path.join(temp_dir, "doesnt_exist.yml")

    findings = [
        Finding(
            rule_id="check_workflow_name",
            severity="LOW",
            message="Missing workflow name",
            file_path=nonexistent_file,
            can_fix=True,
        )
    ]

    fixes_applied, fixes_skipped = fix_workflow_file(nonexistent_file, findings, {})
    assert fixes_applied == 0
    assert fixes_skipped == 0


def test_clean_workflow():
    """Test cleaning workflow before saving."""
    workflow = {
        "name": "Test Workflow",
        "jobs": {
            "build": {
                "__line__": 10,
                "__column__": 2,
                "steps": [{"__line__": 12, "__column__": 4, "uses": "actions/checkout@v3"}],
            }
        },
        "__line__": 1,
        "__column__": 0,
    }

    fixer = Fixer({})
    fixer._clean_workflow(workflow)

    assert "__line__" not in workflow
    assert "__column__" not in workflow
    assert "__line__" not in workflow["jobs"]["build"]
    assert "__column__" not in workflow["jobs"]["build"]
    assert "__line__" not in workflow["jobs"]["build"]["steps"][0]
    assert "__column__" not in workflow["jobs"]["build"]["steps"][0]
