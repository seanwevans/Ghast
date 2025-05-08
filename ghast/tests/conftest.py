"""
conftest.py - Pytest fixtures for ghast tests
"""

import os
import tempfile
from pathlib import Path
import shutil
import pytest
import yaml


@pytest.fixture
def temp_dir():
    """Create a temporary directory that is removed after the test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def sample_workflow_content():
    """Sample GitHub Actions workflow content."""
    return """
name: Sample Workflow

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e .
      - name: Run tests
        run: pytest
"""


@pytest.fixture
def insecure_workflow_content():
    """Sample workflow with security issues."""
    return """
name: Insecure Workflow

on:
  pull_request_target:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - name: Set up Python
        uses: actions/setup-python@v1
      - name: Run command
        run: |
          echo "Running with input ${{ github.event.pull_request.title }}"
          eval "${{ github.event.comment.body }}"
      - name: Set environment variable
        run: echo "MY_VAR=${{ github.event.pull_request.body }}" >> $GITHUB_ENV
"""


@pytest.fixture
def patchable_workflow_content():
    """Sample workflow that can be auto-fixed."""
    return """
on:
  push:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v1
      - name: Multiple steps without timeout
        run: |
          echo "Step 1"
          echo "Step 2"
          echo "Step 3"
          echo "Step 4"
          echo "Step 5"
          echo "Step 6"
      - name: Another step
        run: |
          echo "This is a multiline script"
          echo "Without shell specified"
"""


@pytest.fixture
def sample_workflow_file(temp_dir, sample_workflow_content):
    """Create a sample workflow file in a temporary directory."""
    workflows_dir = Path(temp_dir) / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)

    workflow_file = workflows_dir / "sample.yml"
    workflow_file.write_text(sample_workflow_content)

    return str(workflow_file)


@pytest.fixture
def insecure_workflow_file(temp_dir, insecure_workflow_content):
    """Create an insecure workflow file in a temporary directory."""
    workflows_dir = Path(temp_dir) / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)

    workflow_file = workflows_dir / "insecure.yml"
    workflow_file.write_text(insecure_workflow_content)

    return str(workflow_file)


@pytest.fixture
def patchable_workflow_file(temp_dir, patchable_workflow_content):
    """Create a workflow file that can be patched in a temporary directory."""
    workflows_dir = Path(temp_dir) / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)

    workflow_file = workflows_dir / "patchable.yml"
    workflow_file.write_text(patchable_workflow_content)

    return str(workflow_file)


@pytest.fixture
def mock_repo(temp_dir, sample_workflow_file, insecure_workflow_file, patchable_workflow_file):
    """Create a mock repository with workflow files."""

    readme_file = Path(temp_dir) / "README.md"
    readme_file.write_text("# Mock Repository\n\nThis is a mock repository for testing ghast.")

    git_dir = Path(temp_dir) / ".git"
    git_dir.mkdir(exist_ok=True)

    config_file = Path(temp_dir) / "ghast.yml"
    config = {
        "check_timeout": True,
        "check_shell": True,
        "check_deprecated": True,
        "severity_thresholds": {"check_timeout": "LOW", "check_tokens": "HIGH"},
        "auto_fix": {"enabled": True, "rules": {"check_timeout": True, "check_shell": True}},
    }

    with open(config_file, "w") as f:
        yaml.dump(config, f)

    return temp_dir


@pytest.fixture
def mock_findings():
    """Create mock findings for testing reporting functions."""
    from ghast.core import Finding

    findings = [
        Finding(
            rule_id="check_timeout",
            severity="LOW",
            message="Job 'build' has 6 steps but no timeout-minutes set",
            file_path="/path/to/workflow.yml",
            line_number=10,
            remediation="Add 'timeout-minutes: 15' to job 'build'",
            can_fix=True,
        ),
        Finding(
            rule_id="check_shell",
            severity="LOW",
            message="Multiline script in job 'build' step 2 has no shell specified",
            file_path="/path/to/workflow.yml",
            line_number=20,
            remediation="Add 'shell: bash' to this step",
            can_fix=True,
        ),
        Finding(
            rule_id="check_deprecated",
            severity="MEDIUM",
            message="Deprecated action 'actions/checkout@v1' in job 'build' step 1",
            file_path="/path/to/workflow.yml",
            line_number=15,
            remediation="Use actions/checkout@v3 or later",
            can_fix=True,
        ),
        Finding(
            rule_id="poisoned_pipeline_execution",
            severity="CRITICAL",
            message="Poisoned Pipeline Execution vulnerability: job 'build' uses pull_request_target trigger with checkout of untrusted code",
            file_path="/path/to/workflow.yml",
            line_number=5,
            remediation="Use pull_request trigger instead, or if pull_request_target is required, do not check out untrusted code",
            can_fix=False,
            context={
                "triggers": ["pull_request_target"],
                "ref": "${{ github.event.pull_request.head.ref }}",
            },
        ),
        Finding(
            rule_id="command_injection",
            severity="HIGH",
            message="Untrusted event data in shell command in job 'build' step 3",
            file_path="/path/to/workflow.yml",
            line_number=25,
            remediation="Never use untrusted input directly in shell commands. Use input validation or environment variables with proper quoting.",
            can_fix=False,
        ),
    ]

    return findings


@pytest.fixture
def mock_stats():
    """Create mock statistics for testing reporting functions."""
    return {
        "start_time": "2025-05-01T12:00:00",
        "end_time": "2025-05-01T12:00:05",
        "repo_path": "/path/to/repo",
        "total_files": 3,
        "total_findings": 5,
        "severity_counts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 2},
        "rule_counts": {
            "check_timeout": 1,
            "check_shell": 1,
            "check_deprecated": 1,
            "poisoned_pipeline_execution": 1,
            "command_injection": 1,
        },
        "fixable_findings": 3,
    }
