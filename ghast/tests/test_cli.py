"""
test_cli.py - Tests for the command-line interface
"""

import os
import pytest
import tempfile
import json
from unittest.mock import patch
from pathlib import Path
from click.testing import CliRunner

from ghast.cli import cli


@pytest.fixture
def cli_runner():
    """Create a Click CLI test runner."""
    return CliRunner()


def test_cli_version(cli_runner):
    """Test getting the version with --version."""
    from ghast.utils.version import __version__

    result = cli_runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_help(cli_runner):
    """Test getting help with --help."""
    result = cli_runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "ghast ☠ GitHub Actions Security Tool" in result.output
    assert "scan" in result.output
    assert "fix" in result.output
    assert "config" in result.output
    assert "rules" in result.output
    assert "analyze" in result.output
    assert "report" in result.output


def test_cli_scan_help(cli_runner):
    """Test getting help for scan command."""
    result = cli_runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Audit GitHub Actions workflows for security issues" in result.output


def test_cli_fix_help(cli_runner):
    """Test getting help for fix command."""
    result = cli_runner.invoke(cli, ["fix", "--help"])
    assert result.exit_code == 0
    assert "Audit and apply safe fixes to GitHub Actions workflows" in result.output


def test_cli_rules_help(cli_runner):
    """Test getting help for rules command."""
    result = cli_runner.invoke(cli, ["rules", "--help"])
    assert result.exit_code == 0
    assert "List all available rules and what they do" in result.output


def test_cli_config_help(cli_runner):
    """Test getting help for config command."""
    result = cli_runner.invoke(cli, ["config", "--help"])
    assert result.exit_code == 0
    assert "View or validate current config" in result.output


def test_cli_scan_nonexistent_repo(cli_runner):
    """Test scanning a non-existent repository."""
    with tempfile.TemporaryDirectory() as temp_dir:
        non_existent = os.path.join(temp_dir, "nonexistent")
        result = cli_runner.invoke(cli, ["scan", non_existent])
        assert result.exit_code == 1
        assert "No workflows found" in result.output


def test_cli_scan_empty_repo(cli_runner):
    """Test scanning a repository with no workflows."""
    with tempfile.TemporaryDirectory() as temp_dir:

        workflows_dir = os.path.join(temp_dir, ".github", "workflows")
        os.makedirs(workflows_dir)

        result = cli_runner.invoke(cli, ["scan", temp_dir])
        assert result.exit_code == 1
        assert "No workflows found" in result.output or "Found 0 workflow" in result.output


def test_cli_scan_repo(cli_runner, mock_repo):
    """Test scanning a repository with workflows."""
    result = cli_runner.invoke(cli, ["scan", mock_repo])
    assert result.exit_code == 1  # Should exit with 1 if issues are found
    assert "Scan Summary" in result.output
    assert "Total files scanned" in result.output
    assert "Total issues found" in result.output


def test_cli_scan_single_file(cli_runner, insecure_workflow_file):
    """Test scanning a single workflow file."""
    result = cli_runner.invoke(cli, ["scan", insecure_workflow_file])
    assert result.exit_code == 1  # Should exit with 1 if issues are found
    assert "Scanning single workflow file" in result.output
    assert "Total issues found" in result.output


def test_cli_scan_output_formats(cli_runner, mock_repo):
    """Test scanning with different output formats."""

    result = cli_runner.invoke(cli, ["scan", mock_repo, "--output", "text"])
    assert result.exit_code == 1
    assert "Scan Summary" in result.output

    result = cli_runner.invoke(cli, ["scan", mock_repo, "--output", "json"])
    assert result.exit_code == 1
    try:
        json_data = json.loads(result.output)
        assert "findings" in json_data
        assert "stats" in json_data
    except json.JSONDecodeError:
        pytest.fail("JSON output is not valid JSON")

    result = cli_runner.invoke(cli, ["scan", mock_repo, "--output", "sarif"])
    assert result.exit_code == 1
    try:
        sarif_data = json.loads(result.output)
        assert "$schema" in sarif_data
        assert "runs" in sarif_data
    except json.JSONDecodeError:
        pytest.fail("SARIF output is not valid JSON")


def test_cli_scan_output_file(cli_runner, mock_repo, temp_dir):
    """Test scanning with output to a file."""
    output_file = os.path.join(temp_dir, "output.txt")
    result = cli_runner.invoke(cli, ["scan", mock_repo, "--output-file", output_file])
    assert result.exit_code == 1
    assert "Results written to" in result.output
    assert os.path.exists(output_file)

    with open(output_file, "r") as f:
        content = f.read()
        assert "Scan Summary" in content


def test_cli_scan_severity_threshold(cli_runner, mock_repo):
    """Test scanning with different severity thresholds."""

    result_low = cli_runner.invoke(cli, ["scan", mock_repo, "--severity-threshold", "LOW"])

    result_medium = cli_runner.invoke(cli, ["scan", mock_repo, "--severity-threshold", "MEDIUM"])

    result_high = cli_runner.invoke(cli, ["scan", mock_repo, "--severity-threshold", "HIGH"])

    result_critical = cli_runner.invoke(
        cli, ["scan", mock_repo, "--severity-threshold", "CRITICAL"]
    )

    low_count = result_low.output.count("Total issues found")
    medium_count = result_medium.output.count("Total issues found")
    high_count = result_high.output.count("Total issues found")
    critical_count = result_critical.output.count("Total issues found")

    assert (
        len(result_low.output)
        >= len(result_medium.output)
        >= len(result_high.output)
        >= len(result_critical.output)
    )


def test_cli_fix(cli_runner, patchable_workflow_file, temp_dir):
    """Test fixing workflow issues."""

    test_file = os.path.join(temp_dir, "test_workflow.yml")
    with open(patchable_workflow_file, "r") as src, open(test_file, "w") as dst:
        dst.write(src.read())

    result = cli_runner.invoke(cli, ["fix", test_file])

    assert result.exit_code == 0
    assert "Fix Summary" in result.output
    assert "Issues fixed" in result.output

    backup_file = test_file + ".bak"
    assert os.path.exists(backup_file)


def test_cli_fix_dry_run(cli_runner, patchable_workflow_file):
    """Test fixing workflow issues in dry-run mode."""

    result = cli_runner.invoke(cli, ["fix", patchable_workflow_file, "--dry-run"])

    assert result.exit_code == 0
    assert "Running in dry-run mode" in result.output
    assert "Fix Summary" in result.output
    assert "Fixable issues" in result.output

    with open(patchable_workflow_file, "r") as f:
        content = f.read()
    assert "timeout-minutes" not in content  # Should not be fixed


def test_cli_fix_interactive_dry_run(cli_runner, patchable_workflow_file):
    """Test interactive flag with dry-run mode."""

    result = cli_runner.invoke(
        cli, ["fix", patchable_workflow_file, "--dry-run", "--interactive"]
    )

    assert result.exit_code == 0
    assert "Note: --interactive has no effect in dry-run mode." in result.output


def test_cli_fix_severity_threshold(cli_runner, patchable_workflow_file, temp_dir):
    """Test fixing with different severity thresholds."""

    test_file = os.path.join(temp_dir, "test_workflow.yml")
    with open(patchable_workflow_file, "r") as src, open(test_file, "w") as dst:
        dst.write(src.read())

    result = cli_runner.invoke(cli, ["fix", test_file, "--severity-threshold", "HIGH", "--dry-run"])

    assert result.exit_code == 0
    assert "Fix Summary" in result.output


def test_cli_config_generate(cli_runner, temp_dir):
    """Test generating a default config file."""
    config_file = os.path.join(temp_dir, "ghast.yml")
    result = cli_runner.invoke(cli, ["config", "--generate", "--output", config_file])

    assert result.exit_code == 0
    assert os.path.exists(config_file)

    with open(config_file, "r") as f:
        content = f.read()
    assert "check_timeout" in content
    assert "severity_thresholds" in content
    assert "auto_fix" in content


def test_cli_config_validate(cli_runner, mock_repo):
    """Test validating a config file."""

    config_file = os.path.join(mock_repo, "ghast.yml")

    result = cli_runner.invoke(cli, ["config", "--config", config_file])

    assert result.exit_code == 0
    assert "Config loaded and valid" in result.output


def test_cli_rules(cli_runner):
    """Test listing available rules."""

    result = cli_runner.invoke(cli, ["rules"])

    assert result.exit_code == 0
    assert "ghast supports the following rules" in result.output
    assert "enabled" in result.output
    assert "disabled" in result.output

    result = cli_runner.invoke(cli, ["rules", "--format", "json"])

    assert result.exit_code == 0
    try:
        rules_data = json.loads(result.output)
        assert isinstance(rules_data, list)
        assert len(rules_data) > 0
        assert "id" in rules_data[0]
        assert "enabled" in rules_data[0]
        assert "severity" in rules_data[0]
    except json.JSONDecodeError:
        pytest.fail("Rules JSON output is not valid JSON")


def test_cli_analyze(cli_runner, sample_workflow_file):
    """Test analyzing a single workflow file."""
    result = cli_runner.invoke(cli, ["analyze", sample_workflow_file])

    assert result.exit_code == 0
    assert "Analysis of" in result.output


def test_cli_report(cli_runner, mock_repo, temp_dir):
    """Test generating a comprehensive report."""
    output_file = os.path.join(temp_dir, "report.html")
    result = cli_runner.invoke(cli, ["report", mock_repo, "--output", output_file])

    assert result.exit_code == 0
    assert "Report generated at" in result.output
    assert os.path.exists(output_file)

    with open(output_file, "r") as f:
        content = f.read()
    assert "<!DOCTYPE html>" in content
    assert "GitHub Actions Security Report" in content


def test_cli_with_nonexistent_config(cli_runner, mock_repo):
    """Test scanning with a non-existent config file."""
    result = cli_runner.invoke(cli, ["scan", mock_repo, "--config", "nonexistent.yml"])

    assert result.exit_code == 1
    assert "Error loading config file" in result.output
