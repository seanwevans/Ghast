"""
test_cli_edge.py - Edge-case coverage for the command-line interface

Covers the no-subcommand banner, --no-color, --disable, invalid-config error
paths, repository-mode fix, the various fix/dry-run summary branches, config
generation to stdout, and analyze success/failure paths.
"""

import os

import click
import pytest
from click.testing import CliRunner

from ghast.cli import _prepare_scan, cli


@pytest.fixture
def cli_runner():
    return CliRunner()


def _write_workflow(directory, name, content):
    workflows_dir = os.path.join(directory, ".github", "workflows")
    os.makedirs(workflows_dir, exist_ok=True)
    path = os.path.join(workflows_dir, name)
    with open(path, "w") as f:
        f.write(content)
    return path


SECURE_WORKFLOW = """name: Secure
on: push
permissions: read-all
jobs:
  build:
    permissions: read-all
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""


def test_cli_no_subcommand_shows_banner(cli_runner):
    result = cli_runner.invoke(cli, [])
    assert result.exit_code == 0
    assert "Use `ghast --help`" in result.output


def test_scan_no_color(cli_runner, insecure_workflow_file):
    result = cli_runner.invoke(cli, ["scan", insecure_workflow_file, "--no-color"])
    assert "Scanning single workflow file" in result.output


def test_scan_with_disable(cli_runner, mock_repo):
    result = cli_runner.invoke(cli, ["scan", mock_repo, "--disable", "timeout"])
    assert "Scan Summary" in result.output


def test_scan_invalid_config_file(cli_runner, mock_repo, tmp_path):
    bad_config = tmp_path / "bad.yml"
    bad_config.write_text("unknown_option: true\n")
    result = cli_runner.invoke(cli, ["scan", mock_repo, "--config", str(bad_config)])
    assert result.exit_code == 1
    assert "Error loading config file" in result.output


def test_prepare_scan_none_config_with_disable(monkeypatch, mock_repo, tmp_path):
    # Force load_config to return None so the disable branch initialises it.
    import ghast.cli as cli_module

    cfg = tmp_path / "cfg.yml"
    cfg.write_text("check_timeout: true\n")
    monkeypatch.setattr(cli_module, "load_config", lambda path: None)

    findings, stats, config_data = _prepare_scan(
        mock_repo,
        strict=False,
        config=str(cfg),
        severity_threshold="LOW",
        disable=("timeout",),
    )
    assert config_data == {"check_timeout": False}


def test_fix_invalid_config_file(cli_runner, mock_repo, tmp_path):
    bad_config = tmp_path / "bad.yml"
    bad_config.write_text("unknown_option: true\n")
    result = cli_runner.invoke(cli, ["fix", mock_repo, "--config", str(bad_config)])
    assert result.exit_code == 1
    assert "Error loading config file" in result.output


def test_fix_repository_mode(cli_runner, mock_repo):
    result = cli_runner.invoke(cli, ["fix", mock_repo, "--disable", "tokens"])
    assert result.exit_code == 0
    assert "Scanning repository" in result.output
    assert "Fix Summary" in result.output


def test_fix_repository_no_workflows(cli_runner, tmp_path):
    empty = tmp_path / "empty_repo"
    empty.mkdir()
    result = cli_runner.invoke(cli, ["fix", str(empty)])
    assert result.exit_code == 1
    assert "No workflows found" in result.output


def test_fix_clean_workflow_no_issues(cli_runner, tmp_path):
    repo = tmp_path / "clean"
    repo.mkdir()
    _write_workflow(str(repo), "secure.yml", SECURE_WORKFLOW)
    result = cli_runner.invoke(cli, ["fix", str(repo)])
    assert result.exit_code == 0
    assert "No issues found" in result.output


def test_fix_some_unfixable(cli_runner, insecure_workflow_file, temp_dir):
    # The insecure workflow has findings, but none of them are auto-fixable
    # at HIGH+ severity, exercising the "could not be fixed" branch.
    result = cli_runner.invoke(
        cli, ["fix", insecure_workflow_file, "--severity-threshold", "CRITICAL"]
    )
    assert result.exit_code == 0
    assert "Fix Summary" in result.output


def test_fix_dry_run_clean_workflow(cli_runner, tmp_path):
    repo = tmp_path / "clean_dry"
    repo.mkdir()
    _write_workflow(str(repo), "secure.yml", SECURE_WORKFLOW)
    result = cli_runner.invoke(cli, ["fix", str(repo), "--dry-run"])
    assert result.exit_code == 0
    assert "No issues found" in result.output


def test_fix_dry_run_unfixable(cli_runner, insecure_workflow_file):
    result = cli_runner.invoke(
        cli, ["fix", insecure_workflow_file, "--dry-run", "--severity-threshold", "CRITICAL"]
    )
    assert result.exit_code == 0
    assert "Some issues cannot be automatically fixed" in result.output


def test_config_generate_stdout(cli_runner):
    result = cli_runner.invoke(cli, ["config", "--generate"])
    assert result.exit_code == 0
    assert "check_timeout" in result.output


def test_config_invalid(cli_runner, tmp_path):
    bad_config = tmp_path / "bad.yml"
    bad_config.write_text("unknown_option: true\n")
    result = cli_runner.invoke(cli, ["config", "--config", str(bad_config)])
    assert result.exit_code == 1
    assert "Config validation failed" in result.output


def test_analyze_non_workflow(cli_runner, tmp_path):
    not_a_workflow = tmp_path / "plain.yml"
    not_a_workflow.write_text("hello: world\n")
    result = cli_runner.invoke(cli, ["analyze", str(not_a_workflow)])
    assert result.exit_code == 1
    assert "Error analyzing file" in result.output


def test_analyze_clean_workflow(cli_runner, tmp_path):
    clean = tmp_path / "secure.yml"
    clean.write_text(SECURE_WORKFLOW)
    result = cli_runner.invoke(cli, ["analyze", str(clean)])
    assert result.exit_code == 0
    assert "No issues found" in result.output
