"""The CLI's exit-code contract.

`scan` previously signalled findings by raising ClickException, so a clean run
and a crashed run both exited 1 and printed `Error: Severe findings detected`.
A CI job could not distinguish "your workflows have problems" from "the
scanner broke", which is exactly the distinction a required check needs.
"""

import pytest
from click.testing import CliRunner

from ghast.cli import EXIT_ERROR, EXIT_FINDINGS, cli

CLEAN_WORKFLOW = """\
name: Clean
on: [push]
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: read-all
    timeout-minutes: 5
    steps:
      - run: echo hello
"""

FINDINGS_WORKFLOW = """\
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v1
"""


@pytest.fixture
def runner():
    return CliRunner()


def _repo(tmp_path, content, name="wf.yml"):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / name).write_text(content)
    return str(tmp_path)


def test_clean_scan_exits_zero(runner, tmp_path):
    result = runner.invoke(cli, ["scan", _repo(tmp_path, CLEAN_WORKFLOW)])

    assert result.exit_code == 0


def test_findings_exit_one(runner, tmp_path):
    result = runner.invoke(cli, ["scan", _repo(tmp_path, FINDINGS_WORKFLOW)])

    assert result.exit_code == EXIT_FINDINGS


def test_findings_below_threshold_exit_zero(runner, tmp_path):
    """Raising the threshold above everything found is a clean run."""
    result = runner.invoke(
        cli,
        ["scan", _repo(tmp_path, FINDINGS_WORKFLOW), "--severity-threshold", "CRITICAL"],
    )

    assert result.exit_code == 0


def test_missing_workflows_exits_two(runner, tmp_path):
    result = runner.invoke(cli, ["scan", str(tmp_path)])

    assert result.exit_code == EXIT_ERROR
    assert "No workflows found" in result.output


def test_missing_config_exits_two(runner, tmp_path):
    result = runner.invoke(
        cli,
        ["scan", _repo(tmp_path, CLEAN_WORKFLOW), "--config", str(tmp_path / "nope.yml")],
    )

    assert result.exit_code == EXIT_ERROR


def test_invalid_config_exits_two(runner, tmp_path):
    config = tmp_path / "bad.yml"
    config.write_text("severity_thresholds:\n  timeout: NOT_A_SEVERITY\n")
    result = runner.invoke(cli, ["scan", _repo(tmp_path, CLEAN_WORKFLOW), "--config", str(config)])

    assert result.exit_code == EXIT_ERROR


def test_bad_usage_exits_two(runner, tmp_path):
    """Click's own usage errors already exit 2; tool errors now match."""
    result = runner.invoke(cli, ["scan", str(tmp_path), "--not-a-flag"])

    assert result.exit_code == EXIT_ERROR


def test_findings_are_not_reported_as_an_error(runner, tmp_path):
    """A successful scan that found problems is a normal outcome."""
    result = runner.invoke(cli, ["scan", _repo(tmp_path, FINDINGS_WORKFLOW)])

    assert "Error: Severe findings detected" not in result.output
    assert "finding(s) at or above LOW" in result.output


def test_machine_readable_output_stays_clean_on_stdout(runner, tmp_path):
    """The findings notice goes to stderr so `--output json` can be piped."""
    import json

    result = runner.invoke(cli, ["scan", _repo(tmp_path, FINDINGS_WORKFLOW), "--output", "json"])

    assert result.exit_code == EXIT_FINDINGS
    payload = json.loads(result.stdout)
    assert "findings" in payload


def test_sarif_output_stays_clean_on_stdout(runner, tmp_path):
    import json

    result = runner.invoke(cli, ["scan", _repo(tmp_path, FINDINGS_WORKFLOW), "--output", "sarif"])

    assert json.loads(result.stdout)["version"] == "2.1.0"
