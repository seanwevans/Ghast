"""Tests that a working scanner cannot masquerade as a working scanner.

`scan_file` wrapped its whole body in `except Exception` and reported anything
that escaped as a MEDIUM `file_error` finding about the user's workflow. When
a merge left a call to a deleted method in place, every scan raised
AttributeError, was caught, and reported:

    MEDIUM: Error parsing workflow file: 'WorkflowScanner' object has no
            attribute '_normalize_rule_ids'

ghast was detecting nothing at all, `ghast scan` on a clean repository still
exited 0, and the failure looked like a complaint about the user's YAML.

These tests make that state impossible to reach quietly.
"""

import pytest
import yaml
from click.testing import CliRunner

from ghast.cli import EXIT_ERROR, cli
from ghast.core import WorkflowScanner
from ghast.core.scanner import ScannerError

VALID_WORKFLOW = """\
name: Valid
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v1
      - run: echo hello
"""


def _repo(tmp_path, content=VALID_WORKFLOW, name="w.yml"):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / name).write_text(content)
    return tmp_path


def _workflow(tmp_path, **kwargs):
    return str(_repo(tmp_path, **kwargs) / ".github" / "workflows" / "w.yml")


# --- a valid workflow must actually be scanned --------------------------------


def test_valid_workflow_never_reports_a_file_error(tmp_path):
    """The canary. A parseable workflow reporting `file_error` means ghast broke."""
    findings = WorkflowScanner().scan_file(_workflow(tmp_path))

    errors = [f for f in findings if f.rule_id == "file_error"]
    assert not errors, f"scanner failed on a valid workflow: {[f.message for f in errors]}"


def test_valid_workflow_produces_real_findings(tmp_path):
    """Rules must actually run, not just fail to error."""
    findings = WorkflowScanner().scan_file(_workflow(tmp_path))

    assert findings, "no rules produced findings on a workflow with known issues"
    assert any(f.rule_id == "action_pinning" for f in findings)
    assert any(f.rule_id == "permissions" for f in findings)


def test_scan_repository_produces_real_findings(tmp_path):
    from ghast.core import scan_repository

    findings, stats = scan_repository(str(_repo(tmp_path)))

    assert stats["total_files"] == 1
    assert findings
    assert not [f for f in findings if f.rule_id == "file_error"]


def test_cli_scan_of_a_valid_repo_does_not_report_a_file_error(tmp_path):
    result = CliRunner().invoke(cli, ["scan", str(_repo(tmp_path))])

    assert "Error parsing workflow file" not in result.output


# --- ghast's own bugs are not the user's problem ------------------------------


def test_internal_failure_raises_instead_of_becoming_a_finding(tmp_path, monkeypatch):
    """An unexpected exception must not be dressed up as a finding."""
    scanner = WorkflowScanner()

    def _boom(*args, **kwargs):
        raise AttributeError("object has no attribute '_gone'")

    monkeypatch.setattr(scanner.rule_engine, "scan_workflow", _boom)

    with pytest.raises(ScannerError, match="bug in ghast"):
        scanner.scan_file(_workflow(tmp_path))


@pytest.mark.parametrize("target", ["file", "repo"])
def test_internal_failure_exits_two(tmp_path, monkeypatch, target):
    """It is a tool failure, so it takes the tool-failure exit code, not 0 or 1."""
    from ghast.rules.engine import RuleEngine

    def _boom(*args, **kwargs):
        raise AttributeError("object has no attribute '_gone'")

    workflow = _workflow(tmp_path)
    monkeypatch.setattr(RuleEngine, "scan_workflow", _boom)

    result = CliRunner().invoke(cli, ["scan", workflow if target == "file" else str(tmp_path)])

    assert result.exit_code == EXIT_ERROR
    assert "bug in ghast" in result.output


# --- genuine file problems are still findings ---------------------------------


def test_malformed_yaml_is_still_a_finding(tmp_path):
    findings = WorkflowScanner().scan_file(_workflow(tmp_path, content="a: [1, 2\nb: {"))

    assert [f.rule_id for f in findings] == ["file_error"]


def test_non_workflow_yaml_is_still_a_finding(tmp_path):
    findings = WorkflowScanner().scan_file(_workflow(tmp_path, content="hello: world\n"))

    assert [f.rule_id for f in findings] == ["file_error"]


def test_unreadable_file_is_still_a_finding(tmp_path):
    missing = str(tmp_path / "nope.yml")

    findings = WorkflowScanner().scan_file(missing)

    assert [f.rule_id for f in findings] == ["file_error"]


def test_file_error_is_reported_at_medium(tmp_path):
    findings = WorkflowScanner().scan_file(_workflow(tmp_path, content="a: [1, 2\nb: {"))

    assert findings[0].severity == "MEDIUM"


def test_yaml_error_type_is_caught_not_reraised():
    """Guards the except clause against being narrowed too far."""
    import inspect

    source = inspect.getsource(WorkflowScanner.scan_file)

    assert "yaml.YAMLError" in source
    assert "OSError" in source
    assert "UnicodeDecodeError" in source
