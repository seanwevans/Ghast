"""
test_fixer_edge.py - Edge-case coverage for the auto-remediation module

Covers fixer fall-through branches, interactive prompting, error handling
during fixing/dumping, fix_runs_on, and the fix_repository skip/echo paths.
"""

import os
import shutil

import click
import pytest
import yaml

from ghast.core import Finding
from ghast.core import fixer as fixer_module
from ghast.core.fixer import Fixer, fix_repository


def _copy(src, dst_dir, name):
    dst = os.path.join(dst_dir, name)
    shutil.copy2(src, dst)
    return dst


def _timeout_finding(file_path, message="Job 'build' has 6 steps but no timeout-minutes set"):
    return Finding(
        rule_id="check_timeout",
        severity="LOW",
        message=message,
        file_path=file_path,
        remediation="Add timeout",
        can_fix=True,
    )


def test_fix_workflow_file_no_fixable_findings(patchable_workflow_file, temp_dir):
    test_file = _copy(patchable_workflow_file, temp_dir, "nofix.yml")
    # rule_id is not among the registered fixers.
    findings = [
        Finding(
            rule_id="check_tokens",
            severity="HIGH",
            message="hardcoded token",
            file_path=test_file,
            can_fix=True,
        )
    ]
    assert Fixer({}).fix_workflow_file(test_file, findings) == (0, 0)


def test_fix_workflow_file_missing_fixer_func(patchable_workflow_file, temp_dir):
    test_file = _copy(patchable_workflow_file, temp_dir, "missingfixer.yml")

    class _ContainsButNoGet(dict):
        def get(self, key, default=None):
            return None

    fixer = Fixer({})
    # Passes the membership filter but resolves to no fixer function.
    fixer.fixers = _ContainsButNoGet({"check_timeout": fixer.fix_timeout})
    applied, skipped = fixer.fix_workflow_file(test_file, [_timeout_finding(test_file)])
    assert applied == 0
    assert skipped == 1
    # No fixes applied -> backup is cleaned up.
    assert not os.path.exists(f"{test_file}.bak")


def test_fix_workflow_file_interactive_confirm(patchable_workflow_file, temp_dir, monkeypatch):
    test_file = _copy(patchable_workflow_file, temp_dir, "interactive_yes.yml")
    monkeypatch.setattr(click, "confirm", lambda *a, **k: True)
    fixer = Fixer({}, interactive=True)
    applied, skipped = fixer.fix_workflow_file(test_file, [_timeout_finding(test_file)])
    assert applied == 1


def test_fix_workflow_file_interactive_decline(patchable_workflow_file, temp_dir, monkeypatch):
    test_file = _copy(patchable_workflow_file, temp_dir, "interactive_no.yml")
    monkeypatch.setattr(click, "confirm", lambda *a, **k: False)
    fixer = Fixer({}, interactive=True)
    applied, skipped = fixer.fix_workflow_file(test_file, [_timeout_finding(test_file)])
    assert applied == 0
    assert skipped == 1


def test_fix_workflow_file_fixer_returns_false(patchable_workflow_file, temp_dir):
    test_file = _copy(patchable_workflow_file, temp_dir, "returnsfalse.yml")
    # Message without a recognisable "Job '...'" so fix_timeout returns False.
    finding = _timeout_finding(test_file, message="unmatchable message")
    applied, skipped = Fixer({}).fix_workflow_file(test_file, [finding])
    assert applied == 0
    assert skipped == 1


def test_fix_workflow_file_fixer_raises(patchable_workflow_file, temp_dir, capsys):
    test_file = _copy(patchable_workflow_file, temp_dir, "raises.yml")

    def _boom(workflow, finding):
        raise RuntimeError("kaboom")

    fixer = Fixer({})
    fixer.fixers["check_timeout"] = _boom
    applied, skipped = fixer.fix_workflow_file(test_file, [_timeout_finding(test_file)])
    assert applied == 0
    assert skipped == 1
    assert "Error fixing" in capsys.readouterr().err


def test_fix_workflow_file_dump_error_restores(
    patchable_workflow_file, temp_dir, monkeypatch, capsys
):
    test_file = _copy(patchable_workflow_file, temp_dir, "dumperror.yml")
    with open(test_file, "r") as f:
        original = f.read()

    def _boom(*args, **kwargs):
        raise RuntimeError("dump failed")

    monkeypatch.setattr(fixer_module.yaml, "dump", _boom)
    applied, skipped = Fixer({}).fix_workflow_file(test_file, [_timeout_finding(test_file)])
    assert (applied, skipped) == (0, 0)
    # Original content restored, backup removed.
    with open(test_file, "r") as f:
        assert f.read() == original
    assert not os.path.exists(f"{test_file}.bak")
    assert "Error fixing" in capsys.readouterr().err


# --- direct fixer-method fall-through paths -----------------------------------


def test_fix_timeout_no_match():
    assert Fixer({}).fix_timeout({"jobs": {}}, _timeout_finding("f", message="nope")) is False


def test_fix_timeout_unknown_job():
    finding = _timeout_finding("f", message="Job 'ghost' has 6 steps")
    assert Fixer({}).fix_timeout({"jobs": {"build": {}}}, finding) is False


def test_fix_shell_no_match():
    finding = Finding(rule_id="check_shell", severity="LOW", message="nope", file_path="f")
    assert Fixer({}).fix_shell({"jobs": {}}, finding) is False


def test_fix_shell_unknown_job():
    finding = Finding(
        rule_id="check_shell",
        severity="LOW",
        message="Multiline script in job 'ghost' step 1 has no shell specified",
        file_path="f",
    )
    assert Fixer({}).fix_shell({"jobs": {"build": {}}}, finding) is False


def test_fix_deprecated_no_match():
    finding = Finding(rule_id="check_deprecated", severity="MEDIUM", message="nope", file_path="f")
    assert Fixer({}).fix_deprecated_actions({"jobs": {}}, finding) is False


def test_fix_deprecated_no_replacement():
    finding = Finding(
        rule_id="check_deprecated",
        severity="MEDIUM",
        message="Deprecated action 'actions/unknown@v1' in job 'build' step 1",
        file_path="f",
    )
    assert Fixer({}).fix_deprecated_actions({"jobs": {"build": {}}}, finding) is False


def test_fix_deprecated_no_matching_step():
    finding = Finding(
        rule_id="check_deprecated",
        severity="MEDIUM",
        message="Deprecated action 'actions/checkout@v1' in job 'build' step 1",
        file_path="f",
    )
    config = {"default_action_versions": {"actions/checkout@v1": "actions/checkout@v3"}}
    workflow = {"jobs": {"build": {"steps": [{"uses": "actions/setup-node@v3"}]}}}
    assert Fixer(config).fix_deprecated_actions(workflow, finding) is False


def _runs_on_finding(message="Missing 'runs-on' in job 'build'"):
    return Finding(rule_id="check_runs_on", severity="MEDIUM", message=message, file_path="f")


def test_fix_runs_on_adds_runner():
    workflow = {"jobs": {"build": {"steps": []}}}
    assert Fixer({}).fix_runs_on(workflow, _runs_on_finding()) is True
    assert workflow["jobs"]["build"]["runs-on"] == "ubuntu-latest"


def test_fix_runs_on_no_match():
    assert Fixer({}).fix_runs_on({"jobs": {}}, _runs_on_finding(message="nope")) is False


def test_fix_runs_on_unknown_job():
    finding = _runs_on_finding(message="Missing 'runs-on' in job 'ghost'")
    assert Fixer({}).fix_runs_on({"jobs": {"build": {}}}, finding) is False


def test_fix_runs_on_already_present():
    workflow = {"jobs": {"build": {"runs-on": "ubuntu-latest"}}}
    assert Fixer({}).fix_runs_on(workflow, _runs_on_finding()) is False


# --- fix_repository skip/echo paths -------------------------------------------


def test_fix_repository_skips_empty_and_unfixable(patchable_workflow_file, temp_dir):
    empty_file = _copy(patchable_workflow_file, temp_dir, "empty.yml")
    unfixable_file = _copy(patchable_workflow_file, temp_dir, "unfixable.yml")
    findings_by_file = {
        empty_file: [],
        unfixable_file: [
            Finding(
                rule_id="check_tokens",
                severity="HIGH",
                message="token",
                file_path=unfixable_file,
                can_fix=True,
            )
        ],
    }
    applied, skipped = fix_repository(temp_dir, findings_by_file, {})
    assert applied == 0
    assert skipped == 0


def test_fix_repository_echoes_skipped(patchable_workflow_file, temp_dir, capsys):
    test_file = _copy(patchable_workflow_file, temp_dir, "skipme.yml")
    # Fixable rule but unmatchable message -> fixer returns False -> skipped.
    findings_by_file = {test_file: [_timeout_finding(test_file, message="unmatchable")]}
    applied, skipped = fix_repository(temp_dir, findings_by_file, {})
    assert applied == 0
    assert skipped == 1
    assert "Skipped" in capsys.readouterr().out
