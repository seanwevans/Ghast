"""Round-trip safety tests for the workflow fixer.

`ghast fix` rewrites files that gate a repository's CI. These tests pin the
three ways a naive PyYAML load/dump cycle silently destroyed them:

1. ``on:`` resolved to the boolean ``True`` under YAML 1.1, leaving a workflow
   with no triggers that could never run again.
2. Every comment was discarded.
3. Block scalars (``run: |``) were re-emitted as folded strings with blank
   lines injected between the original lines.
"""

import os

import pytest
import yaml
from ruamel.yaml import YAML

from ghast.core.fixer import (
    Fixer,
    detect_sequence_indent,
    dump_workflow,
    load_workflow_for_edit,
)
from ghast.core.scanner import Finding

WORKFLOW = """\
# Build pipeline -- please keep comments!
name: CI
on: [push]

jobs:
  build:            # main job
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v1
      - name: multi
        run: |
          echo one
          echo two
      - run: echo a
"""


def _write(tmp_path, content=WORKFLOW, name="w.yml"):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    path = workflows / name
    path.write_text(content)
    return str(path)


def _timeout_finding(path):
    return Finding(
        rule_id="timeout",
        severity="LOW",
        message="Job 'build' has 6 steps but no timeout-minutes set",
        file_path=path,
        remediation="Add 'timeout-minutes: 15' to job 'build'",
        can_fix=True,
    )


def _fix(path, finding=None):
    applied, _ = Fixer({}).fix_workflow_file(path, [finding or _timeout_finding(path)])
    assert applied == 1
    with open(path) as handle:
        return handle.read()


# --- the three corruptions ----------------------------------------------------


def test_on_trigger_survives(tmp_path):
    """The YAML 1.1 'Norway problem': `on` must not be written back as `true`."""
    result = _fix(_write(tmp_path))

    # The bug emitted the literal key `true:` here, leaving GitHub with a
    # workflow that has no triggers and therefore never runs.
    assert "on: [push]" in result
    assert "true:" not in result

    reloaded = YAML().load(result)
    assert "on" in reloaded
    assert reloaded["on"] == ["push"]


def test_comments_survive(tmp_path):
    result = _fix(_write(tmp_path))

    assert "# Build pipeline -- please keep comments!" in result
    assert "# main job" in result


def test_block_scalars_survive_verbatim(tmp_path):
    result = _fix(_write(tmp_path))

    assert "run: |" in result
    # The folded-string bug turned this into "echo one\n\necho two\n".
    reloaded = yaml.safe_load(result)
    run = reloaded["jobs"]["build"]["steps"][1]["run"]
    assert run == "echo one\necho two\n"


# --- formatting fidelity ------------------------------------------------------


def test_only_the_intended_line_changes(tmp_path):
    """A fix should be a surgical edit, not a reformat of the whole document."""
    path = _write(tmp_path)
    before = open(path).read().splitlines()
    after = _fix(path).splitlines()

    added = [line for line in after if line not in before]
    assert added == ["    timeout-minutes: 15"]


@pytest.mark.parametrize(
    "steps_block,expected",
    [
        ("    steps:\n      - run: echo a\n", "      - run: echo a"),
        ("    steps:\n    - run: echo a\n", "    - run: echo a"),
    ],
    ids=["indented-sequence", "flush-sequence"],
)
def test_sequence_indentation_style_is_preserved(tmp_path, steps_block, expected):
    content = "name: CI\non: [push]\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n" + steps_block
    result = _fix(_write(tmp_path, content))
    assert expected in result


def test_quoting_style_is_preserved(tmp_path):
    content = (
        'name: "CI"\non: [push]\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n'
        "    steps:\n      - run: echo 'single'\n"
    )
    result = _fix(_write(tmp_path, content))
    assert 'name: "CI"' in result
    assert "echo 'single'" in result


def test_long_lines_are_not_rewrapped(tmp_path):
    long_run = "echo " + "x" * 200
    content = (
        "name: CI\non: [push]\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        f"    steps:\n      - run: {long_run}\n"
    )
    result = _fix(_write(tmp_path, content))
    assert long_run in result


def test_no_op_run_leaves_file_byte_identical(tmp_path):
    """Nothing fixable means nothing written, so no incidental reformatting."""
    path = _write(tmp_path)
    before = open(path).read()

    unfixable = Finding(
        rule_id="timeout",
        severity="LOW",
        message="Job 'nonexistent' has 6 steps but no timeout-minutes set",
        file_path=path,
        can_fix=True,
    )
    applied, _ = Fixer({}).fix_workflow_file(path, [unfixable])

    assert applied == 0
    assert open(path).read() == before
    assert not os.path.exists(f"{path}.bak")


def test_workflow_name_insert_keeps_comments(tmp_path):
    """Adding `name:` must not detach comments from the keys it moves past."""
    content = "# leading comment\non: [push]\n\njobs:\n  build:  # job comment\n    runs-on: x\n"
    path = _write(tmp_path, content, name="my-flow.yml")
    finding = Finding(
        rule_id="workflow_name",
        severity="LOW",
        message="Missing workflow name (top-level 'name' field)",
        file_path=path,
        can_fix=True,
    )
    result = _fix(path, finding)

    assert "# leading comment" in result
    assert "# job comment" in result
    assert result.index("name: My Flow") < result.index("on: [push]")
    assert "on: [push]" in result


# --- the write-time safety net ------------------------------------------------


def test_corrupt_output_is_refused_and_file_restored(tmp_path, monkeypatch, capsys):
    """If serialization ever loses `on:`, the original must survive."""
    import ghast.core.fixer as fixer_module

    path = _write(tmp_path)
    before = open(path).read()

    monkeypatch.setattr(
        fixer_module, "dump_workflow", lambda *a, **k: "name: CI\ntrue:\n- push\njobs: {}\n"
    )
    applied, skipped = Fixer({}).fix_workflow_file(path, [_timeout_finding(path)])

    assert (applied, skipped) == (0, 0)
    assert open(path).read() == before
    assert not os.path.exists(f"{path}.bak")
    assert "boolean key" in capsys.readouterr().err


@pytest.mark.parametrize(
    "rendered,expected",
    [
        ("- just\n- a\n- list\n", "non-mapping document"),
        ("name: CI\non: [push]\n", "dropped the 'jobs' section"),
        ("name: CI\ntrue:\n- push\njobs: {}\n", "boolean key"),
        ("name: CI\njobs: {}\n", "dropped the 'on:' triggers"),
    ],
)
def test_verify_roundtrip_rejects(rendered, expected):
    with pytest.raises(ValueError, match=expected):
        Fixer({})._verify_roundtrip(rendered, "w.yml")


def test_verify_roundtrip_accepts_valid_document():
    Fixer({})._verify_roundtrip("name: CI\non: [push]\njobs:\n  build: {}\n", "w.yml")


# --- indentation detection ----------------------------------------------------


@pytest.mark.parametrize(
    "source,expected",
    [
        ("steps:\n  - a\n", (4, 2)),
        ("steps:\n- a\n", (2, 0)),
        ("steps:\n    - a\n", (6, 4)),
        ("name: CI\n", (4, 2)),
        ("", (4, 2)),
        ("# only a comment\n\n", (4, 2)),
        ("key: value\n- orphan\n", (4, 2)),
    ],
)
def test_detect_sequence_indent(source, expected):
    assert detect_sequence_indent(source) == expected


def test_load_and_dump_are_lossless(tmp_path):
    path = _write(tmp_path)
    workflow, handler = load_workflow_for_edit(path)
    assert dump_workflow(workflow, handler) == WORKFLOW


def test_loader_keeps_on_as_a_string_key(tmp_path):
    """Contrast with PyYAML, whose YAML 1.1 resolver turns this key into True."""
    path = _write(tmp_path)
    workflow, _ = load_workflow_for_edit(path)

    assert "on" in workflow
    assert True not in workflow

    with open(path) as handle:
        assert True in yaml.safe_load(handle), "PyYAML behaviour changed; comment above is stale"


# --- driven by real findings, not hand-written ids ----------------------------

FIXABLE_WORKFLOW = """\
# keep me
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v1
      - run: |
          echo a
          echo b
      - run: echo c
      - run: echo d
      - run: echo e
"""


def test_fix_applies_to_findings_produced_by_the_scanner(tmp_path):
    """Drive the fixer from real findings rather than hand-built ones.

    Hand-written `rule_id`s in tests drift silently when rule ids are renamed:
    the fixer registry stops matching and every fix becomes a no-op while the
    tests that construct their own findings keep passing until someone updates
    the literals. Going through the scanner keeps the two in sync by
    construction.
    """
    from ghast.core import WorkflowScanner

    path = _write(tmp_path, FIXABLE_WORKFLOW)
    findings = WorkflowScanner().scan_file(path)
    assert findings

    applied, _ = Fixer({}).fix_workflow_file(path, findings)

    assert applied > 0, "no scanner finding matched a registered fixer"

    result = open(path).read()
    assert "# keep me" in result
    assert "on: [push]" in result
    assert "timeout-minutes: 15" in result
    assert "shell: bash" in result


def test_every_fixer_key_is_reachable_from_a_real_finding(tmp_path):
    """Each registered fixer must correspond to a rule that actually reports."""
    from ghast.core import WorkflowScanner

    path = _write(tmp_path, FIXABLE_WORKFLOW)
    reported = {finding.rule_id for finding in WorkflowScanner().scan_file(path)}

    registry = set(Fixer({}).fixers)
    assert registry & reported, f"no fixer in {sorted(registry)} matches any of {sorted(reported)}"
