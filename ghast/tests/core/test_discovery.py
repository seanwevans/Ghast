"""Tests for scan-target discovery.

Discovery was open-coded in four places, each globbing
``<root>/.github/workflows/*.y*ml``. Two things it could never reach: a bare
directory of workflow files, and composite actions — which run steps with the
same supply-chain exposure as a workflow and were never looked at.
"""

import pytest

from ghast.core import WorkflowScanner
from ghast.core.discovery import (
    WORKFLOW_ONLY_RULES,
    TargetKind,
    adapt_action_to_workflow,
    discover_targets,
    is_action_definition,
)

WORKFLOW = """\
name: CI
on: [push]
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: read-all
    timeout-minutes: 5
    steps:
      - run: echo hi
"""

COMPOSITE_ACTION = """\
name: Build
description: builds things
runs:
  using: composite
  steps:
    - uses: actions/checkout@v3
    - run: echo "${{ github.event.issue.title }}"
      shell: bash
"""

JS_ACTION = """\
name: Node thing
description: no steps to check
runs:
  using: node20
  main: dist/index.js
"""


def _repo(tmp_path, workflows=None, actions=None):
    if workflows:
        directory = tmp_path / ".github" / "workflows"
        directory.mkdir(parents=True, exist_ok=True)
        for name, content in workflows.items():
            (directory / name).write_text(content)
    for path, content in (actions or {}).items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return str(tmp_path)


# --- discovery ----------------------------------------------------------------


def test_finds_workflows_in_a_repository(tmp_path):
    root = _repo(tmp_path, workflows={"ci.yml": WORKFLOW, "release.yaml": WORKFLOW})
    targets = discover_targets(root)

    assert [t.path.name for t in targets] == ["ci.yml", "release.yaml"]
    assert all(t.kind is TargetKind.WORKFLOW for t in targets)


def test_finds_composite_actions_anywhere_in_the_repository(tmp_path):
    root = _repo(
        tmp_path,
        workflows={"ci.yml": WORKFLOW},
        actions={"actions/build/action.yml": COMPOSITE_ACTION, "action.yaml": COMPOSITE_ACTION},
    )
    targets = discover_targets(root)

    actions = [t for t in targets if t.kind is TargetKind.ACTION]
    assert len(actions) == 2


def test_actions_can_be_excluded(tmp_path):
    root = _repo(tmp_path, workflows={"ci.yml": WORKFLOW}, actions={"action.yml": COMPOSITE_ACTION})

    targets = discover_targets(root, include_actions=False)

    assert all(t.kind is TargetKind.WORKFLOW for t in targets)


def test_a_bare_directory_of_workflows_is_scannable(tmp_path):
    """`ghast scan ./workflows` reported nothing found before."""
    (tmp_path / "ci.yml").write_text(WORKFLOW)
    (tmp_path / "release.yaml").write_text(WORKFLOW)

    targets = discover_targets(str(tmp_path))

    assert [t.path.name for t in targets] == ["ci.yml", "release.yaml"]


def test_a_single_file_is_its_own_target(tmp_path):
    path = tmp_path / "ci.yml"
    path.write_text(WORKFLOW)

    assert discover_targets(str(path)) == [(path, TargetKind.WORKFLOW)]


def test_a_single_action_file_is_recognised(tmp_path):
    path = tmp_path / "action.yml"
    path.write_text(COMPOSITE_ACTION)

    assert discover_targets(str(path))[0].kind is TargetKind.ACTION


def test_non_yaml_files_are_ignored(tmp_path):
    _repo(tmp_path, workflows={"ci.yml": WORKFLOW})
    (tmp_path / ".github" / "workflows" / "README.md").write_text("hi")

    assert [t.path.name for t in discover_targets(str(tmp_path))] == ["ci.yml"]


def test_vendored_directories_are_skipped(tmp_path):
    root = _repo(
        tmp_path,
        workflows={"ci.yml": WORKFLOW},
        actions={"node_modules/pkg/action.yml": COMPOSITE_ACTION},
    )

    assert not [t for t in discover_targets(root) if t.kind is TargetKind.ACTION]


def test_missing_path_yields_nothing(tmp_path):
    assert discover_targets(str(tmp_path / "nope")) == []


def test_discovery_order_is_stable(tmp_path):
    root = _repo(
        tmp_path,
        workflows={"b.yml": WORKFLOW, "a.yml": WORKFLOW},
        actions={"z/action.yml": COMPOSITE_ACTION, "a/action.yml": COMPOSITE_ACTION},
    )

    once = [str(t.path) for t in discover_targets(root)]
    twice = [str(t.path) for t in discover_targets(root)]

    assert once == twice
    assert once == sorted(once[:2]) + sorted(once[2:])


def test_unreadable_subdirectory_does_not_abort_the_walk(tmp_path, monkeypatch):
    root = _repo(
        tmp_path, workflows={"ci.yml": WORKFLOW}, actions={"a/action.yml": COMPOSITE_ACTION}
    )

    import pathlib

    original = pathlib.Path.iterdir

    def _selective(self):
        if self.name == "a":
            raise PermissionError("denied")
        return original(self)

    monkeypatch.setattr(pathlib.Path, "iterdir", _selective)

    assert discover_targets(root)


# --- action adaptation --------------------------------------------------------


def test_composite_action_is_recognised():
    import yaml

    assert is_action_definition(yaml.safe_load(COMPOSITE_ACTION))


def test_workflow_is_not_mistaken_for_an_action():
    import yaml

    assert not is_action_definition(yaml.safe_load(WORKFLOW))


@pytest.mark.parametrize("content", [None, [], "string", {}, {"runs": "not-a-mapping"}])
def test_non_action_content_is_not_an_action(content):
    assert not is_action_definition(content)


def test_adaptation_presents_steps_as_a_single_job():
    import yaml

    adapted = adapt_action_to_workflow(yaml.safe_load(COMPOSITE_ACTION))

    assert adapted is not None
    assert list(adapted["jobs"]) == ["runs"]
    assert len(adapted["jobs"]["runs"]["steps"]) == 2


@pytest.mark.parametrize("content", [{"runs": {"using": "node20"}}, {"runs": "x"}, {}])
def test_actions_without_steps_adapt_to_nothing(content):
    assert adapt_action_to_workflow(content) is None


# --- scanning actions end to end ----------------------------------------------


def test_composite_action_step_issues_are_reported(tmp_path):
    path = tmp_path / "action.yml"
    path.write_text(COMPOSITE_ACTION)

    findings = WorkflowScanner().scan_file(str(path))
    reported = {f.rule_id for f in findings}

    assert "action_pinning" in reported
    assert "command_injection" in reported


def test_workflow_only_rules_are_not_reported_for_actions(tmp_path):
    """An action declares no triggers, permissions or job timeout."""
    path = tmp_path / "action.yml"
    path.write_text(COMPOSITE_ACTION)

    reported = {f.rule_id for f in WorkflowScanner().scan_file(str(path))}

    assert not reported & WORKFLOW_ONLY_RULES


def test_stepless_action_produces_no_findings(tmp_path):
    """A JavaScript action has no step surface, and is not a parse error."""
    path = tmp_path / "action.yml"
    path.write_text(JS_ACTION)

    assert WorkflowScanner().scan_file(str(path)) == []


def test_scan_repository_counts_actions_as_files(tmp_path):
    from ghast.core import scan_repository

    root = _repo(
        tmp_path, workflows={"ci.yml": WORKFLOW}, actions={"a/action.yml": COMPOSITE_ACTION}
    )
    _, stats = scan_repository(root)

    assert stats["total_files"] == 2


def test_cli_reports_how_many_composite_actions_were_scanned(tmp_path):
    """Scanning actions is new behaviour, so say so rather than silently doing it."""
    from click.testing import CliRunner

    from ghast.cli import cli

    root = _repo(
        tmp_path, workflows={"ci.yml": WORKFLOW}, actions={"a/action.yml": COMPOSITE_ACTION}
    )
    result = CliRunner().invoke(cli, ["scan", root])

    assert "Found 2 file(s) to scan (1 composite action(s))" in result.output


def test_cli_omits_the_action_count_when_there_are_none(tmp_path):
    from click.testing import CliRunner

    from ghast.cli import cli

    result = CliRunner().invoke(cli, ["scan", _repo(tmp_path, workflows={"ci.yml": WORKFLOW})])

    assert "Found 1 file(s) to scan" in result.output
    assert "composite action" not in result.output
