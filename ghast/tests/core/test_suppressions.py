"""Tests for inline ignore comments and baseline files.

Without these, a repository with any existing findings cannot adopt ghast as a
blocking check: the first run is red and stays red. That is exactly the
population most in need of the scanner.
"""

import json

import pytest

from ghast.core import WorkflowScanner
from ghast.core.scanner import Finding
from ghast.core.suppressions import (
    ALL_RULES,
    BASELINE_VERSION,
    BaselineError,
    apply_baseline,
    apply_suppressions,
    build_baseline,
    finding_fingerprint,
    load_baseline,
    load_suppressions,
    parse_suppressions,
)

WORKFLOW = """\
name: Demo
on: [push]
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: read-all
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
"""


def _repo(tmp_path, content=WORKFLOW):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    path = workflows / "w.yml"
    path.write_text(content)
    return str(path)


def _finding(rule_id="action_pinning", line=10, message="m", path="w.yml"):
    return Finding(
        rule_id=rule_id, severity="MEDIUM", message=message, file_path=path, line_number=line
    )


# --- directive parsing --------------------------------------------------------


def test_bare_ignore_covers_every_rule():
    result = parse_suppressions("- uses: x  # ghast: ignore\n")

    assert result.by_line[1] == {ALL_RULES}
    assert result.suppresses("anything", 1)


def test_ignore_with_rule_list():
    result = parse_suppressions("- uses: x  # ghast: ignore[action_pinning, timeout]\n")

    assert result.by_line[1] == {"action_pinning", "timeout"}
    assert result.suppresses("timeout", 1)
    assert not result.suppresses("permissions", 1)


def test_standalone_directive_applies_to_the_following_line():
    """Putting the justification above the line it explains must work."""
    result = parse_suppressions("# ghast: ignore[timeout] -- see #42\n- uses: x\n")

    assert result.suppresses("timeout", 2)
    assert not result.suppresses("timeout", 1)


def test_standalone_directive_does_not_leak_further_down():
    result = parse_suppressions("# ghast: ignore\n- a\n- b\n")

    assert result.suppresses("timeout", 2)
    assert not result.suppresses("timeout", 3)


def test_trailing_directive_does_not_leak_to_the_next_line():
    """One annotation must not silence the step after it as well."""
    result = parse_suppressions("- uses: a  # ghast: ignore\n- uses: b\n")

    assert result.suppresses("action_pinning", 1)
    assert not result.suppresses("action_pinning", 2)


def test_standalone_directive_skips_blank_and_comment_lines():
    result = parse_suppressions("# ghast: ignore\n\n# unrelated note\n- uses: x\n")

    assert result.suppresses("timeout", 4)


def test_standalone_directive_at_end_of_file_targets_nothing():
    result = parse_suppressions("- uses: x\n# ghast: ignore\n")

    assert result.by_line == {}


def test_ignore_file_covers_the_whole_document():
    result = parse_suppressions("# ghast: ignore-file\nname: X\n")

    assert result.file_level == {ALL_RULES}
    assert result.suppresses("timeout", 999)


def test_ignore_file_with_rule_list():
    result = parse_suppressions("# ghast: ignore-file[timeout]\n")

    assert result.suppresses("timeout", 5)
    assert not result.suppresses("permissions", 5)


def test_ignore_file_reaches_findings_without_a_line_number():
    """Only a file-level directive can silence an unpositioned finding."""
    result = parse_suppressions("# ghast: ignore-file\n")

    assert result.suppresses("permissions", None)


def test_line_directive_cannot_silence_an_unpositioned_finding():
    result = parse_suppressions("- x  # ghast: ignore\n")

    assert not result.suppresses("permissions", None)


@pytest.mark.parametrize(
    "comment",
    [
        "# ghast: ignore",
        "#ghast:ignore",
        "#  GHAST:  IGNORE",
        "# ghast: ignore[]",
    ],
)
def test_directive_spelling_variations(comment):
    assert parse_suppressions(f"- x  {comment}\n").suppresses("any", 1)


def test_empty_rule_list_means_every_rule():
    assert parse_suppressions("- x  # ghast: ignore[]\n").by_line[1] == {ALL_RULES}


def test_unrelated_comments_are_ignored():
    result = parse_suppressions("- x  # just a normal comment\n# ghastly\n")

    assert result.by_line == {}
    assert result.file_level == set()


def test_load_suppressions_tolerates_an_unreadable_file(tmp_path):
    """A read failure must not silently swallow every finding."""
    result = load_suppressions(str(tmp_path / "does-not-exist.yml"))

    assert result.by_line == {}
    assert result.file_level == set()


def test_apply_suppressions_reports_how_many_were_hidden():
    findings = [_finding(line=1), _finding(line=5)]
    suppressions = parse_suppressions("- x  # ghast: ignore\n")

    kept, suppressed = apply_suppressions(findings, suppressions)

    assert len(kept) == 1
    assert suppressed == 1


# --- end to end through the scanner ------------------------------------------


def test_scanner_honours_inline_directives(tmp_path):
    path = _repo(tmp_path)
    before = WorkflowScanner().scan_file(path)
    assert sum(1 for f in before if "not pinned" in f.message) == 2

    annotated = WORKFLOW.replace(
        "      - uses: actions/checkout@v4",
        "      - uses: actions/checkout@v4  # ghast: ignore[action_pinning]",
    )
    path = _repo(tmp_path, annotated)

    scanner = WorkflowScanner()
    after = scanner.scan_file(path)

    assert sum(1 for f in after if "not pinned" in f.message) == 1
    assert scanner.suppressed_count == 1


def test_scanner_counts_suppressions_across_files(tmp_path):
    annotated = WORKFLOW.replace(
        "      - uses: actions/checkout@v4",
        "      - uses: actions/checkout@v4  # ghast: ignore[action_pinning]",
    )
    path = _repo(tmp_path, annotated)

    scanner = WorkflowScanner()
    scanner.scan_file(path)
    scanner.scan_file(path)

    assert scanner.suppressed_count == 2


def test_bare_ignore_silences_every_rule_on_the_line(tmp_path):
    """A checkout line carries both a pinning and a credentials finding."""
    annotated = WORKFLOW.replace(
        "      - uses: actions/checkout@v4",
        "      - uses: actions/checkout@v4  # ghast: ignore",
    )
    scanner = WorkflowScanner()
    scanner.scan_file(_repo(tmp_path, annotated))

    assert scanner.suppressed_count == 2


# --- fingerprints -------------------------------------------------------------


def test_fingerprint_is_stable_across_calls():
    finding = _finding()

    assert finding_fingerprint(finding) == finding_fingerprint(finding)


def test_fingerprint_ignores_line_number():
    """Reformatting a workflow must not invalidate the whole baseline."""
    assert finding_fingerprint(_finding(line=10)) == finding_fingerprint(_finding(line=99))


def test_fingerprint_distinguishes_rules():
    assert finding_fingerprint(_finding(rule_id="timeout")) != finding_fingerprint(
        _finding(rule_id="permissions")
    )


def test_fingerprint_distinguishes_messages():
    assert finding_fingerprint(_finding(message="a")) != finding_fingerprint(_finding(message="b"))


def test_fingerprint_is_relative_to_the_scan_root(tmp_path):
    """A baseline must survive being used from a different checkout path."""
    one = _finding(path="/checkout-a/.github/workflows/w.yml")
    two = _finding(path="/checkout-b/.github/workflows/w.yml")

    assert finding_fingerprint(one, "/checkout-a") == finding_fingerprint(two, "/checkout-b")


# --- baseline documents -------------------------------------------------------


def test_build_baseline_records_every_finding():
    document = build_baseline([_finding(message="a"), _finding(message="b")])

    assert document["version"] == BASELINE_VERSION
    assert len(document["findings"]) == 2
    assert document["generated"]


def test_build_baseline_entries_are_human_readable():
    document = build_baseline([_finding(rule_id="timeout", message="slow job")])
    entry = next(iter(document["findings"].values()))

    assert entry["rule_id"] == "timeout"
    assert entry["message"] == "slow job"
    assert entry["severity"] == "MEDIUM"


def test_apply_baseline_drops_known_findings():
    known = _finding(message="old")
    new = _finding(message="new")
    fingerprints = set(build_baseline([known])["findings"])

    kept, suppressed = apply_baseline([known, new], fingerprints)

    assert [f.message for f in kept] == ["new"]
    assert suppressed == 1


def test_load_baseline_round_trip(tmp_path):
    path = tmp_path / "baseline.json"
    document = build_baseline([_finding()])
    path.write_text(json.dumps(document))

    assert load_baseline(str(path)) == set(document["findings"])


def test_load_baseline_missing_file(tmp_path):
    with pytest.raises(BaselineError, match="not found"):
        load_baseline(str(tmp_path / "nope.json"))


def test_load_baseline_invalid_json(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text("{not json")

    with pytest.raises(BaselineError, match="not valid JSON"):
        load_baseline(str(path))


def test_load_baseline_wrong_shape(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text('{"hello": "world"}')

    with pytest.raises(BaselineError, match="not a ghast baseline"):
        load_baseline(str(path))


def test_load_baseline_unsupported_version(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text('{"version": 99, "findings": {}}')

    with pytest.raises(BaselineError, match="not supported"):
        load_baseline(str(path))


def test_load_baseline_findings_must_be_a_mapping(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"version": BASELINE_VERSION, "findings": []}))

    with pytest.raises(BaselineError, match="must be an object"):
        load_baseline(str(path))


def test_load_baseline_unreadable_path(tmp_path):
    """A directory is readable as a path but not as a file."""
    with pytest.raises(BaselineError, match="Could not read"):
        load_baseline(str(tmp_path))


# --- CLI integration ----------------------------------------------------------


def _cli_repo(tmp_path, content=WORKFLOW):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / "w.yml").write_text(content)
    return str(tmp_path)


def test_baseline_command_writes_a_file(tmp_path):
    from click.testing import CliRunner

    from ghast.cli import cli

    out = tmp_path / "baseline.json"
    result = CliRunner().invoke(cli, ["baseline", _cli_repo(tmp_path), "--output", str(out)])

    assert result.exit_code == 0
    document = json.loads(out.read_text())
    assert document["version"] == BASELINE_VERSION
    assert document["findings"]
    assert "Recorded" in result.output


def test_baselined_scan_reports_nothing(tmp_path):
    """The whole point: an existing repo can gate on new findings today."""
    from click.testing import CliRunner

    from ghast.cli import cli

    runner = CliRunner()
    repo = _cli_repo(tmp_path)
    out = tmp_path / "baseline.json"

    assert runner.invoke(cli, ["baseline", repo, "--output", str(out)]).exit_code == 0

    result = runner.invoke(cli, ["scan", repo, "--baseline", str(out)])

    assert result.exit_code == 0
    assert "Total issues found: 0" in result.output


def test_baselined_scan_still_reports_new_findings(tmp_path):
    from click.testing import CliRunner

    from ghast.cli import cli

    runner = CliRunner()
    repo = _cli_repo(tmp_path)
    out = tmp_path / "baseline.json"
    runner.invoke(cli, ["baseline", repo, "--output", str(out)])

    workflow = tmp_path / ".github" / "workflows" / "w.yml"
    workflow.write_text(workflow.read_text() + "      - uses: brand/new-action@v1\n")

    result = runner.invoke(cli, ["scan", repo, "--baseline", str(out)])

    assert result.exit_code != 0
    assert "brand/new-action@v1" in result.output


def test_scan_rejects_a_broken_baseline(tmp_path):
    from click.testing import CliRunner

    from ghast.cli import cli

    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    result = CliRunner().invoke(cli, ["scan", _cli_repo(tmp_path), "--baseline", str(bad)])

    assert result.exit_code != 0
    assert "not valid JSON" in result.output


def test_baseline_of_a_clean_repo_is_empty(tmp_path):
    from click.testing import CliRunner

    from ghast.cli import cli

    clean = WORKFLOW.replace(
        "      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v3\n",
        "      - run: echo hi\n",
    )
    out = tmp_path / "baseline.json"
    result = CliRunner().invoke(cli, ["baseline", _cli_repo(tmp_path, clean), "--output", str(out)])

    assert result.exit_code == 0
    assert json.loads(out.read_text())["findings"] == {}
    assert "Recorded 0 finding(s)" in result.output


def test_scan_reports_inline_suppression_count(tmp_path):
    """Suppressions must be visible in the output, not silently applied."""
    from click.testing import CliRunner

    from ghast.cli import cli

    annotated = WORKFLOW.replace(
        "      - uses: actions/checkout@v4",
        "      - uses: actions/checkout@v4  # ghast: ignore",
    )
    result = CliRunner().invoke(cli, ["scan", _cli_repo(tmp_path, annotated)])

    assert "Ignored 2 finding(s) via inline '# ghast: ignore' comments" in result.output


def test_fingerprint_survives_an_unrelatable_path(monkeypatch):
    """Windows paths on different drives cannot be made relative."""
    import ghast.core.suppressions as module

    def _boom(*args, **kwargs):
        raise ValueError("different drives")

    monkeypatch.setattr(module.os.path, "relpath", _boom)
    finding = _finding(path="D:/repo/.github/workflows/w.yml")

    assert finding_fingerprint(finding, "C:/other")
