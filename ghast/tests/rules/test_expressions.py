"""Tests for the untrusted-expression taint model.

The previous command-injection check was four hardcoded regexes covering
issue/comment/review data, `head_ref`, and PR title/body. Everything else in
GitHub's script-injection guidance went undetected. These tests pin the
contexts that must be caught and, just as importantly, the ones that must not
be, since a scanner that flags the recommended mitigation is unusable.
"""

import pytest

from ghast.rules.expressions import (
    find_dangerous_serialization,
    find_remote_script_execution,
    find_untrusted,
    iter_expressions,
)

# Contexts an attacker controls. Each was silently missed before, except where
# noted as previously covered.
UNTRUSTED = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.discussion_comment.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.review.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.pull_request.head.repo.description",
    "github.event.pull_request.head.repo.homepage",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.display_title",
    "github.event.workflow_run.head_commit.message",
    "github.event.pages[0].page_name",
    "github.head_ref",
    "github.event.inputs.target",
    "inputs.name",
]

# Values GitHub controls, or that identify rather than describe. Flagging
# these would drown real findings.
TRUSTED = [
    "github.repository",
    "github.sha",
    "github.ref",
    "github.actor",
    "github.run_id",
    "github.workspace",
    "github.event.pull_request.number",
    "github.event.pull_request.head.sha",
    "github.event.issue.number",
    "secrets.GITHUB_TOKEN",
    "env.SOME_VAR",
    "matrix.python-version",
    "steps.build.outputs.result",
    "job.status",
    "runner.os",
]


@pytest.mark.parametrize("context", UNTRUSTED)
def test_untrusted_context_is_detected(context):
    uses = find_untrusted("echo ${{ " + context + " }}")

    assert len(uses) == 1, f"{context} was not flagged"
    assert uses[0].description


@pytest.mark.parametrize("context", TRUSTED)
def test_trusted_context_is_not_flagged(context):
    assert find_untrusted("echo ${{ " + context + " }}") == []


def test_multiple_untrusted_values_report_separately():
    uses = find_untrusted(
        "echo ${{ github.event.issue.title }} ${{ github.event.head_commit.message }}"
    )

    assert len(uses) == 2


def test_one_expression_reports_once():
    """A single interpolation should not fan out across matching patterns."""
    uses = find_untrusted("echo ${{ github.event.pull_request.head.ref }}")

    assert len(uses) == 1


def test_untrusted_value_survives_surrounding_text():
    uses = find_untrusted('git checkout "${{ github.head_ref }}" && make')

    assert len(uses) == 1
    assert uses[0].expression == "github.head_ref"


def test_multiline_expressions_are_found():
    uses = find_untrusted("echo ${{\n  github.event.issue.title\n}}")

    assert len(uses) == 1


def test_plain_text_mentioning_a_context_is_not_flagged():
    """Only interpolations count; prose about them does not."""
    assert find_untrusted("# never use github.event.issue.title here") == []


def test_inputs_does_not_match_a_longer_identifier():
    assert find_untrusted("echo ${{ steps.x.outputs.inputs.name }}") == []


def test_iter_expressions_yields_each_interpolation():
    assert list(iter_expressions("a ${{ x }} b ${{ y }}")) == [" x ", " y "]


# --- remote script execution --------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "curl -sL https://example.com/i.sh | bash",
        "curl https://example.com/i.sh | sh",
        "wget -qO- https://example.com/i.sh | bash",
        "curl -s https://example.com/get.py | python3",
        "curl -fsSL https://example.com/x | zsh",
    ],
)
def test_remote_script_execution_is_detected(command):
    assert find_remote_script_execution(command) is not None


@pytest.mark.parametrize(
    "command",
    [
        "curl -sL https://example.com/i.sh -o i.sh",
        "curl -s https://example.com/data.json | jq .name",
        "bash script.sh",
        "echo hello | cat",
    ],
)
def test_safe_downloads_are_not_flagged(command):
    assert find_remote_script_execution(command) is None


# --- whole-context serialization ---------------------------------------------


@pytest.mark.parametrize(
    "expression",
    [
        "toJson(secrets)",
        "toJSON(secrets)",
        "TOJSON(secrets)",
        "toJSON( secrets )",
        "toJSON(github.event)",
        "toJson(github)",
    ],
)
def test_dangerous_serialization_is_detected(expression):
    """`toJson(secrets)` was matched as a case-sensitive literal, so GitHub's
    own `toJSON` spelling went undetected."""
    assert find_dangerous_serialization("${{ " + expression + " }}") is not None


@pytest.mark.parametrize(
    "expression",
    [
        "toJSON(matrix)",
        "toJSON(steps.build.outputs)",
        "fromJSON(needs.build.outputs.data)",
    ],
)
def test_safe_serialization_is_not_flagged(expression):
    assert find_dangerous_serialization("${{ " + expression + " }}") is None
