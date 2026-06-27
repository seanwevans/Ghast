"""
test_best_practices_edge.py - Edge-case coverage for best-practice rules

Covers position-marker skipping, non-dict steps, ``fix`` fall-through paths,
and the reusable-workflow input declaration edge cases.
"""

from ghast.rules.best_practices import (
    ContinueOnErrorRule,
    DeprecatedActionsRule,
    ReusableWorkflowRule,
    ShellSpecificationRule,
    TimeoutRule,
    WorkflowNameRule,
)


def test_timeout_check_skips_markers_and_non_dict_jobs():
    rule = TimeoutRule()
    workflow = {"jobs": {"__line__": 1, "build": "not-a-dict"}}
    assert rule.check(workflow, "wf.yml") == []


def test_timeout_fix_returns_false_without_job_match():
    rule = TimeoutRule()
    finding = rule.create_finding(message="no job reference here", file_path="wf.yml")
    assert rule.fix({"jobs": {}}, finding) is False


def test_timeout_fix_returns_false_for_unknown_job():
    rule = TimeoutRule()
    finding = rule.create_finding(message="Job 'ghost' has 6 steps", file_path="wf.yml")
    assert rule.fix({"jobs": {"build": {}}}, finding) is False


def test_shell_check_skips_markers_and_non_dict_steps():
    rule = ShellSpecificationRule()
    workflow = {
        "jobs": {
            "__line__": 1,
            "build": {"steps": ["not-a-dict", {"run": "line1\nline2"}]},
        }
    }
    findings = rule.check(workflow, "wf.yml")
    assert len(findings) == 1
    assert "shell" in findings[0].message.lower()


def test_shell_fix_returns_false_when_no_multiline():
    rule = ShellSpecificationRule()
    workflow = {"jobs": {"build": {"steps": [{"run": "single line"}]}}}
    finding = rule.create_finding(
        message="Multiline script in job 'build' step 1 has no shell specified",
        file_path="wf.yml",
    )
    assert rule.fix(workflow, finding) is False


def test_shell_fix_returns_false_without_match():
    rule = ShellSpecificationRule()
    finding = rule.create_finding(message="no markers", file_path="wf.yml")
    assert rule.fix({"jobs": {}}, finding) is False


def test_workflow_name_fix_returns_false_when_named():
    rule = WorkflowNameRule()
    workflow = {"name": "Existing", "on": "push"}
    finding = rule.create_finding(message="Missing workflow name", file_path="wf.yml")
    assert rule.fix(workflow, finding) is False


def test_deprecated_check_skips_markers_and_non_dict_steps():
    rule = DeprecatedActionsRule()
    workflow = {
        "jobs": {
            "__line__": 1,
            "build": {"steps": ["not-a-dict", {"uses": "actions/checkout@v1"}]},
        }
    }
    findings = rule.check(workflow, "wf.yml")
    assert any("deprecated action" in f.message.lower() for f in findings)


def test_deprecated_fix_uses_replacement_fallback():
    rule = DeprecatedActionsRule()
    workflow = {"jobs": {"build": {"steps": [{"uses": "actions/checkout@v1"}]}}}
    # No 'replacement' in context forces the lookup fallback path.
    finding = rule.create_finding(
        message="Deprecated action 'actions/checkout@v1' in job 'build' step 1",
        file_path="wf.yml",
        context={},
    )
    assert rule.fix(workflow, finding) is True
    assert workflow["jobs"]["build"]["steps"][0]["uses"] == "actions/checkout@v3"


def test_deprecated_fix_returns_false_without_match():
    rule = DeprecatedActionsRule()
    finding = rule.create_finding(message="nothing matches", file_path="wf.yml")
    assert rule.fix({"jobs": {}}, finding) is False


def test_continue_on_error_skips_markers_and_non_dict_steps():
    rule = ContinueOnErrorRule()
    workflow = {
        "jobs": {
            "__line__": 1,
            "build": {
                "continue-on-error": True,
                "steps": ["not-a-dict", {"run": "echo"}],
            },
        }
    }
    findings = rule.check(workflow, "wf.yml")
    assert len(findings) == 1
    assert "continue-on-error" in findings[0].message.lower()


def test_reusable_workflow_call_non_dict_trigger():
    rule = ReusableWorkflowRule()
    workflow = {
        "on": {"workflow_call": "not-a-dict"},
        "jobs": {
            "__line__": 1,
            "build": {"steps": [{"run": "echo ${{ inputs.foo }}"}]},
        },
    }
    findings = rule.check(workflow, "wf.yml")
    assert any("does not define on.workflow_call.inputs" in f.message for f in findings)


def test_reusable_workflow_call_non_dict_inputs():
    rule = ReusableWorkflowRule()
    workflow = {
        "on": {"workflow_call": {"inputs": "not-a-dict"}},
        "jobs": {
            "build": {"steps": [{"run": "echo ${{ inputs.foo }}"}]},
        },
    }
    findings = rule.check(workflow, "wf.yml")
    # Non-dict declared inputs are treated as no declarations.
    assert any("inputs" in f.message.lower() for f in findings)


def test_reusable_workflow_no_workflow_call():
    rule = ReusableWorkflowRule()
    workflow = {"on": {"push": {}}, "jobs": {"build": {"steps": []}}}
    assert rule.check(workflow, "wf.yml") == []


def test_reusable_workflow_undeclared_inputs():
    rule = ReusableWorkflowRule()
    workflow = {
        "on": {"workflow_call": {"inputs": {"declared": {"type": "string"}}}},
        "jobs": {
            "build": {"steps": [{"run": "echo ${{ inputs.declared }} ${{ inputs.missing }}"}]},
        },
    }
    findings = rule.check(workflow, "wf.yml")
    assert any("undeclared input 'missing'" in f.message for f in findings)
    # The properly declared input must not be reported.
    assert not any("input 'declared'" in f.message for f in findings)
