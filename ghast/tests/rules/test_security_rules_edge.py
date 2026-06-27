"""
test_security_rules_edge.py - Edge-case coverage for security rules

Covers the defensive branches that the happy-path tests don't reach: the
``__line__``/``__column__`` position-marker keys injected by the YAML loader,
non-dict steps and jobs, list-form trigger declarations, ``secrets: inherit``
exposure, and the ``fix`` fall-through paths.
"""

from ghast.rules.security import (
    ActionPinningRule,
    CommandInjectionRule,
    EnvironmentInjectionRule,
    PermissionsRule,
    PoisonedPipelineExecutionRule,
    TokenSecurityRule,
)


def test_permissions_rule_skips_position_markers_and_non_dict_jobs():
    rule = PermissionsRule()
    workflow = {
        "permissions": "read-all",
        "jobs": {
            "__line__": 1,
            "__column__": 1,
            "build": "not-a-dict",
        },
    }
    # All jobs are skipped; only workflow-level permission (present) is checked.
    assert rule.check(workflow, "wf.yml") == []


def test_permissions_rule_job_write_all():
    rule = PermissionsRule()
    findings = rule.check_job_permissions("build", {"permissions": "write-all"}, "wf.yml")
    assert len(findings) == 1
    assert "overly permissive" in findings[0].message.lower()


def test_permissions_rule_fix_job_level():
    rule = PermissionsRule()
    workflow = {"jobs": {"build": {"runs-on": "ubuntu-latest"}}}
    finding = rule.create_finding(
        message="Missing explicit permissions in job 'build'", file_path="wf.yml"
    )
    assert rule.fix(workflow, finding) is True
    assert workflow["jobs"]["build"]["permissions"] == "read-all"


def test_permissions_rule_fix_unknown_job_returns_false():
    rule = PermissionsRule()
    workflow = {"jobs": {"build": {}}}
    finding = rule.create_finding(
        message="Missing explicit permissions in job 'ghost'", file_path="wf.yml"
    )
    assert rule.fix(workflow, finding) is False


def test_permissions_rule_fix_no_match_returns_false():
    rule = PermissionsRule()
    finding = rule.create_finding(message="something unrelated", file_path="wf.yml")
    assert rule.fix({}, finding) is False


def test_ppe_list_form_triggers_and_secrets_inherit():
    rule = PoisonedPipelineExecutionRule()
    workflow = {
        "on": ["push", "pull_request_target"],
        "jobs": {
            "__line__": 1,
            "build": {
                "secrets": "inherit",
                "steps": [
                    "not-a-dict",
                    {"uses": "actions/checkout@v3"},
                ],
            },
        },
    }
    findings = rule.check(workflow, "wf.yml")
    assert any("secrets: inherit" in f.message.lower() for f in findings)


def test_ppe_dict_form_triggers():
    rule = PoisonedPipelineExecutionRule()
    workflow = {
        "on": {"pull_request_target": {"branches": ["main"]}},
        "jobs": {
            "build": {
                "steps": [
                    {
                        "uses": "actions/checkout@v3",
                        "with": {"ref": "${{ github.head_ref }}"},
                    },
                    {"run": "echo hi"},
                ],
            }
        },
    }
    findings = rule.check(workflow, "wf.yml")
    assert any("poisoned pipeline execution" in f.message.lower() for f in findings)


def test_ppe_modifies_environment_after_untrusted_checkout():
    rule = PoisonedPipelineExecutionRule()
    workflow = {
        "on": "pull_request_target",
        "jobs": {
            "build": {
                "steps": [
                    {
                        "uses": "actions/checkout@v3",
                        "with": {"ref": "${{ github.event.pull_request.head.ref }}"},
                    },
                    "not-a-dict-step",
                    {"run": "echo X=1 >> $GITHUB_ENV"},
                ],
            }
        },
    }
    findings = rule.check(workflow, "wf.yml")
    assert any("modifies environment" in f.message.lower() for f in findings)


def test_command_injection_skips_markers_and_non_dict_steps():
    rule = CommandInjectionRule()
    workflow = {
        "jobs": {
            "__line__": 1,
            "build": {
                "steps": [
                    "not-a-dict",
                    {"run": "echo ${{ github.event.comment.body }}"},
                ],
            },
        }
    }
    findings = rule.check(workflow, "wf.yml")
    assert len(findings) == 1
    assert "untrusted" in findings[0].message.lower()


def test_environment_injection_skips_markers_and_non_dict_steps():
    rule = EnvironmentInjectionRule()
    workflow = {
        "jobs": {
            "__line__": 1,
            "build": {
                "steps": [
                    "not-a-dict",
                    {"uses": "actions/checkout@v3"},
                    {"run": "echo X=1 >> $GITHUB_ENV"},
                ],
            },
        }
    }
    findings = rule.check(workflow, "wf.yml")
    assert any("github_env" in f.message.lower() for f in findings)


def test_token_security_skips_markers_and_non_dict_steps():
    rule = TokenSecurityRule()
    workflow = {
        "jobs": {
            "__line__": 1,
            "build": {
                "steps": [
                    "not-a-dict",
                    {"uses": "actions/checkout@v3"},
                ],
            },
        }
    }
    findings = rule.check(workflow, "wf.yml")
    assert any("credential persistence" in f.message.lower() for f in findings)


def test_token_security_fix_returns_false_for_unrelated():
    rule = TokenSecurityRule()
    finding = rule.create_finding(message="unrelated message", file_path="wf.yml")
    assert rule.fix({}, finding) is False


def test_token_security_fix_returns_false_for_missing_job():
    rule = TokenSecurityRule()
    workflow = {"jobs": {}}
    finding = rule.create_finding(
        message="actions/checkout in job 'build' step 1 does not disable credential persistence",
        file_path="wf.yml",
    )
    assert rule.fix(workflow, finding) is False


def test_action_pinning_skips_markers_and_non_dict_steps():
    rule = ActionPinningRule()
    workflow = {
        "jobs": {
            "__line__": 1,
            "build": {
                "steps": [
                    "not-a-dict",
                    {"uses": "actions/checkout@v3"},
                ],
            },
        }
    }
    findings = rule.check(workflow, "wf.yml")
    assert any("not pinned" in f.message.lower() for f in findings)
