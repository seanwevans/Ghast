"""
security.py - Security-focused rules for GitHub Actions

This module provides rules focused on security issues in GitHub Actions workflows.
"""

import re
from typing import Any, Dict, List

from ..core import Finding
from ..utils.yaml_handler import get_position
from .base import Rule, StepRule, TokenRule, WorkflowRule, _is_false
from .expressions import (
    CODE_EXECUTING_ACTION_INPUTS,
    find_dangerous_serialization,
    find_remote_script_execution,
    find_untrusted,
)


class PermissionsRule(WorkflowRule):
    """Rule for checking workflow permissions"""

    def __init__(self) -> None:
        super().__init__(
            rule_id="permissions",
            severity="HIGH",
            description="Workflows should have explicit permissions set to read-only by default",
            remediation="Add 'permissions: read-all' at the workflow level and specify write permissions only where needed",
            category="security",
        )
        self.can_fix = True

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check workflow and job permissions"""
        findings = self.check_workflow_permissions(workflow, file_path)

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__") or not isinstance(job, dict):
                continue
            findings.extend(self.check_job_permissions(job_id, job, file_path))

        return findings

    # The original implementation attempted to call ``check_workflow_permissions``
    # and ``check_job_permissions`` but these helper methods were never
    # implemented.  As a result the rule raised ``AttributeError`` during
    # execution, causing many tests that rely on permissions checking to fail.
    # The methods below provide the missing functionality by validating both
    # workflow-level and job-level permission declarations.

    def check_workflow_permissions(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Validate permissions defined at the workflow level."""
        findings: List[Finding] = []

        permissions = workflow.get("permissions")

        if permissions is None:
            findings.append(
                self.create_finding(
                    message="Missing explicit permissions at workflow level",
                    file_path=file_path,
                    line_number=get_position(workflow)[0] or 1,
                    column=get_position(workflow)[1] or 1,
                    can_fix=True,
                )
            )
        elif isinstance(permissions, str) and permissions.lower() == "write-all":
            findings.append(
                self.create_finding(
                    message="Overly permissive workflow permissions (write-all)",
                    file_path=file_path,
                    line_number=get_position(workflow)[0] or 1,
                    column=get_position(workflow)[1] or 1,
                )
            )

        return findings

    def check_job_permissions(
        self, job_id: str, job: Dict[str, Any], file_path: str
    ) -> List[Finding]:
        """Validate permissions for a specific job."""
        findings: List[Finding] = []

        permissions = job.get("permissions")

        if permissions is None:
            findings.append(
                self.create_finding(
                    message=f"Missing explicit permissions in job '{job_id}'",
                    file_path=file_path,
                    line_number=get_position(job)[0] or 1,
                    column=get_position(job)[1] or 1,
                    can_fix=True,
                )
            )
        elif isinstance(permissions, str) and permissions.lower() == "write-all":
            findings.append(
                self.create_finding(
                    message=f"Job '{job_id}' has overly permissive permissions (write-all)",
                    file_path=file_path,
                    line_number=get_position(job)[0] or 1,
                    column=get_position(job)[1] or 1,
                )
            )

        return findings

    def fix(self, workflow: Dict[str, Any], finding: Finding) -> bool:
        """Fix missing permissions"""
        if "Missing explicit permissions at workflow level" in finding.message:
            workflow["permissions"] = "read-all"
            return True

        job_match = re.search(r"job '([^']+)'", finding.message)
        if job_match:
            job_id = job_match.group(1)
            jobs = workflow.get("jobs", {})
            if job_id in jobs:
                jobs[job_id]["permissions"] = "read-all"
                return True

        return False


class PoisonedPipelineExecutionRule(Rule):
    """Rule for detecting Poisoned Pipeline Execution (PPE) vulnerabilities"""

    def __init__(self) -> None:
        super().__init__(
            rule_id="poisoned_pipeline_execution",
            severity="CRITICAL",
            description="Detects Poisoned Pipeline Execution vulnerabilities in GitHub Actions workflows",
            remediation="Use pull_request trigger instead of pull_request_target, or if pull_request_target is required, do not check out untrusted code",
            category="security",
        )
        # Triggers that run against the base repository with a write-scoped
        # token and access to secrets, while carrying attacker-supplied data.
        # Previously only the first two were recognised, so a workflow that
        # checked out a fork from an `issue_comment` handler was missed.
        self.high_risk_triggers = {
            "pull_request_target",
            "workflow_run",
            "issue_comment",
            "pull_request_review",
            "pull_request_review_comment",
            "discussion_comment",
        }
        self.dangerous_refs = [
            "github.event.pull_request",
            "github.head_ref",
            "github.event.issue",
            "github.event.comment",
            "github.event.review",
            "github.event.workflow_run",
            "github.event.discussion",
        ]

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for PPE vulnerabilities"""
        findings: List[Finding] = []

        on_section = workflow.get("on", {})
        triggers = set()

        if isinstance(on_section, dict):
            triggers = set(on_section.keys())
        elif isinstance(on_section, list):
            triggers = set(on_section)
        elif isinstance(on_section, str):
            triggers = {on_section}

        high_risk_triggers_used = triggers.intersection(self.high_risk_triggers)
        if not high_risk_triggers_used:
            return findings  # No high-risk triggers, exit early

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__") or not isinstance(job, dict):
                continue
            steps = job.get("steps", [])

            checkout_found = False
            untrusted_ref_used = None

            for step in steps:
                if not isinstance(step, dict):
                    continue

                uses = step.get("uses", "")

                if uses.startswith("actions/checkout"):
                    checkout_found = True

                    if "with" in step and "ref" in step["with"]:
                        ref = step["with"]["ref"]
                        for dangerous_ref in self.dangerous_refs:
                            if dangerous_ref in str(ref):
                                untrusted_ref_used = ref
                                break

            if checkout_found and untrusted_ref_used:
                sorted_triggers = sorted(high_risk_triggers_used)
                triggers_used = "{} trigger{}".format(
                    ", ".join(sorted_triggers),
                    "s" if len(sorted_triggers) > 1 else "",
                )

                # One finding per job, not one per step. The previous version
                # emitted a near-identical HIGH for every `run:` step in the
                # job — six duplicates for a single root cause — which buried
                # the CRITICAL that actually explains the problem. The affected
                # steps are carried in context instead.
                executing_steps = [
                    step_idx + 1
                    for step_idx, step in enumerate(steps)
                    if isinstance(step, dict) and "run" in step
                ]
                env_modifying_steps = [
                    step_idx + 1
                    for step_idx, step in enumerate(steps)
                    if isinstance(step, dict)
                    and ("GITHUB_ENV" in str(step) or "GITHUB_PATH" in str(step))
                ]

                detail = ""
                if executing_steps:
                    joined = ", ".join(str(idx) for idx in executing_steps)
                    detail = f"; untrusted code then runs in step(s) {joined}"

                findings.append(
                    self.create_finding(
                        message=(
                            f"Poisoned Pipeline Execution vulnerability: job "
                            f"'{job_id}' uses {triggers_used} with checkout "
                            f"of untrusted code{detail}"
                        ),
                        file_path=file_path,
                        line_number=get_position(job)[0],
                        column=get_position(job)[1],
                        context={
                            "triggers": sorted(high_risk_triggers_used),
                            "ref": str(untrusted_ref_used),
                            "executing_steps": executing_steps,
                            "env_modifying_steps": env_modifying_steps,
                        },
                    )
                )

            if "secrets" in job and job["secrets"] == "inherit" and high_risk_triggers_used:
                findings.append(
                    self.create_finding(
                        message=f"High-risk secret exposure: job '{job_id}' uses 'secrets: inherit' with {', '.join(high_risk_triggers_used)} trigger",
                        file_path=file_path,
                        context={"triggers": list(high_risk_triggers_used)},
                    )
                )

        return findings


class CommandInjectionRule(StepRule):
    """Rule for detecting potential command injection vulnerabilities"""

    def __init__(self) -> None:
        super().__init__(
            rule_id="command_injection",
            severity="HIGH",
            description="Detects potential command injection vulnerabilities in shell commands",
            remediation="Never use untrusted input directly in shell commands. Use input validation or environment variables with proper quoting.",
            category="security",
        )
        # Patterns that indicate untrusted input being used directly within a
        # shell command. The previous implementation mistakenly included the
        # literal ``"run:"`` prefix even though the rule inspects only the
        # command text. As a result no matches were found. These expressions
        # operate directly on the command string to properly flag injection
        # risks.

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for command injection"""
        findings: List[Finding] = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__") or not isinstance(job, dict):
                continue

            for step_idx, step in enumerate(job.get("steps", [])):
                if not isinstance(step, dict):
                    continue

                findings.extend(self._check_step(job_id, step_idx, step, file_path))

        return findings

    def _check_step(
        self, job_id: str, step_idx: int, step: Dict[str, Any], file_path: str
    ) -> List[Finding]:
        """Check one step for untrusted interpolation and remote execution."""
        findings: List[Finding] = []
        line, column = get_position(step)
        where = f"job '{job_id}' step {step_idx + 1}"

        run_command = step.get("run")
        if isinstance(run_command, str):
            # `${{ }}` is substituted into the script before the shell sees it,
            # so untrusted values here are executed, not passed as data.
            for use in find_untrusted(run_command):
                findings.append(
                    self.create_finding(
                        message=(
                            f"Untrusted {use.description} interpolated into a shell "
                            f"command in {where}: ${{{{ {use.expression} }}}}"
                        ),
                        file_path=file_path,
                        line_number=line,
                        column=column,
                        remediation=(
                            "Pass the value through an environment variable and "
                            "reference it quoted, e.g. env: TITLE: "
                            f'${{{{ {use.expression} }}}} then "$TITLE"'
                        ),
                    )
                )

            command = find_remote_script_execution(run_command)
            if command is not None:
                findings.append(
                    self.create_finding(
                        message=(f"Remote script piped into a shell in {where}: {command}"),
                        file_path=file_path,
                        line_number=line,
                        column=column,
                        severity="MEDIUM",
                        remediation=("Download to a file, verify its checksum, then execute it"),
                    )
                )

        findings.extend(self._check_action_inputs(job_id, step_idx, step, file_path))

        return findings

    def _check_action_inputs(
        self, job_id: str, step_idx: int, step: Dict[str, Any], file_path: str
    ) -> List[Finding]:
        """Flag untrusted data passed to action inputs that execute as code.

        Deliberately narrow: putting untrusted data into a plain `env:` or a
        non-executing `with:` input is the *recommended* mitigation, so flagging
        those would penalise correct workflows.
        """
        findings: List[Finding] = []

        uses = step.get("uses")
        inputs = step.get("with")
        if not isinstance(uses, str) or not isinstance(inputs, dict):
            return findings

        action = uses.split("@", 1)[0]
        code_inputs = CODE_EXECUTING_ACTION_INPUTS.get(action)
        if not code_inputs:
            return findings

        line, column = get_position(step)

        for input_name in code_inputs:
            value = inputs.get(input_name)
            if not isinstance(value, str):
                continue

            for use in find_untrusted(value):
                findings.append(
                    self.create_finding(
                        message=(
                            f"Untrusted {use.description} interpolated into "
                            f"'{action}' input '{input_name}' in job '{job_id}' "
                            f"step {step_idx + 1}: ${{{{ {use.expression} }}}}"
                        ),
                        file_path=file_path,
                        line_number=line,
                        column=column,
                        remediation=(
                            "Pass the value in through env: and read it from "
                            "process.env inside the script"
                        ),
                    )
                )

        return findings


class EnvironmentInjectionRule(StepRule):
    """Rule for detecting unsafe modifications to GITHUB_ENV and GITHUB_PATH"""

    # Noisy enough to stay off unless asked for. Declaring it here rather than
    # assigning self.enabled in __init__ means `environment_injection: true`
    # in a config file can actually turn it on.
    default_enabled = False

    def __init__(self) -> None:
        super().__init__(
            rule_id="environment_injection",
            severity="HIGH",
            description="Detects unsafe modifications to GITHUB_ENV and GITHUB_PATH after checkout of untrusted code",
            remediation="Avoid modifying GITHUB_ENV or GITHUB_PATH after checking out untrusted code, or move environment modifications before checkout",
            category="security",
        )

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for environment injection"""
        findings = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__") or not isinstance(job, dict):
                continue
            steps = job.get("steps", [])

            checkout_step_idx = None

            for step_idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue

                if "uses" in step and step["uses"].startswith("actions/checkout"):
                    # Credential persistence is reported by TokenSecurityRule.
                    # Emitting it here too produced two byte-identical findings
                    # for one checkout step.
                    checkout_step_idx = step_idx

            if checkout_step_idx is not None:
                for step_idx, step in enumerate(steps):
                    if step_idx <= checkout_step_idx or not isinstance(step, dict):
                        continue

                    if "run" in step and isinstance(step["run"], str):
                        run_command = step["run"]

                        if (
                            "GITHUB_ENV" in run_command
                            or ">>$GITHUB_ENV" in run_command
                            or ">> $GITHUB_ENV" in run_command
                        ):
                            findings.append(
                                self.create_finding(
                                    message=f"Modification of GITHUB_ENV after checkout in job '{job_id}' step {step_idx+1}",
                                    file_path=file_path,
                                )
                            )

                        if (
                            "GITHUB_PATH" in run_command
                            or ">>$GITHUB_PATH" in run_command
                            or ">> $GITHUB_PATH" in run_command
                        ):
                            findings.append(
                                self.create_finding(
                                    message=(
                                        f"Modification of GITHUB_PATH after checkout in job '{job_id}' "
                                        f"step {step_idx+1}"
                                    ),
                                    file_path=file_path,
                                )
                            )

        return findings


class TokenSecurityRule(TokenRule):
    """Rule for checking token and secret usage"""

    def __init__(self) -> None:
        super().__init__(
            rule_id="token_security",
            severity="HIGH",
            description="Detects hardcoded tokens and insecure secret handling in workflows",
            remediation=(
                "Store secrets in GitHub Secrets and reference them "
                "with ${{ secrets.SECRET_NAME }}"
            ),
            category="security",
        )

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for token security issues"""
        findings = self.check_hardcoded_tokens(workflow, file_path)

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__") or not isinstance(job, dict):
                continue
            steps = job.get("steps", [])

            for step_idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue

                if "uses" in step and step["uses"].startswith("actions/checkout"):
                    if (
                        "with" not in step
                        or "persist-credentials" not in step["with"]
                        or not _is_false(step["with"]["persist-credentials"])
                    ):
                        findings.append(
                            self.create_finding(
                                message=(
                                    f"actions/checkout in job '{job_id}' step {step_idx+1} "
                                    "does not disable credential persistence"
                                ),
                                file_path=file_path,
                                line_number=get_position(step)[0],
                                column=get_position(step)[1],
                                remediation=(
                                    "Add 'persist-credentials: false' to the 'with' section of actions/checkout steps"
                                ),
                                can_fix=True,
                            )
                        )

        return findings

    def fix(self, workflow: Dict[str, Any], finding: Finding) -> bool:
        """Fix persist-credentials issues"""
        if "actions/checkout" in finding.message and "credential persistence" in finding.message:
            job_match = re.search(r"job '([^']+)'", finding.message)
            step_match = re.search(r"step (\d+)", finding.message)

            if job_match and step_match:
                job_id = job_match.group(1)
                step_idx = int(step_match.group(1)) - 1

                jobs = workflow.get("jobs", {})
                if job_id in jobs:
                    steps = jobs[job_id].get("steps", [])

                    if 0 <= step_idx < len(steps):
                        step = steps[step_idx]

                        if "uses" in step and step["uses"].startswith("actions/checkout"):
                            if "with" not in step:
                                step["with"] = {}

                            step["with"]["persist-credentials"] = False
                            return True

        return False


class ActionPinningRule(StepRule):
    """Rule for checking action pinning"""

    def __init__(self) -> None:
        super().__init__(
            rule_id="action_pinning",
            severity="MEDIUM",
            description="Checks if actions are pinned to specific commit SHAs",
            remediation="Pin actions to specific commit SHAs for better security",
            category="security",
        )

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for action pinning issues"""
        findings = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__") or not isinstance(job, dict):
                continue
            steps = job.get("steps", [])

            for step_idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue

                if "uses" in step:
                    findings.extend(
                        self.check_step_action_pinning(job_id, step_idx, step, file_path)
                    )

        return findings
