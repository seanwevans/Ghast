"""
security.py - Security-focused rules for GitHub Actions

This module provides rules focused on security issues in GitHub Actions workflows.
"""

from typing import List, Dict, Any, Set
import re

from .base import Rule, WorkflowRule, JobRule, StepRule, TriggerRule, TokenRule
from ..core import Finding


class PermissionsRule(WorkflowRule):
    """Rule for checking workflow permissions"""

    def __init__(self):
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

        # Check jobs
        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            findings.extend(self.check_job_permissions(job_id, job, file_path))

        return findings

    def fix(self, workflow: Dict[str, Any], finding: Finding) -> bool:
        """Fix missing permissions"""
        if "Missing explicit permissions at workflow level" in finding.message:
            workflow["permissions"] = "read-all"
            return True

        # Job level permission fix
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

    def __init__(self):
        super().__init__(
            rule_id="poisoned_pipeline_execution",
            severity="CRITICAL",
            description="Detects Poisoned Pipeline Execution vulnerabilities in GitHub Actions workflows",
            remediation="Use pull_request trigger instead of pull_request_target, or if pull_request_target is required, do not check out untrusted code",
            category="security",
        )
        self.high_risk_triggers = {"pull_request_target", "workflow_run"}
        self.dangerous_refs = [
            "github.event.pull_request",
            "github.head_ref",
            "github.event.issue",
            "github.event.comment",
            "github.event.review",
        ]

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for PPE vulnerabilities"""
        findings = []

        # Get triggers from 'on' section
        on_section = workflow.get("on", {})
        triggers = set()

        if isinstance(on_section, dict):
            triggers = set(on_section.keys())
        elif isinstance(on_section, list):
            triggers = set(on_section)

        # Check for high-risk triggers
        high_risk_triggers_used = triggers.intersection(self.high_risk_triggers)
        if not high_risk_triggers_used:
            return findings  # No high-risk triggers, exit early

        # We have high-risk triggers, now check for dangerous patterns
        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            steps = job.get("steps", [])

            # Check for checkout of untrusted code with high-risk triggers
            checkout_found = False
            untrusted_ref_used = None

            for step in steps:
                if not isinstance(step, dict):
                    continue

                uses = step.get("uses", "")

                if uses.startswith("actions/checkout"):
                    checkout_found = True

                    # Check if ref parameter uses untrusted input
                    if "with" in step and "ref" in step["with"]:
                        ref = step["with"]["ref"]
                        for dangerous_ref in self.dangerous_refs:
                            if dangerous_ref in str(ref):
                                untrusted_ref_used = ref
                                break

            # If checkout of untrusted code is found with high-risk triggers
            if checkout_found and untrusted_ref_used:
                findings.append(
                    self.create_finding(
                        message=f"Poisoned Pipeline Execution vulnerability: job '{job_id}' uses {', '.join(high_risk_triggers_used)} trigger with checkout of untrusted code",
                        file_path=file_path,
                        context={
                            "triggers": list(high_risk_triggers_used),
                            "ref": str(untrusted_ref_used),
                        },
                    )
                )

                # Check for other dangerous operations in this job
                for step_idx, step in enumerate(steps):
                    if not isinstance(step, dict):
                        continue

                    # Check for script execution
                    if "run" in step:
                        findings.append(
                            self.create_finding(
                                message=f"Job '{job_id}' executes scripts in step {step_idx+1} after checking out untrusted code in a high-privilege context",
                                file_path=file_path,
                                severity="HIGH",
                            )
                        )

                    # Check for environment variable setting
                    if "GITHUB_ENV" in str(step) or "GITHUB_PATH" in str(step):
                        findings.append(
                            self.create_finding(
                                message=f"Job '{job_id}' modifies environment variables or path in step {step_idx+1} after checking out untrusted code in a high-privilege context",
                                file_path=file_path,
                                severity="HIGH",
                            )
                        )

            # Check for secrets: inherit with high-risk triggers
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

    def __init__(self):
        super().__init__(
            rule_id="command_injection",
            severity="HIGH",
            description="Detects potential command injection vulnerabilities in shell commands",
            remediation="Never use untrusted input directly in shell commands. Use input validation or environment variables with proper quoting.",
            category="security",
        )
        self.dangerous_patterns = [
            (
                r"run:.*\${{.*github\.event\.(issue|comment|review).*}}",
                "Untrusted event data in shell command",
            ),
            (
                r"run:.*\${{.*github\.head_ref.*}}",
                "Untrusted head_ref in shell command",
            ),
            (
                r"run:.*\${{.*github\.event\.pull_request\.title.*}}",
                "Untrusted PR title in shell command",
            ),
            (
                r"run:.*\${{.*github\.event\.pull_request\.body.*}}",
                "Untrusted PR body in shell command",
            ),
        ]

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for command injection"""
        findings = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            steps = job.get("steps", [])

            for step_idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue

                if "run" in step and isinstance(step["run"], str):
                    run_command = step["run"]

                    for pattern, desc in self.dangerous_patterns:
                        if re.search(pattern, run_command, re.DOTALL):
                            findings.append(
                                self.create_finding(
                                    message=f"{desc} in job '{job_id}' step {step_idx+1}",
                                    file_path=file_path,
                                )
                            )

        return findings


class EnvironmentInjectionRule(StepRule):
    """Rule for detecting unsafe modifications to GITHUB_ENV and GITHUB_PATH"""

    def __init__(self):
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
            steps = job.get("steps", [])

            # Track if checkout is used and at what step
            checkout_step_idx = None

            for step_idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue

                if "uses" in step and step["uses"].startswith("actions/checkout"):
                    checkout_step_idx = step_idx
                    break

            # If checkout is used, check for GITHUB_ENV or GITHUB_PATH modifications after it
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
                                    message=f"Modification of GITHUB_PATH after checkout in job '{job_id}' step {step_idx+1}",
                                    file_path=file_path,
                                )
                            )

        return findings


class TokenSecurityRule(TokenRule):
    """Rule for checking token and secret usage"""

    def __init__(self):
        super().__init__(
            rule_id="token_security",
            severity="HIGH",
            description="Detects hardcoded tokens and insecure secret handling in workflows",
            remediation="Store secrets in GitHub Secrets and reference them with ${{ secrets.SECRET_NAME }}",
            category="security",
        )

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for token security issues"""
        findings = self.check_hardcoded_tokens(workflow, file_path)

        # Check for persist-credentials in actions/checkout
        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            steps = job.get("steps", [])

            for step_idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue

                if "uses" in step and step["uses"].startswith("actions/checkout"):
                    if (
                        "with" not in step
                        or "persist-credentials" not in step["with"]
                        or step["with"]["persist-credentials"] is not False
                    ):
                        findings.append(
                            self.create_finding(
                                message=f"actions/checkout in job '{job_id}' step {step_idx+1} does not disable credential persistence",
                                file_path=file_path,
                                remediation="Add 'persist-credentials: false' to the 'with' section of actions/checkout steps",
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

    def __init__(self):
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
            steps = job.get("steps", [])

            for step_idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue

                if "uses" in step:
                    findings.extend(
                        self.check_step_action_pinning(job_id, step_idx, step, file_path)
                    )

        return findings
