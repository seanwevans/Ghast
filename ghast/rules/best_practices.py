"""
best_practices.py - Best practice rules for GitHub Actions

This module provides rules focused on best practices rather than strict security issues.
"""

from typing import List, Dict, Any, Set, Optional
import re

from .base import Rule, WorkflowRule, JobRule, StepRule
from ..core import Finding


class TimeoutRule(JobRule):
    """Rule for checking job timeouts"""

    def __init__(self):
        super().__init__(
            rule_id="timeout",
            severity="LOW",
            description="Jobs should have a timeout set to prevent hanging",
            remediation="Add timeout-minutes to jobs, especially those with many steps",
            category="best-practice",
        )
        self.can_fix = True
        self.min_steps = 5

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for missing timeouts"""
        findings = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            findings.extend(self.check_job_timeout(job_id, job, file_path, self.min_steps))

        return findings

    def fix(self, workflow: Dict[str, Any], finding: Finding) -> bool:
        """Fix missing timeouts"""
        job_match = re.search(r"Job '([^']+)'", finding.message)

        if job_match:
            job_id = job_match.group(1)
            jobs = workflow.get("jobs", {})

            if job_id in jobs:
                jobs[job_id]["timeout-minutes"] = 15
                return True

        return False


class ShellSpecificationRule(StepRule):
    """Rule for checking shell specification in multiline scripts"""

    def __init__(self):
        super().__init__(
            rule_id="shell_specification",
            severity="LOW",
            description="Multiline scripts should have a shell specified",
            remediation="Add 'shell: bash' to steps with multiline run commands",
            category="best-practice",
        )
        self.can_fix = True

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for missing shell specifications"""
        findings = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            steps = job.get("steps", [])

            for step_idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue

                findings.extend(self.check_step_shell(job_id, step_idx, step, file_path))

        return findings

    def fix(self, workflow: Dict[str, Any], finding: Finding) -> bool:
        """Fix missing shell specifications"""
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

                    if (
                        "run" in step
                        and isinstance(step["run"], str)
                        and "\n" in step["run"]
                        and "shell" not in step
                    ):
                        step["shell"] = "bash"
                        return True

        return False


class WorkflowNameRule(WorkflowRule):
    """Rule for checking workflow name"""

    def __init__(self):
        super().__init__(
            rule_id="workflow_name",
            severity="LOW",
            description="Workflows should have a name",
            remediation="Add a 'name' field at the top level of the workflow",
            category="best-practice",
        )
        self.can_fix = True

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for missing workflow name"""
        return self.check_workflow_name(workflow, file_path)

    def fix(self, workflow: Dict[str, Any], finding: Finding) -> bool:
        """Fix missing workflow name"""
        if "name" not in workflow:
            # Generate a name based on the file path
            file_name = finding.file_path.split("/")[-1]

            # Remove extension and convert to title case
            workflow_name = (
                os.path.splitext(file_name)[0].replace("-", " ").replace("_", " ").title()
            )

            # Add the name field
            keys = list(workflow.keys())
            ordered_workflow = {"name": workflow_name}
            for key in keys:
                ordered_workflow[key] = workflow[key]

            # Update the workflow in-place
            workflow.clear()
            workflow.update(ordered_workflow)

            return True

        return False


class DeprecatedActionsRule(StepRule):
    """Rule for checking deprecated actions"""

    def __init__(self):
        super().__init__(
            rule_id="deprecated_actions",
            severity="MEDIUM",
            description="Detects usage of deprecated actions",
            remediation="Update to the latest version of the action",
            category="best-practice",
        )
        self.can_fix = True
        self.deprecated_actions = {
            "actions/checkout@v1": "actions/checkout@v3",
            "actions/checkout@v2": "actions/checkout@v3",
            "actions/setup-python@v1": "actions/setup-python@v4",
            "actions/setup-python@v2": "actions/setup-python@v4",
            "actions/setup-node@v1": "actions/setup-node@v3",
            "actions/setup-node@v2": "actions/setup-node@v3",
            "actions/cache@v1": "actions/cache@v3",
            "actions/cache@v2": "actions/cache@v3",
        }

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for deprecated actions"""
        findings = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            steps = job.get("steps", [])

            for step_idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue

                if "uses" in step:
                    action = step["uses"]

                    for deprecated, replacement in self.deprecated_actions.items():
                        if action.startswith(deprecated):
                            findings.append(
                                self.create_finding(
                                    message=f"Deprecated action '{action}' in job '{job_id}' step {step_idx+1}",
                                    file_path=file_path,
                                    remediation=f"Update to {replacement}",
                                    can_fix=True,
                                    context={
                                        "deprecated": deprecated,
                                        "replacement": replacement,
                                    },
                                )
                            )

        return findings

    def fix(self, workflow: Dict[str, Any], finding: Finding) -> bool:
        """Fix deprecated actions"""
        job_match = re.search(r"job '([^']+)'", finding.message)
        step_match = re.search(r"step (\d+)", finding.message)
        action_match = re.search(r"'([^']+)'", finding.message)

        if job_match and step_match and action_match:
            job_id = job_match.group(1)
            step_idx = int(step_match.group(1)) - 1
            deprecated_action = action_match.group(1)

            jobs = workflow.get("jobs", {})
            if job_id in jobs:
                steps = jobs[job_id].get("steps", [])

                if 0 <= step_idx < len(steps):
                    step = steps[step_idx]

                    if "uses" in step and step["uses"] == deprecated_action:
                        # Get the replacement from context if available
                        replacement = finding.context.get("replacement")

                        # Fallback to the mapping if not in context
                        if not replacement:
                            for depr, repl in self.deprecated_actions.items():
                                if deprecated_action.startswith(depr):
                                    replacement = repl
                                    break

                        if replacement:
                            step["uses"] = replacement
                            return True

        return False


class ContinueOnErrorRule(Rule):
    """Rule for checking continue-on-error usage"""

    def __init__(self):
        super().__init__(
            rule_id="continue_on_error",
            severity="MEDIUM",
            description="Detects usage of continue-on-error which can mask failures",
            remediation="Remove continue-on-error or set to false to ensure workflow fails on error",
            category="best-practice",
        )

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for continue-on-error usage"""
        findings = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job.get("continue-on-error") is True:
                findings.append(
                    self.create_finding(
                        message=f"Job '{job_id}' has 'continue-on-error: true'",
                        file_path=file_path,
                    )
                )

            steps = job.get("steps", [])
            for step_idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue

                if step.get("continue-on-error") is True:
                    findings.append(
                        self.create_finding(
                            message=f"Step {step_idx+1} in job '{job_id}' has 'continue-on-error: true'",
                            file_path=file_path,
                        )
                    )

        return findings


class ReusableWorkflowRule(Rule):
    """Rule for checking reusable workflow inputs"""

    def __init__(self):
        super().__init__(
            rule_id="reusable_workflow_inputs",
            severity="MEDIUM",
            description="Checks if reusable workflows define proper inputs",
            remediation="Define explicit 'inputs' for reusable workflows",
            category="best-practice",
        )

    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for reusable workflow input issues"""
        findings = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job.get("uses") and "with" in job:
                # Check if the job is using a reusable workflow
                if not job.get("inputs"):
                    findings.append(
                        self.create_finding(
                            message=f"Reusable workflow in job '{job_id}' uses 'with' without defining 'inputs'",
                            file_path=file_path,
                        )
                    )

        return findings


import os  # For the WorkflowNameRule

# Additional rule classes can be added here
