"""
base.py - Base class for GitHub Actions security rules

This module provides the foundation for implementing security rules in ghast.
Rules are used to check for security issues in GitHub Actions workflows.
"""

import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..core import Finding


class Rule(ABC):
    """Base class for all ghast security rules"""

    def __init__(
        self,
        rule_id: str,
        severity: str,
        description: str,
        remediation: str,
        category: str = "security",
    ):
        """
        Initialize a rule

        Args:
            rule_id: Unique identifier for the rule
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            description: Human-readable description of the rule
            remediation: Generic remediation advice for this rule
            category: Category of the rule (security, best-practice, etc.)
        """
        self.rule_id = rule_id
        self.severity = severity
        self.description = description
        self.remediation = remediation
        self.category = category
        self.enabled = True

        self.can_fix = False

    @abstractmethod
    def check(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """
        Check a workflow for security issues

        Args:
            workflow: Workflow data as a dictionary
            file_path: Path to the workflow file

        Returns:
            List of findings
        """
        pass

    def fix(self, workflow: Dict[str, Any], finding: Finding) -> bool:
        """
        Fix a security issue in a workflow

        Args:
            workflow: Workflow data as a dictionary
            finding: Finding to fix

        Returns:
            True if the issue was fixed, False otherwise
        """
        return False

    def create_finding(
        self,
        message: str,
        file_path: str,
        line_number: Optional[int] = None,
        column: Optional[int] = None,
        remediation: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        can_fix: Optional[bool] = None,
        severity: Optional[str] = None,
    ) -> Finding:
        """
        Create a Finding object for this rule

        Args:
            message: Message describing the issue
            file_path: Path to the workflow file
            line_number: Line number where the issue was found
            column: Column number where the issue was found
            remediation: Specific remediation advice (defaults to rule's generic advice)
            context: Additional context for the finding
            can_fix: Whether this specific finding can be automatically fixed

        Returns:
            Finding object
        """
        return Finding(
            rule_id=self.rule_id,
            severity=severity or self.severity,
            message=message,
            file_path=file_path,
            line_number=line_number,
            column=column,
            remediation=remediation or self.remediation,
            context=context or {},
            can_fix=can_fix if can_fix is not None else self.can_fix,
        )


class WorkflowRule(Rule):
    """Base class for rules that check workflow-level issues"""

    def check_workflow_name(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """
        Check if the workflow has a name

        Args:
            workflow: Workflow data as a dictionary
            file_path: Path to the workflow file

        Returns:
            List of findings
        """
        findings = []

        if "name" not in workflow:
            findings.append(
                self.create_finding(
                    message="Missing workflow name (top-level 'name' field)",
                    file_path=file_path,
                    can_fix=True,
                )
            )

        return findings

    def check_workflow_permissions(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """
        Check if the workflow has explicit permissions set

        Args:
            workflow: Workflow data as a dictionary
            file_path: Path to the workflow file

        Returns:
            List of findings
        """
        findings = []

        if "permissions" not in workflow:
            findings.append(
                self.create_finding(
                    message="Missing explicit permissions at workflow level",
                    file_path=file_path,
                    remediation="Add 'permissions: read-all' at the top level of the workflow",
                    can_fix=True,
                )
            )
        elif workflow["permissions"] == "write-all":
            findings.append(
                self.create_finding(
                    message="Overly permissive 'write-all' permissions at workflow level",
                    file_path=file_path,
                    remediation=(
                        "Restrict permissions to only what's needed using "
                        "specific permission keys"
                    ),
                    can_fix=False,
                )
            )

        return findings


class JobRule(Rule):
    """Base class for rules that check job-level issues"""

    def check_job_permissions(
        self, job_id: str, job: Dict[str, Any], file_path: str
    ) -> List[Finding]:
        """
        Check if the job has explicit permissions set

        Args:
            job_id: Job identifier
            job: Job data as a dictionary
            file_path: Path to the workflow file

        Returns:
            List of findings
        """
        findings = []

        if "permissions" not in job:
            findings.append(
                self.create_finding(
                    message=f"Missing explicit permissions in job '{job_id}'",
                    file_path=file_path,
                    remediation=f"Add 'permissions: read-all' to job '{job_id}'",
                    can_fix=True,
                )
            )
        elif job["permissions"] == "write-all":
            findings.append(
                self.create_finding(
                    message=f"Overly permissive 'write-all' permissions in job '{job_id}'",
                    file_path=file_path,
                    remediation=(
                        "Restrict permissions to only what's needed using "
                        "specific permission keys"
                    ),
                    can_fix=False,
                )
            )

        return findings

    def check_job_timeout(
        self, job_id: str, job: Dict[str, Any], file_path: str, min_steps: int = 5
    ) -> List[Finding]:
        """
        Check if the job has a timeout set

        Args:
            job_id: Job identifier
            job: Job data as a dictionary
            file_path: Path to the workflow file
            min_steps: Minimum number of steps before requiring a timeout

        Returns:
            List of findings
        """
        findings = []

        steps = job.get("steps", [])
        if "timeout-minutes" not in job and len(steps) >= min_steps:
            findings.append(
                self.create_finding(
                    message=f"Job '{job_id}' has {len(steps)} steps but no timeout-minutes set",
                    file_path=file_path,
                    remediation=f"Add 'timeout-minutes: 15' to job '{job_id}'",
                    can_fix=True,
                )
            )

        return findings

    def check_job_runner(self, job_id: str, job: Dict[str, Any], file_path: str) -> List[Finding]:
        """
        Check if the job specifies a runner

        Args:
            job_id: Job identifier
            job: Job data as a dictionary
            file_path: Path to the workflow file

        Returns:
            List of findings
        """
        findings = []

        runs_on = job.get("runs-on", "")

        if not runs_on:
            findings.append(
                self.create_finding(
                    message=f"Missing 'runs-on' in job '{job_id}'",
                    file_path=file_path,
                    remediation="Specify a runner, e.g., 'runs-on: ubuntu-latest'",
                    can_fix=True,
                )
            )
        elif runs_on == "self-hosted":
            findings.append(
                self.create_finding(
                    message=f"Job '{job_id}' uses self-hosted runner without labels",
                    file_path=file_path,
                    remediation=(
                        "Add specific labels to self-hosted runners for better security isolation"
                    ),
                    can_fix=False,
                )
            )
        elif isinstance(runs_on, list) and "self-hosted" in runs_on:
            findings.append(
                self.create_finding(
                    message=f"Job '{job_id}' uses self-hosted runner",
                    file_path=file_path,
                    remediation=(
                        "Consider using GitHub-hosted runners for better security isolation"
                    ),
                    can_fix=False,
                    severity="LOW" if len(runs_on) > 1 else self.severity,
                )
            )

        return findings


class StepRule(Rule):
    """Base class for rules that check step-level issues"""

    def check_step_shell(
        self, job_id: str, step_idx: int, step: Dict[str, Any], file_path: str
    ) -> List[Finding]:
        """
        Check if a step with a multiline script has a shell specified

        Args:
            job_id: Job identifier
            step_idx: Step index (0-based)
            step: Step data as a dictionary
            file_path: Path to the workflow file

        Returns:
            List of findings
        """
        findings = []

        if (
            "run" in step
            and isinstance(step["run"], str)
            and "\n" in step["run"]
            and "shell" not in step
        ):
            findings.append(
                self.create_finding(
                    message=(
                        f"Multiline script in job '{job_id}' step {step_idx+1} "
                        "has no shell specified"
                    ),
                    file_path=file_path,
                    remediation="Add 'shell: bash' to this step",
                    can_fix=True,
                )
            )

        return findings

    def check_step_action_pinning(
        self, job_id: str, step_idx: int, step: Dict[str, Any], file_path: str
    ) -> List[Finding]:
        """
        Check if the step's action is pinned to a specific version

        Args:
            job_id: Job identifier
            step_idx: Step index (0-based)
            step: Step data as a dictionary
            file_path: Path to the workflow file

        Returns:
            List of findings
        """
        findings = []

        if "uses" in step:
            action = step["uses"]

            if re.search(r"@(main|master)$", action):
                findings.append(
                    self.create_finding(
                        message=(
                            f"Step {step_idx+1} in job '{job_id}' uses unstable reference: {action}"
                        ),
                        file_path=file_path,
                        remediation="Pin the action to a specific commit SHA",
                        can_fix=False,
                        severity="HIGH",  # Unstable references are high risk
                    )
                )

            # Consider an action pinned only if it references a 39 or 40
            # character commit SHA. The previous implementation required 40
            # characters exactly which caused some legitimately pinned actions
            # to be flagged if the SHA length differed.
            elif not re.search(r"@[0-9a-fA-F]{39,40}$", action):
                findings.append(
                    self.create_finding(
                        message=(
                            f"Step {step_idx+1} in job '{job_id}' is not pinned to a specific "
                            f"commit SHA: {action}"
                        ),
                        file_path=file_path,
                        remediation="Pin to a specific commit SHA for better security",
                        can_fix=False,
                    )
                )

        return findings


class TriggerRule(Rule):
    """Base class for rules that check workflow trigger issues"""

    def check_high_risk_triggers(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """
        Check for high-risk workflow triggers

        Args:
            workflow: Workflow data as a dictionary
            file_path: Path to the workflow file

        Returns:
            List of findings
        """
        findings = []
        high_risk_triggers = {"pull_request_target", "workflow_run"}

        on_section = workflow.get("on", {})
        triggers = set()

        if isinstance(on_section, dict):
            triggers = set(on_section.keys())
        elif isinstance(on_section, list):
            triggers = set(on_section)

        high_risk_triggers_used = triggers.intersection(high_risk_triggers)
        for trigger in high_risk_triggers_used:
            findings.append(
                self.create_finding(
                    message=f"High-risk workflow trigger: '{trigger}'",
                    file_path=file_path,
                    remediation=(
                        f"Use '{trigger}' trigger with caution. It runs with "
                        "repository access token and secrets access."
                    ),
                    can_fix=False,
                )
            )

        return findings


class TokenRule(Rule):
    """Base class for rules that check token and secret usage"""

    def check_hardcoded_tokens(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """
        Check for hardcoded tokens in the workflow

        Args:
            workflow: Workflow data as a dictionary
            file_path: Path to the workflow file

        Returns:
            List of findings
        """
        findings = []

        workflow_str = str(workflow)

        token_patterns = [
            (r'token\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Hardcoded token"),
            (r"token\s+[A-Za-z0-9_\-]{20,}", "Hardcoded token"),
            (
                r'api[_\-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
                "Hardcoded API key",
            ),
            (
                r'auth[_\-]?token\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
                "Hardcoded auth token",
            ),
            (r'password\s*[:=]\s*["\']([^"\']{8,})["\']', "Hardcoded password"),
            (r'secret\s*[:=]\s*["\']([^"\']{8,})["\']', "Hardcoded secret"),
            (
                r'access[_\-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
                "Hardcoded access key",
            ),
            (
                r'gh[_\-]?token\s*[:=]\s*["\']([A-Za-z0-9_\-]{30,})["\']',
                "Hardcoded GitHub token",
            ),
        ]

        for pattern, desc in token_patterns:
            matches = re.finditer(pattern, workflow_str, re.IGNORECASE)
            for match in matches:
                context_before = workflow_str[max(0, match.start() - 30) : match.start()]
                if (
                    "secrets." in context_before
                    or "${{" in context_before
                    and "secrets." in context_before
                ):
                    continue

                findings.append(
                    self.create_finding(
                        message=f"{desc} found in workflow file",
                        file_path=file_path,
                        remediation=(
                            "Replace hardcoded tokens with secrets, e.g., "
                            "${{ secrets.GITHUB_TOKEN }}"
                        ),
                        can_fix=False,
                    )
                )

        if "toJson(secrets)" in workflow_str:
            findings.append(
                self.create_finding(
                    message="Dangerous 'toJson(secrets)' usage exposes all secrets",
                    file_path=file_path,
                    remediation=(
                        "Never use toJson(secrets), reference individual secrets explicitly"
                    ),
                    can_fix=False,
                    severity="CRITICAL",
                )
            )

        return findings
