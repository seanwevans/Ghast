"""
fixer.py - Automatic fixing for GitHub Actions workflows

This module provides functionality to automatically fix common security issues
in GitHub Actions workflows.
"""

import os
import yaml
import re
import tempfile
import shutil
from typing import Dict, Any, List, Tuple, Optional, Callable
import click

from .scanner import Finding


class SafeLoader(yaml.SafeLoader):
    """Custom YAML loader that preserves line numbers"""

    def __init__(self, stream):
        super(SafeLoader, self).__init__(stream)

    def compose_node(self, parent, index):
        """Override to add line information"""
        node = super(SafeLoader, self).compose_node(parent, index)
        node.start_mark.line = self.line
        node.start_mark.column = self.column
        return node


class SafeDumper(yaml.SafeDumper):
    """Custom YAML dumper that preserves formatting"""

    pass


# Add line/column tracking to container nodes
def construct_mapping(self, node, deep=False):
    mapping = super(SafeLoader, self).construct_mapping(node, deep=deep)
    mapping["__line__"] = node.start_mark.line
    mapping["__column__"] = node.start_mark.column
    return mapping


SafeLoader.add_constructor(yaml.resolver.Resolver.DEFAULT_MAPPING_TAG, construct_mapping)


class Fixer:
    """Class for fixing GitHub Actions workflow issues"""

    def __init__(self, config: Dict[str, Any], interactive: bool = False):
        """
        Initialize the fixer

        Args:
            config: Configuration dictionary
            interactive: Whether to prompt for each fix
        """
        self.config = config
        self.interactive = interactive
        self.fixes_applied = 0
        self.fixes_skipped = 0

        # Register fixers keyed by rule_id
        self.fixers = {
            "check_timeout": self.fix_timeout,
            "check_shell": self.fix_shell,
            "check_deprecated": self.fix_deprecated_actions,
            "check_workflow_name": self.fix_workflow_name,
            "check_runs_on": self.fix_runs_on,
        }

    def fix_workflow_file(self, file_path: str, findings: List[Finding]) -> Tuple[int, int]:
        """
        Fix issues in a workflow file

        Args:
            file_path: Path to the workflow file
            findings: List of findings to fix

        Returns:
            Tuple of (fixes_applied, fixes_skipped)
        """
        if not os.path.exists(file_path):
            return 0, 0

        # Reset counters
        self.fixes_applied = 0
        self.fixes_skipped = 0

        # Group findings by rule_id
        findings_by_rule = {}
        for finding in findings:
            if finding.can_fix and finding.rule_id in self.fixers:
                if finding.rule_id not in findings_by_rule:
                    findings_by_rule[finding.rule_id] = []
                findings_by_rule[finding.rule_id].append(finding)

        # If no fixable findings, return early
        if not findings_by_rule:
            return 0, 0

        # Load the workflow with line numbers
        with open(file_path, "r") as f:
            workflow = yaml.load(f, Loader=SafeLoader)

        # Create a backup file
        backup_path = f"{file_path}.bak"
        shutil.copy2(file_path, backup_path)

        # Apply fixes by rule_id
        try:
            for rule_id, rule_findings in findings_by_rule.items():
                # Skip if auto-fix is disabled for this rule
                if not self.config.get("auto_fix", {}).get("rules", {}).get(rule_id, True):
                    self.fixes_skipped += len(rule_findings)
                    continue

                # Get the fixer function for this rule
                fixer_func = self.fixers.get(rule_id)
                if not fixer_func:
                    self.fixes_skipped += len(rule_findings)
                    continue

                # Apply the fixer
                for finding in rule_findings:
                    if self.interactive:
                        if not click.confirm(
                            f"\nFix {finding.rule_id} issue in {file_path}?\n{finding.message}\nProposed fix: {finding.remediation}",
                            default=True,
                        ):
                            self.fixes_skipped += 1
                            continue

                    # Apply the fix
                    try:
                        fixed = fixer_func(workflow, finding)
                        if fixed:
                            self.fixes_applied += 1
                        else:
                            self.fixes_skipped += 1
                    except Exception as e:
                        click.echo(
                            f"Error fixing {finding.rule_id} in {file_path}: {e}",
                            err=True,
                        )
                        self.fixes_skipped += 1

            # Write the updated workflow back to the file
            self._clean_workflow(workflow)
            with open(file_path, "w") as f:
                yaml.dump(
                    workflow,
                    f,
                    Dumper=SafeDumper,
                    sort_keys=False,
                    default_flow_style=False,
                )

            # Remove backup if successful and no fixes applied
            if self.fixes_applied == 0:
                os.remove(backup_path)

        except Exception as e:
            # Restore from backup on error
            click.echo(f"Error fixing {file_path}: {e}", err=True)
            shutil.copy2(backup_path, file_path)
            os.remove(backup_path)
            return 0, 0

        return self.fixes_applied, self.fixes_skipped

    def _clean_workflow(self, obj):
        """Remove line/column tracking info before writing"""
        if isinstance(obj, dict):
            # Remove line and column info
            if "__line__" in obj:
                del obj["__line__"]
            if "__column__" in obj:
                del obj["__column__"]

            # Recursively clean values
            for key, value in list(obj.items()):
                if isinstance(value, (dict, list)):
                    self._clean_workflow(value)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    self._clean_workflow(item)

    # Fixer implementations

    def fix_timeout(self, workflow: Dict[str, Any], finding: Finding) -> bool:
        """
        Fix missing timeout-minutes in jobs

        Args:
            workflow: Workflow dictionary
            finding: Finding to fix

        Returns:
            True if fixed, False otherwise
        """
        jobs = workflow.get("jobs", {})

        # Extract job ID from the finding message
        match = re.search(r"Job '([^']+)'", finding.message)
        if not match:
            return False

        job_id = match.group(1)

        if job_id in jobs:
            job = jobs[job_id]
            job["timeout-minutes"] = self.config.get("default_timeout_minutes", 15)
            return True

        return False

    def fix_shell(self, workflow: Dict[str, Any], finding: Finding) -> bool:
        """
        Fix missing shell in multiline run scripts

        Args:
            workflow: Workflow dictionary
            finding: Finding to fix

        Returns:
            True if fixed, False otherwise
        """
        jobs = workflow.get("jobs", {})

        # Extract job ID and step from the finding message
        match = re.search(r"job '([^']+)' step (\d+)", finding.message)
        if not match:
            return False

        job_id = match.group(1)
        step_idx = int(match.group(2)) - 1  # Convert to 0-based index

        if job_id in jobs:
            steps = jobs[job_id].get("steps", [])
            if 0 <= step_idx < len(steps):
                step = steps[step_idx]
                if "run" in step and "\n" in step["run"] and "shell" not in step:
                    step["shell"] = "bash"
                    return True

        return False

    def fix_deprecated_actions(self, workflow: Dict[str, Any], finding: Finding) -> bool:
        """
        Fix deprecated GitHub Actions

        Args:
            workflow: Workflow dictionary
            finding: Finding to fix

        Returns:
            True if fixed, False otherwise
        """
        jobs = workflow.get("jobs", {})

        # Extract action name and job ID from the finding message
        action_match = re.search(r"Deprecated action '([^']+)'", finding.message)
        job_match = re.search(r"in job '([^']+)'", finding.message)

        if not action_match or not job_match:
            return False

        deprecated_action = action_match.group(1)
        job_id = job_match.group(1)

        # Check if we have a replacement for this action
        replacement = self.config.get("default_action_versions", {}).get(deprecated_action)
        if not replacement:
            return False

        # Find and replace the action
        if job_id in jobs:
            steps = jobs[job_id].get("steps", [])
            for step in steps:
                if isinstance(step, dict) and step.get("uses") == deprecated_action:
                    step["uses"] = replacement
                    return True

        return False

    def fix_workflow_name(self, workflow: Dict[str, Any], finding: Finding) -> bool:
        """
        Fix missing workflow name

        Args:
            workflow: Workflow dictionary
            finding: Finding to fix

        Returns:
            True if fixed, False otherwise
        """
        if "name" not in workflow:
            # Generate a name based on the file path
            file_path = finding.file_path
            file_name = os.path.basename(file_path)

            # Remove extension and convert to title case
            workflow_name = (
                os.path.splitext(file_name)[0].replace("-", " ").replace("_", " ").title()
            )

            workflow["name"] = workflow_name

            # Make sure name comes first in the YAML
            keys = list(workflow.keys())
            keys.remove("name")
            ordered_workflow = {"name": workflow_name}
            for key in keys:
                ordered_workflow[key] = workflow[key]

            # Update the workflow in-place
            workflow.clear()
            workflow.update(ordered_workflow)

            return True

        return False

    def fix_runs_on(self, workflow: Dict[str, Any], finding: Finding) -> bool:
        """
        Fix missing or ambiguous runs-on

        Args:
            workflow: Workflow dictionary
            finding: Finding to fix

        Returns:
            True if fixed, False otherwise
        """
        jobs = workflow.get("jobs", {})

        # Extract job ID from the finding message
        match = re.search(r"job '([^']+)'", finding.message)
        if not match:
            return False

        job_id = match.group(1)

        if job_id in jobs:
            job = jobs[job_id]

            # Only fix missing runs-on, not self-hosted runners
            if "runs-on" not in job:
                job["runs-on"] = "ubuntu-latest"
                return True

        return False


def fix_workflow_file(
    file_path: str,
    findings: List[Finding],
    config: Dict[str, Any],
    interactive: bool = False,
) -> Tuple[int, int]:
    """
    Fix issues in a workflow file

    Args:
        file_path: Path to the workflow file
        findings: List of findings to fix
        config: Configuration dictionary
        interactive: Whether to prompt for each fix

    Returns:
        Tuple of (fixes_applied, fixes_skipped)
    """
    fixer = Fixer(config, interactive)
    return fixer.fix_workflow_file(file_path, findings)


def fix_repository(
    repo_path: str,
    findings_by_file: Dict[str, List[Finding]],
    config: Dict[str, Any],
    interactive: bool = False,
) -> Tuple[int, int]:
    """
    Fix issues in all workflow files in a repository

    Args:
        repo_path: Path to the repository
        findings_by_file: Dictionary of file paths to findings
        config: Configuration dictionary
        interactive: Whether to prompt for each fix

    Returns:
        Tuple of (total_fixes_applied, total_fixes_skipped)
    """
    total_fixes_applied = 0
    total_fixes_skipped = 0

    fixer = Fixer(config, interactive)

    for file_path, findings in findings_by_file.items():
        if not findings:
            continue

        # Only consider fixable findings
        fixable_findings = [f for f in findings if f.can_fix and f.rule_id in fixer.fixers]
        if not fixable_findings:
            continue

        click.echo(f"\nFixing issues in {file_path}...")
        fixes_applied, fixes_skipped = fixer.fix_workflow_file(file_path, fixable_findings)

        total_fixes_applied += fixes_applied
        total_fixes_skipped += fixes_skipped

        if fixes_applied > 0:
            click.echo(f"✅ Applied {fixes_applied} fix(es) to {file_path}")
        if fixes_skipped > 0:
            click.echo(f"⚠️ Skipped {fixes_skipped} fix(es) in {file_path}")

    return total_fixes_applied, total_fixes_skipped
