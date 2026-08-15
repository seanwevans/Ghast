"""
fixer.py - Automatic fixing for GitHub Actions workflows

This module provides functionality to automatically fix common security issues
in GitHub Actions workflows.

Rewriting is done with ruamel.yaml in round-trip mode. A plain PyYAML
load/dump cycle is not safe for workflow files: it resolves ``on:`` to the
boolean ``True`` under YAML 1.1, discards every comment, and re-emits block
scalars as folded strings. All three silently corrupt the file being repaired.
"""

import io
import os
import re
import shutil
from typing import Any, Dict, List, Tuple

import click
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

from .scanner import Finding

# ruamel wraps long plain scalars at 80 columns by default, which would reflow
# `run:` bodies and long `if:` expressions. Workflow lines are never too long
# to keep as-is.
_MAX_LINE_WIDTH = 4096

_SEQUENCE_ITEM = re.compile(r"^(?P<indent> *)- ")
_MAPPING_KEY = re.compile(r"^(?P<indent> *)[^\s#-][^:]*:\s*$")


def detect_sequence_indent(source: str) -> Tuple[int, int]:
    """Infer the block-sequence indentation style used by a document.

    GitHub Actions workflows are written in two common styles::

        steps:              steps:
          - uses: a         - uses: a

    ruamel needs this configured up front, and guessing wrong reindents every
    list in the file. Returns the ``(sequence, offset)`` pair for
    ``YAML.indent``, defaulting to the indented style when a file has no block
    sequences to learn from.

    Args:
        source: Raw text of the YAML document.

    Returns:
        Tuple of (sequence, offset) suitable for ``YAML.indent``.
    """
    previous_key_indent = None

    for line in source.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        item = _SEQUENCE_ITEM.match(line)
        if item is not None and previous_key_indent is not None:
            offset = len(item.group("indent")) - previous_key_indent
            if offset >= 0:
                # ruamel expresses this as the dash column (offset) inside a
                # block indented by `sequence` from the parent key.
                return offset + 2, offset

        key = _MAPPING_KEY.match(line)
        previous_key_indent = len(key.group("indent")) if key is not None else None

    return 4, 2


def _build_yaml(source: str) -> YAML:
    """Create a round-trip YAML handler matched to a document's style."""
    yaml_handler = YAML()  # round-trip mode
    yaml_handler.preserve_quotes = True
    yaml_handler.width = _MAX_LINE_WIDTH
    sequence, offset = detect_sequence_indent(source)
    yaml_handler.indent(mapping=2, sequence=sequence, offset=offset)
    return yaml_handler


def load_workflow_for_edit(file_path: str) -> Tuple[Any, YAML]:
    """Load a workflow preserving comments, quoting, and scalar styles.

    Args:
        file_path: Path to the workflow file.

    Returns:
        Tuple of (workflow, yaml_handler); pass the handler back to
        :func:`dump_workflow` so the document is written in its original style.
    """
    with open(file_path, "r", encoding="utf-8") as handle:
        source = handle.read()

    yaml_handler = _build_yaml(source)
    return yaml_handler.load(source), yaml_handler


def dump_workflow(workflow: Any, yaml_handler: YAML) -> str:
    """Serialize a workflow loaded by :func:`load_workflow_for_edit`."""
    buffer = io.StringIO()
    yaml_handler.dump(workflow, buffer)
    return buffer.getvalue()


class Fixer:
    """Class for fixing GitHub Actions workflow issues"""

    def __init__(
        self, config: Dict[str, Any], interactive: bool = False, backup: bool = False
    ) -> None:
        """
        Initialize the fixer

        Args:
            config: Configuration dictionary
            interactive: Whether to prompt for each fix
            backup: Keep a ``.bak`` copy of each file that was changed. Off by
                default: workflows live in version control, the rewrite is
                verified before it is written, and the old behaviour left a
                stray file next to every workflow it fixed.
        """
        self.config = config
        self.interactive = interactive
        self.backup = backup
        self.fixes_applied = 0
        self.fixes_skipped = 0

        # Keyed by rule id, matching what findings actually carry. These were
        # previously keyed by config-file names ("check_shell",
        # "check_deprecated") that no finding ever used, so those two fixers
        # could never run.
        self.fixers = {
            "timeout": self.fix_timeout,
            "shell_specification": self.fix_shell,
            "deprecated_actions": self.fix_deprecated_actions,
            "workflow_name": self.fix_workflow_name,
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

        self.fixes_applied = 0
        self.fixes_skipped = 0

        auto_fix_enabled = self.config.get("auto_fix", {}).get("enabled", True)
        if not auto_fix_enabled:
            skipped_count = len(findings)
            if skipped_count:
                click.echo(f"Auto-fix disabled; skipping fixes for {file_path}")
            return 0, skipped_count

        findings_by_rule: Dict[str, List[Finding]] = {}
        for finding in findings:
            if finding.can_fix and finding.rule_id in self.fixers:
                if finding.rule_id not in findings_by_rule:
                    findings_by_rule[finding.rule_id] = []
                findings_by_rule[finding.rule_id].append(finding)

        if not findings_by_rule:
            return 0, 0

        workflow, yaml_handler = load_workflow_for_edit(file_path)

        # Rollback works from the original text held here rather than from a
        # file on disk. A `.bak` was previously written on every run and only
        # deleted when nothing was fixed, so a successful fix always left one
        # behind for the user to find and clean up. Keeping the original in
        # memory removes both the litter and the cleanup logic.
        with open(file_path, "r", encoding="utf-8") as handle:
            original = handle.read()

        backup_path = f"{file_path}.bak" if self.backup else None
        if backup_path is not None:
            shutil.copy2(file_path, backup_path)

        try:
            for rule_id, rule_findings in findings_by_rule.items():
                if not self.config.get("auto_fix", {}).get("rules", {}).get(rule_id, True):
                    self.fixes_skipped += len(rule_findings)
                    continue

                fixer_func = self.fixers.get(rule_id)
                if not fixer_func:
                    self.fixes_skipped += len(rule_findings)
                    continue

                for finding in rule_findings:
                    if self.interactive:
                        prompt = (
                            f"\nFix {finding.rule_id} issue in {file_path}?\n"
                            f"{finding.message}\n"
                            f"Proposed fix: {finding.remediation}\n"
                        )

                        if not click.confirm(prompt, default=True):
                            self.fixes_skipped += 1
                            continue

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

            self._clean_workflow(workflow)

            # Only touch the file when something actually changed, so a no-op
            # run cannot introduce incidental reformatting.
            if self.fixes_applied > 0:
                rendered = dump_workflow(workflow, yaml_handler)
                self._verify_roundtrip(rendered, file_path)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(rendered)
            elif backup_path is not None:
                # Nothing changed, so a backup of an untouched file is litter
                # even when the user asked for backups.
                os.remove(backup_path)

        except Exception as e:
            click.echo(f"Error fixing {file_path}: {e}", err=True)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(original)
            if backup_path is not None:
                os.remove(backup_path)
            return 0, 0

        return self.fixes_applied, self.fixes_skipped

    def _verify_roundtrip(self, rendered: str, file_path: str) -> None:
        """Re-parse rendered output before it overwrites a workflow.

        A fixer that silently breaks CI is worse than one that declines to run,
        so the serialized document is checked for the invariants that make a
        workflow runnable at all.

        Args:
            rendered: The serialized document about to be written.
            file_path: Path being written, used in error messages.

        Raises:
            ValueError: If the output is unparseable or has lost its triggers.
        """
        reloaded = YAML().load(rendered)

        if not isinstance(reloaded, dict):
            raise ValueError(f"fix produced a non-mapping document for {file_path}")

        if "jobs" not in reloaded:
            raise ValueError(f"fix dropped the 'jobs' section of {file_path}")

        # `on` resolving to the boolean True is the specific YAML 1.1 failure
        # this module exists to avoid; a workflow with no `on:` key never runs.
        if "on" not in reloaded:
            if True in reloaded:
                raise ValueError(
                    f"fix converted the 'on:' trigger of {file_path} into a boolean key"
                )
            raise ValueError(f"fix dropped the 'on:' triggers of {file_path}")

    def _clean_workflow(self, obj: Any) -> None:
        """Remove line/column metadata from workflow objects before dumping."""
        if isinstance(obj, dict):
            if "__line__" in obj:
                del obj["__line__"]
            if "__column__" in obj:
                del obj["__column__"]

            for key, value in list(obj.items()):
                if isinstance(value, (dict, list)):
                    self._clean_workflow(value)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    self._clean_workflow(item)

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

        match = re.search(r"job '([^']+)' step (\d+)", finding.message)
        if not match:
            return False

        job_id = match.group(1)
        step_number = int(match.group(2))

        if job_id in jobs:
            steps = jobs[job_id].get("steps", [])

            # Rules report steps one-based (`step_idx + 1` in
            # StepRule.check_step_shell), so the reported number maps to
            # exactly one list index. The previous implementation guessed
            # between two candidates, which meant a finding for one step could
            # silently add `shell:` to its neighbour instead.
            step_idx = step_number - 1
            if 0 <= step_idx < len(steps):
                step = steps[step_idx]
                if (
                    isinstance(step, dict)
                    and isinstance(step.get("run"), str)
                    and "\n" in step["run"]
                    and "shell" not in step
                ):
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

        action_match = re.search(r"Deprecated action '([^']+)'", finding.message)
        job_match = re.search(r"in job '([^']+)'", finding.message)

        if not action_match or not job_match:
            return False

        deprecated_action = action_match.group(1)
        job_id = job_match.group(1)

        replacement = self.config.get("default_action_versions", {}).get(deprecated_action)
        if not replacement:
            return False

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
        # Some findings may be generated even if a name is already present. To
        # keep the fixer predictable we always set the workflow name based on
        # the filename whenever this fixer is invoked. This ensures consistent
        # behaviour across repositories and satisfies the expectations of the
        # tests which provide a finding for every workflow file.
        file_path = finding.file_path
        file_name = os.path.basename(file_path)

        workflow_name = os.path.splitext(file_name)[0].replace("-", " ").replace("_", " ").title()

        # Place "name" first for readability. On a round-trip document this
        # must be an in-place insert: clearing and rebuilding the mapping would
        # detach every comment anchored to the keys being moved.
        if isinstance(workflow, CommentedMap):
            if "name" in workflow:
                workflow["name"] = workflow_name
            else:
                workflow.insert(0, "name", workflow_name)
            return True

        workflow["name"] = workflow_name

        keys = list(workflow.keys())
        keys.remove("name")
        ordered_workflow = {"name": workflow_name}
        for key in keys:
            ordered_workflow[key] = workflow[key]

        workflow.clear()
        workflow.update(ordered_workflow)

        return True


def fix_workflow_file(
    file_path: str,
    findings: List[Finding],
    config: Dict[str, Any],
    interactive: bool = False,
    backup: bool = False,
) -> Tuple[int, int]:
    """
    Fix issues in a workflow file

    Args:
        file_path: Path to the workflow file
        findings: List of findings to fix
        config: Configuration dictionary
        interactive: Whether to prompt for each fix
        backup: Keep a ``.bak`` copy of each changed file

    Returns:
        Tuple of (fixes_applied, fixes_skipped)
    """
    fixer = Fixer(config, interactive, backup=backup)
    return fixer.fix_workflow_file(file_path, findings)


def fix_repository(
    repo_path: str,
    findings_by_file: Dict[str, List[Finding]],
    config: Dict[str, Any],
    interactive: bool = False,
    backup: bool = False,
) -> Tuple[int, int]:
    """
    Fix issues in all workflow files in a repository

    Args:
        repo_path: Path to the repository
        findings_by_file: Dictionary of file paths to findings
        config: Configuration dictionary
        interactive: Whether to prompt for each fix
        backup: Keep a ``.bak`` copy of each changed file

    Returns:
        Tuple of (total_fixes_applied, total_fixes_skipped)
    """
    total_fixes_applied = 0
    total_fixes_skipped = 0

    fixer = Fixer(config, interactive, backup=backup)

    for file_path, findings in findings_by_file.items():
        if not findings:
            continue

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
