"""
discovery.py - Finding the files ghast should scan

Target discovery was open-coded in four places (`WorkflowScanner.scan_directory`,
`scan_repository`, and both CLI paths), each globbing
``<root>/.github/workflows/*.y*ml`` slightly differently. That both duplicated
the rule and made it impossible to widen in one step.

Two things it could not reach:

* A bare directory of workflow files. ``ghast scan ./workflows`` failed with
  "No workflows found" unless the directory happened to be a repository root.
* Composite actions. An ``action.yml`` runs steps with the same
  supply-chain exposure as a workflow — unpinned `uses`, unspecified shells,
  untrusted interpolation — and none of it was ever looked at.
"""

from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional

#: Directories that never contain a repository's own workflows, and which are
#: expensive to walk. Vendored actions belong to their upstream, not here.
SKIP_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "site-packages",
    "venv",
}

YAML_SUFFIXES = (".yml", ".yaml")


class TargetKind(Enum):
    """What sort of file a target is, which decides how it is interpreted."""

    WORKFLOW = "workflow"
    ACTION = "action"


class ScanTarget(NamedTuple):
    """A file to scan, and how to read it."""

    path: Path
    kind: TargetKind


def is_action_definition(content: Any) -> bool:
    """Whether parsed YAML looks like an action definition rather than a workflow.

    Actions declare ``runs``; workflows declare ``on`` and ``jobs``.
    """
    return (
        isinstance(content, dict)
        and isinstance(content.get("runs"), dict)
        and "jobs" not in content
    )


def adapt_action_to_workflow(action: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Present a composite action's steps in the shape the step rules expect.

    Step-level rules — action pinning, shell specification, command injection,
    deprecated actions — apply to an action's steps unchanged. Rather than
    teaching each rule a second schema, the steps are presented as a
    single-job workflow so every existing rule works as written.

    Workflow-level concepts have no analogue in an action: an action declares
    no triggers, holds no permissions, and cannot set a job timeout. Those
    rules are filtered out by the caller rather than fabricated here.

    Args:
        action: Parsed contents of an ``action.yml``.

    Returns:
        A synthetic workflow, or None if the action runs no steps (a
        JavaScript or Docker action, which has no step surface to check).
    """
    runs = action.get("runs")
    if not isinstance(runs, dict):
        return None

    steps = runs.get("steps")
    if not isinstance(steps, list):
        return None

    return {"on": "action", "jobs": {"runs": {"steps": steps}}}


#: Rules that describe a workflow, and have no meaning for an action file.
WORKFLOW_ONLY_RULES = frozenset(
    {
        "permissions",
        "poisoned_pipeline_execution",
        "timeout",
        "workflow_name",
        "reusable_workflow_inputs",
        "environment_injection",
    }
)


def _is_yaml(path: Path) -> bool:
    return path.suffix in YAML_SUFFIXES


def _iter_action_files(root: Path) -> List[Path]:
    """Find composite action definitions beneath a repository root."""
    found: List[Path] = []
    stack = [root]

    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue

        for entry in entries:
            if entry.is_dir():
                if entry.name not in SKIP_DIRECTORIES:
                    stack.append(entry)
            elif entry.name in ("action.yml", "action.yaml"):
                found.append(entry)

    return found


def discover_targets(path: str, include_actions: bool = True) -> List[ScanTarget]:
    """Find everything ghast should scan under a path.

    Accepts a repository root, a bare directory of YAML files, or a single
    file. A repository root is anything containing ``.github/workflows``.

    Args:
        path: What the user asked to scan.
        include_actions: Whether to include composite action definitions.

    Returns:
        Targets in a stable order: workflows first, then actions, each sorted
        by path so output does not depend on filesystem iteration order.
    """
    root = Path(path)

    if root.is_file():
        kind = (
            TargetKind.ACTION if root.name in ("action.yml", "action.yaml") else TargetKind.WORKFLOW
        )
        return [ScanTarget(root, kind)]

    if not root.is_dir():
        return []

    workflow_dir = root / ".github" / "workflows"
    targets: List[ScanTarget] = []

    if workflow_dir.is_dir():
        targets.extend(
            ScanTarget(p, TargetKind.WORKFLOW)
            for p in sorted(workflow_dir.iterdir())
            if p.is_file() and _is_yaml(p)
        )
        if include_actions:
            targets.extend(
                ScanTarget(p, TargetKind.ACTION) for p in sorted(_iter_action_files(root))
            )
        return targets

    # Not a repository root: treat it as a plain directory of YAML files, so
    # `ghast scan ./workflows` works instead of reporting nothing found.
    return [
        ScanTarget(p, TargetKind.ACTION if p.name.startswith("action.") else TargetKind.WORKFLOW)
        for p in sorted(root.iterdir())
        if p.is_file() and _is_yaml(p)
    ]
