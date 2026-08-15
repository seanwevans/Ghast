"""
suppressions.py - Inline ignore comments and baseline files

Without a way to accept a known finding, a repository with any existing issues
cannot turn ghast into a blocking check: the first run is red and stays red.
That is the population most likely to need the scanner.

Two mechanisms, for two different situations:

* **Inline comments** annotate a specific line that is intentionally the way it
  is. The justification lives next to the code it explains.
* **A baseline file** records everything currently outstanding, so a repository
  can gate on *new* findings today and burn down the rest over time.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Set, Tuple

if TYPE_CHECKING:  # pragma: no cover - import cycle; scanner imports this module
    from .scanner import Finding

#: ``# ghast: ignore`` suppresses every rule on the line.
#: ``# ghast: ignore[timeout, action_pinning]`` suppresses only those rules.
#: An optional trailing ``-- reason`` is preserved for humans, not parsed.
IGNORE_COMMENT = re.compile(
    r"#\s*ghast:\s*ignore(?:\[(?P<rules>[^\]]*)\])?",
    re.IGNORECASE,
)

#: ``# ghast: ignore-file`` suppresses the whole file. Same optional rule list.
IGNORE_FILE_COMMENT = re.compile(
    r"#\s*ghast:\s*ignore-file(?:\[(?P<rules>[^\]]*)\])?",
    re.IGNORECASE,
)

#: Sentinel meaning "every rule", used when a directive names none.
ALL_RULES = "*"

BASELINE_VERSION = 1


def _parse_rule_list(raw: Optional[str]) -> Set[str]:
    """Turn a bracketed rule list into a set, or ALL_RULES when absent."""
    if raw is None:
        return {ALL_RULES}

    rules = {rule.strip() for rule in raw.split(",") if rule.strip()}
    return rules or {ALL_RULES}


@dataclass
class FileSuppressions:
    """Ignore directives found in one workflow file."""

    #: Rules suppressed for the entire file.
    file_level: Set[str] = field(default_factory=set)
    #: Rules suppressed per line number (1-based).
    by_line: Dict[int, Set[str]] = field(default_factory=dict)

    def suppresses(self, rule_id: str, line_number: Optional[int]) -> bool:
        """Whether a finding for ``rule_id`` at ``line_number`` is suppressed."""
        if self._matches(self.file_level, rule_id):
            return True

        if line_number is None:
            # Findings without a position cannot be pinned to a line; only a
            # file-level directive can silence them.
            return False

        return self._matches(self.by_line.get(line_number, set()), rule_id)

    @staticmethod
    def _matches(rules: Set[str], rule_id: str) -> bool:
        return bool(rules) and (ALL_RULES in rules or rule_id in rules)


def _is_standalone_comment(line: str) -> bool:
    """Whether a line is only a comment, with no YAML content before the ``#``."""
    return line.lstrip().startswith("#")


def _next_content_line(lines: List[str], start: int) -> Optional[int]:
    """Find the next line that carries YAML content, 1-based.

    Args:
        lines: All lines of the document.
        start: Zero-based index to search after.

    Returns:
        The 1-based line number, or None if the file ends first.
    """
    for offset in range(start + 1, len(lines)):
        candidate = lines[offset]
        if candidate.strip() and not _is_standalone_comment(candidate):
            return offset + 1
    return None


def parse_suppressions(source: str) -> FileSuppressions:
    """Extract ghast ignore directives from a workflow's raw text.

    A directive written as a trailing comment applies to its own line::

        - uses: actions/checkout@v3  # ghast: ignore[action_pinning]

    A directive on a line of its own applies to the next line with content,
    so a longer justification can sit above what it explains::

        # ghast: ignore[action_pinning] -- vendored, tracked in #42
        - uses: actions/checkout@v3

    Making a trailing comment apply to the following line as well would let a
    single annotation silence the step after it, which is how one intended
    suppression quietly becomes two.

    Args:
        source: The file's text. Comments are read from the raw source because
            the YAML parser discards them.

    Returns:
        The directives found, indexed by the line they apply to.
    """
    suppressions = FileSuppressions()
    lines = source.splitlines()

    for index, line in enumerate(lines):
        file_match = IGNORE_FILE_COMMENT.search(line)
        if file_match is not None:
            suppressions.file_level |= _parse_rule_list(file_match.group("rules"))
            continue

        line_match = IGNORE_COMMENT.search(line)
        if line_match is None:
            continue

        rules = _parse_rule_list(line_match.group("rules"))

        if _is_standalone_comment(line):
            target = _next_content_line(lines, index)
            if target is None:
                continue
        else:
            target = index + 1

        suppressions.by_line.setdefault(target, set()).update(rules)

    return suppressions


def load_suppressions(file_path: str) -> FileSuppressions:
    """Read ignore directives from a workflow file, tolerating read errors."""
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return parse_suppressions(handle.read())
    except OSError:
        # An unreadable file is the scanner's problem to report, not this
        # module's; returning no suppressions keeps every finding visible.
        return FileSuppressions()


def apply_suppressions(
    findings: Iterable[Finding], suppressions: FileSuppressions
) -> Tuple[List[Finding], int]:
    """Filter findings against a file's inline directives.

    Returns:
        Tuple of (kept findings, number suppressed).
    """
    all_findings = list(findings)
    kept = [
        finding
        for finding in all_findings
        if not suppressions.suppresses(finding.rule_id, finding.line_number)
    ]
    return kept, len(all_findings) - len(kept)


def finding_fingerprint(finding: Finding, repo_path: Optional[str] = None) -> str:
    """Compute a stable identity for a finding.

    Deliberately excludes the line number, so reformatting a workflow or
    editing an unrelated part of it does not invalidate every baseline entry
    in the file. The rule, the path, and the message — which names the job and
    step — identify the finding.

    This is stable against line movement but not against renumbering: messages
    for step-indexed rules embed the step number, so inserting a step *above*
    an existing finding changes its fingerprint and it will be reported as
    new. Regenerating the baseline is the remedy.

    Args:
        finding: The finding to fingerprint.
        repo_path: Scan root, used to make the recorded path relative so a
            baseline is portable between checkouts.

    Returns:
        A 16-character hex digest.
    """
    payload = "\0".join(
        [finding.rule_id, _relative_path(finding.file_path, repo_path), finding.message]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _relative_path(file_path: str, repo_path: Optional[str]) -> str:
    """Express a path relative to the scan root, using forward slashes."""
    if repo_path:
        try:
            file_path = os.path.relpath(file_path, repo_path)
        except ValueError:
            # Different drives on Windows; the absolute path is the best we
            # can do and is still stable within one checkout.
            pass
    return file_path.replace(os.sep, "/")


def build_baseline(findings: Iterable[Finding], repo_path: Optional[str] = None) -> Dict[str, Any]:
    """Build a baseline document recording every given finding."""
    entries: Dict[str, Any] = {}

    for finding in findings:
        entries[finding_fingerprint(finding, repo_path)] = {
            "rule_id": finding.rule_id,
            "file": _relative_path(finding.file_path, repo_path),
            "severity": finding.severity,
            "message": finding.message,
        }

    return {
        "version": BASELINE_VERSION,
        "generated": datetime.now(timezone.utc).isoformat(),
        "findings": entries,
    }


class BaselineError(Exception):
    """Raised when a baseline file cannot be read or understood."""


def load_baseline(baseline_path: str) -> Set[str]:
    """Load the fingerprints recorded in a baseline file.

    Raises:
        BaselineError: If the file is missing, not JSON, or not a baseline.
    """
    try:
        with open(baseline_path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError:
        raise BaselineError(f"Baseline file not found: {baseline_path}")
    except json.JSONDecodeError as error:
        raise BaselineError(f"Baseline file is not valid JSON: {error}")
    except OSError as error:
        raise BaselineError(f"Could not read baseline file: {error}")

    if not isinstance(document, dict) or "findings" not in document:
        raise BaselineError(
            f"{baseline_path} is not a ghast baseline. "
            "Generate one with 'ghast baseline <path> --output <file>'."
        )

    version = document.get("version")
    if version != BASELINE_VERSION:
        raise BaselineError(
            f"Baseline version {version!r} is not supported (expected {BASELINE_VERSION}). "
            "Regenerate it with 'ghast baseline'."
        )

    findings = document["findings"]
    if not isinstance(findings, dict):
        raise BaselineError("Baseline 'findings' must be an object keyed by fingerprint")

    return set(findings)


def apply_baseline(
    findings: Iterable[Finding], fingerprints: Set[str], repo_path: Optional[str] = None
) -> Tuple[List[Finding], int]:
    """Drop findings already recorded in a baseline.

    Returns:
        Tuple of (new findings, number suppressed).
    """
    kept: List[Finding] = []
    suppressed = 0

    for finding in findings:
        if finding_fingerprint(finding, repo_path) in fingerprints:
            suppressed += 1
        else:
            kept.append(finding)

    return kept, suppressed
