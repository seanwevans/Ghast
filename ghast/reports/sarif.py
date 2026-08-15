"""
sarif.py - SARIF format reporting for ghast

This module provides functionality for formatting scanning results in SARIF
(Static Analysis Results Interchange Format) format, suitable for GitHub
integration and other static analysis tools.

See https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/
sarif-support-for-code-scanning for more information on GitHub's SARIF support.
"""

import hashlib
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, cast

from ..core import Finding
from ..core.scanner import normalize_severity
from ..utils.version import __version__

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

GITHUB_SEVERITY_LEVELS = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

SECURITY_SEVERITY_SCORES = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.0,
    "LOW": 3.0,
    "INFO": 1.0,
}


def severity_to_sarif_level(severity: str) -> str:
    """
    Convert a ghast severity level to a SARIF level

    Args:
        severity: ghast severity level

    Returns:
        SARIF level
    """
    return GITHUB_SEVERITY_LEVELS.get(severity, "warning")


#: Where a reader can go to understand a rule.
RULE_HELP_URI = "https://github.com/seanwevans/ghast#built-in-rules"

#: Namespaced so a future change to the scheme can coexist with old reports.
FINGERPRINT_KEY = "ghast/rule-file-message/v1"


def _rule_metadata() -> Dict[str, Dict[str, str]]:
    """Describe every built-in rule, keyed by rule id.

    Imported lazily: ``ghast.rules`` pulls in ``ghast.core``, and this package
    is imported before it during package initialisation.
    """
    from ..rules.registry import build_default_rules

    return {
        rule.rule_id: {
            "description": rule.description,
            "remediation": rule.remediation,
            "category": rule.category,
        }
        for rule in build_default_rules()
    }


def rule_to_sarif_rule(
    rule_id: str,
    severity: str,
    description: Optional[str] = None,
    help_text: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convert a ghast rule to a SARIF rule

    Args:
        rule_id: Rule ID
        severity: Rule severity
        description: What the rule checks for. This must describe the *rule*,
            not one of its findings: the driver's rule list is shared metadata,
            so putting a single finding's message here labels the rule with
            whichever finding happened to be reported first.
        help_text: Remediation guidance shown alongside the rule.

    Returns:
        SARIF rule definition
    """
    sarif_rule: Dict[str, Any] = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": description or f"Rule {rule_id}"},
        "defaultConfiguration": {"level": severity_to_sarif_level(severity)},
        "helpUri": RULE_HELP_URI,
        "properties": {
            "security-severity": str(SECURITY_SEVERITY_SCORES.get(severity, 5.0)),
            "tags": ["security", "github-actions"],
        },
    }

    if description:
        sarif_rule["fullDescription"] = {"text": description}

    if help_text:
        # `helpText` is not a SARIF property. The spec defines `help`, a
        # multiformatMessageString, and GitHub renders it in the alert body;
        # anything under `helpText` was silently dropped by every consumer.
        sarif_rule["help"] = {"text": help_text}

    return sarif_rule


def finding_to_sarif_result(finding: Finding, repo_root: Optional[str] = None) -> Dict[str, Any]:
    """
    Convert a ghast finding to a SARIF result

    Args:
        finding: Finding to convert
        repo_root: Repository root path for converting absolute paths to relative

    Returns:
        SARIF result
    """

    file_path = finding.file_path
    if repo_root and file_path.startswith(repo_root):
        file_path = os.path.relpath(file_path, repo_root)

    result: Dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": severity_to_sarif_level(normalize_severity(finding.severity)),
        "message": {"text": finding.message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": file_path}}}],
    }

    if finding.line_number is not None:
        locations = cast(List[Dict[str, Any]], result["locations"])
        physical_loc = cast(Dict[str, Any], locations[0]["physicalLocation"])
        physical_loc["region"] = {"startLine": finding.line_number}

        if finding.column is not None:
            region = cast(Dict[str, Any], physical_loc["region"])
            region["startColumn"] = finding.column

    # Lets GitHub Code Scanning track one finding across commits instead of
    # closing and reopening it whenever the file moves. Deliberately the same
    # fingerprint the baseline file uses, so the two agree on identity.
    from ..core.suppressions import finding_fingerprint

    result["partialFingerprints"] = {FINGERPRINT_KEY: finding_fingerprint(finding, repo_root)}

    result["properties"] = {"severity": finding.severity}

    if finding.remediation:
        # Not `fixes`: a SARIF `fix` requires `artifactChanges` describing the
        # edit to apply, and ghast's remediation is prose. Emitting a fix with
        # only a description made the document fail schema validation.
        properties = cast(Dict[str, Any], result["properties"])
        properties["remediation"] = finding.remediation

    if finding.context:
        properties = cast(Dict[str, Any], result["properties"])
        properties["context"] = finding.context

    return result


def generate_sarif_report(
    findings: List[Finding],
    stats: Dict[str, Any],
    repo_root: Optional[str] = None,
    tool_name: str = "ghast",
    tool_version: str = __version__,
) -> str:
    """
    Generate a SARIF report from findings

    Args:
        findings: List of findings
        stats: Statistics dictionary (not directly used in SARIF but useful for metadata)
        repo_root: Repository root path for converting absolute paths to relative
        tool_name: Name of the analysis tool
        tool_version: Version of the analysis tool

    Returns:
        SARIF report as a JSON string
    """

    sarif: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/seanwevans/ghast",
                        "rules": [],
                    }
                },
                "results": [],
                "properties": {
                    "metrics": {
                        "total_findings": stats.get("total_findings", 0),
                        "total_files": stats.get("total_files", 0),
                    }
                },
            }
        ],
    }

    start_time = stats.get("start_time")
    end_time = stats.get("end_time")
    if start_time:
        sarif["runs"][0]["invocations"] = [
            {
                "executionSuccessful": True,
                "startTimeUtc": start_time,
            }
        ]
        if end_time:
            sarif["runs"][0]["invocations"][0]["endTimeUtc"] = end_time

    rules_dict: Dict[str, Dict[str, Any]] = {}
    metadata = _rule_metadata()

    for finding in findings:
        if finding.rule_id not in rules_dict:
            # Prefer the rule's own description over the finding's message.
            # Falling back to the message is only for synthetic ids such as
            # `file_error`, which have no registered rule behind them.
            info = metadata.get(finding.rule_id, {})
            rule = rule_to_sarif_rule(
                finding.rule_id,
                normalize_severity(finding.severity),
                description=info.get("description") or finding.message,
                help_text=info.get("remediation") or finding.remediation,
            )
            rules_dict[finding.rule_id] = rule
            sarif["runs"][0]["tool"]["driver"]["rules"].append(rule)

        result = finding_to_sarif_result(finding, repo_root)
        sarif["runs"][0]["results"].append(result)

    return json.dumps(sarif, indent=2)


def save_sarif_report(
    findings: List[Finding],
    stats: Dict[str, Any],
    output_path: str,
    repo_root: Optional[str] = None,
    tool_name: str = "ghast",
    tool_version: str = __version__,
) -> None:
    """
    Generate a SARIF report and save it to a file

    Args:
        findings: List of findings
        stats: Statistics dictionary
        output_path: Path to save the report to
        repo_root: Repository root path for converting absolute paths to relative
        tool_name: Name of the analysis tool
        tool_version: Version of the analysis tool

    Raises:
        IOError: If the file cannot be written
    """
    report = generate_sarif_report(
        findings,
        stats,
        repo_root=repo_root,
        tool_name=tool_name,
        tool_version=tool_version,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)


def generate_sarif_suppression_file(findings: List[Finding], output_path: str) -> None:
    """
    Generate a SARIF suppressions file from findings

    This creates a file that can be used to suppress specific findings in future scans.

    Args:
        findings: List of findings to suppress
        output_path: Path to save the suppressions file to

    Raises:
        IOError: If the file cannot be written
    """
    suppressions: List[Dict[str, Any]] = []

    for finding in findings:
        hash_input = (
            f"{finding.rule_id}:{finding.file_path}:{finding.line_number or ''}:{finding.message}"
        )
        finding_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()[:32]

        suppression: Dict[str, Any] = {
            "guid": finding_hash,
            "kind": "inSource",
            "justification": "Known issue, suppressed",
            "location": {"physicalLocation": {"artifactLocation": {"uri": finding.file_path}}},
            "properties": {
                "rule_id": finding.rule_id,
                "suppressed_at": datetime.now().isoformat(),
            },
        }

        if finding.line_number is not None:
            location = cast(Dict[str, Any], suppression["location"])
            physical_loc = cast(Dict[str, Any], location["physicalLocation"])
            physical_loc["region"] = {"startLine": finding.line_number}

        suppressions.append(suppression)

    suppressions_file = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": {"name": "ghast", "version": __version__}},
                "suppressions": suppressions,
            }
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(suppressions_file, f, indent=2)
