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
        description: Rule description
        help_text: Rule help text

    Returns:
        SARIF rule definition
    """
    sarif_rule = {
        "id": rule_id,
        "shortDescription": {"text": description or f"Rule {rule_id}"},
        "properties": {"security-severity": str(SECURITY_SEVERITY_SCORES.get(severity, 5.0))},
    }

    if help_text:
        sarif_rule["helpText"] = {"text": help_text}

    if description:
        sarif_rule["fullDescription"] = {"text": description}

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
        "level": severity_to_sarif_level(finding.severity),
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

    if finding.remediation:
        result["fixes"] = [{"description": {"text": finding.remediation}}]

    result["properties"] = {"severity": finding.severity}

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

    for finding in findings:
        if finding.rule_id not in rules_dict:
            rule = rule_to_sarif_rule(
                finding.rule_id,
                finding.severity,
                description=finding.message,
                help_text=finding.remediation,
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
        finding_hash = hashlib.md5(hash_input.encode("utf-8")).hexdigest()

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
