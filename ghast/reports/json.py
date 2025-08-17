"""
json.py - JSON reporting for ghast

This module provides functionality for formatting scanning results as JSON,
suitable for machine processing or integration with other tools.
"""

import json
from datetime import datetime
from typing import Any, Dict, List

from ..core import Finding
from ..utils.version import __version__


def finding_to_dict(finding: Finding) -> Dict[str, Any]:
    """
    Convert a Finding object to a dictionary suitable for JSON serialization

    Args:
        finding: Finding to convert

    Returns:
        Dictionary representation of the finding
    """
    result = {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "message": finding.message,
        "file_path": finding.file_path,
        "can_fix": finding.can_fix,
    }

    if finding.line_number is not None:
        result["line_number"] = finding.line_number
    if finding.column is not None:
        result["column"] = finding.column
    if finding.remediation:
        result["remediation"] = finding.remediation
    if finding.context:
        result["context"] = finding.context

    return result


def generate_json_report(
    findings: List[Finding], stats: Dict[str, Any], include_stats: bool = True
) -> str:
    """
    Generate a JSON report of findings and statistics

    Args:
        findings: List of findings
        stats: Statistics dictionary
        include_stats: Whether to include statistics in the output

    Returns:
        JSON string representation of the report
    """

    findings_data: List[Dict[str, Any]] = [finding_to_dict(finding) for finding in findings]

    report: Dict[str, Any] = {
        "ghast_version": __version__,
        "generated_at": datetime.now().isoformat(),
        "findings": findings_data,
    }

    if include_stats:
        clean_stats: Dict[str, Any] = {}
        for key, value in stats.items():
            if isinstance(value, (str, int, float, bool, list, dict)) or value is None:
                clean_stats[key] = value

        report["stats"] = clean_stats

    return json.dumps(report, indent=2)


def generate_json_summary(stats: Dict[str, Any]) -> str:
    """
    Generate a JSON summary of scan statistics without detailed findings

    Args:
        stats: Statistics dictionary

    Returns:
        JSON string representation of the summary
    """

    summary: Dict[str, Any] = {
        "ghast_version": __version__,
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_files": stats.get("total_files", 0),
            "total_findings": stats.get("total_findings", 0),
            "severity_counts": stats.get("severity_counts", {}),
            "rule_counts": stats.get("rule_counts", {}),
            "fixable_findings": stats.get("fixable_findings", 0),
            "scan_duration_seconds": None,
        },
    }

    start_time = stats.get("start_time")
    end_time = stats.get("end_time")
    if start_time and end_time:
        try:
            start = datetime.fromisoformat(start_time)
            end = datetime.fromisoformat(end_time)
            duration = (end - start).total_seconds()
            summary["summary"]["scan_duration_seconds"] = duration
        except (ValueError, TypeError):
            pass

    return json.dumps(summary, indent=2)


def save_json_report(
    findings: List[Finding],
    stats: Dict[str, Any],
    output_path: str,
    include_stats: bool = True,
) -> None:
    """
    Generate a JSON report and save it to a file

    Args:
        findings: List of findings
        stats: Statistics dictionary
        output_path: Path to save the report to
        include_stats: Whether to include statistics in the output

    Raises:
        IOError: If the file cannot be written
    """
    report = generate_json_report(findings, stats, include_stats)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)
