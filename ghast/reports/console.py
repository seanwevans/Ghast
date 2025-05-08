"""
console.py - Console/terminal reporting for ghast

This module provides functionality for formatting and displaying scanning
results in a human-readable format for terminal output.
"""

import os
import sys
from datetime import datetime
from typing import List, Dict, Any, Optional, TextIO
import click

from ..core import Finding, SEVERITY_LEVELS

COLORS = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "green",
    "RESET": "reset",
    "BOLD": "bold",
    "UNDERLINE": "underline",
}


def get_severity_symbol(severity: str) -> str:
    """Get a symbol representing the severity level"""
    if severity == "CRITICAL":
        return "🚨"
    elif severity == "HIGH":
        return "❗"
    elif severity == "MEDIUM":
        return "⚠️"
    elif severity == "LOW":
        return "ℹ️"
    else:
        return "✓"


def colorize(text: str, color: str) -> str:
    """
    Apply color to text if color output is enabled

    Args:
        text: Text to colorize
        color: Color to apply

    Returns:
        Colorized text or original text if color is disabled
    """
    if os.environ.get("NO_COLOR"):
        return text

    return click.style(text, **{color: True})


def format_finding(finding: Finding, verbose: bool = False, show_remediation: bool = True) -> str:
    """
    Format a single finding for console output

    Args:
        finding: Finding to format
        verbose: Whether to include additional details
        show_remediation: Whether to include remediation advice

    Returns:
        Formatted finding as string
    """
    severity = finding.severity
    symbol = get_severity_symbol(severity)

    formatted = f"{symbol} {colorize(severity, COLORS.get(severity, 'reset'))}: {finding.message}\n"
    formatted += f"  Rule: {finding.rule_id}\n"

    file_info = f"  File: {finding.file_path}"
    if finding.line_number is not None:
        file_info += f":{finding.line_number}"
    formatted += f"{file_info}\n"

    if show_remediation and finding.remediation:
        formatted += f"  Remediation: {finding.remediation}\n"

    if verbose and finding.context:
        formatted += "  Context:\n"
        for key, value in finding.context.items():
            formatted += f"    - {key}: {value}\n"

    return formatted


def format_findings_by_file(
    findings: List[Finding], verbose: bool = False, show_remediation: bool = True
) -> str:
    """
    Format findings grouped by file

    Args:
        findings: List of findings to format
        verbose: Whether to include additional details
        show_remediation: Whether to include remediation advice

    Returns:
        Formatted findings as string
    """
    if not findings:
        return "No issues found."

    findings_by_file = {}
    for finding in findings:
        if finding.file_path not in findings_by_file:
            findings_by_file[finding.file_path] = []
        findings_by_file[finding.file_path].append(finding)

    output = ""
    for file_path, file_findings in findings_by_file.items():
        output += f"\n{colorize('File: ' + file_path, 'bold')}\n"

        findings_by_severity = {}
        for level in SEVERITY_LEVELS:
            findings_by_severity[level] = [f for f in file_findings if f.severity == level]

        for level in SEVERITY_LEVELS:
            level_findings = findings_by_severity[level]
            if not level_findings:
                continue

            for finding in level_findings:
                output += format_finding(finding, verbose, show_remediation) + "\n"

    return output


def format_findings_by_severity(
    findings: List[Finding], verbose: bool = False, show_remediation: bool = True
) -> str:
    """
    Format findings grouped by severity

    Args:
        findings: List of findings to format
        verbose: Whether to include additional details
        show_remediation: Whether to include remediation advice

    Returns:
        Formatted findings as string
    """
    if not findings:
        return "No issues found."

    findings_by_severity = {}
    for level in SEVERITY_LEVELS:
        findings_by_severity[level] = [f for f in findings if f.severity == level]

    output = ""
    for level in SEVERITY_LEVELS:
        level_findings = findings_by_severity[level]
        if not level_findings:
            continue

        output += f"\n{colorize(f'{level} Severity Issues ({len(level_findings)})', COLORS.get(level, 'reset'))}\n"
        output += "=" * 50 + "\n"

        for finding in level_findings:
            output += format_finding(finding, verbose, show_remediation) + "\n"

    return output


def format_summary(stats: Dict[str, Any]) -> str:
    """
    Format summary statistics

    Args:
        stats: Statistics dictionary

    Returns:
        Formatted summary as string
    """
    output = f"\n{colorize('Scan Summary', 'bold')}\n"
    output += "=" * 50 + "\n"

    output += f"Total files scanned: {stats.get('total_files', 0)}\n"
    output += f"Total issues found: {stats.get('total_findings', 0)}\n"

    output += "\nIssues by severity:\n"
    for level in SEVERITY_LEVELS:
        count = stats.get("severity_counts", {}).get(level, 0)
        if count > 0:
            output += f"  {colorize(level, COLORS.get(level, 'reset'))}: {count}\n"

    if stats.get("rule_counts"):
        output += "\nIssues by rule:\n"
        for rule, count in sorted(
            stats.get("rule_counts", {}).items(), key=lambda x: x[1], reverse=True
        ):
            output += f"  {rule}: {count}\n"

    start_time = stats.get("start_time")
    end_time = stats.get("end_time")
    if start_time and end_time:
        try:
            start = datetime.fromisoformat(start_time)
            end = datetime.fromisoformat(end_time)
            duration = (end - start).total_seconds()
            output += f"\nScan duration: {duration:.2f} seconds\n"
        except (ValueError, TypeError):
            pass

    return output


def format_console_report(
    findings: List[Finding],
    stats: Dict[str, Any],
    verbose: bool = False,
    group_by_severity: bool = False,
    show_remediation: bool = True,
    show_summary: bool = True,
) -> str:
    """
    Generate a complete console report

    Args:
        findings: List of findings
        stats: Statistics dictionary
        verbose: Whether to include additional details
        group_by_severity: Whether to group findings by severity instead of by file
        show_remediation: Whether to include remediation advice
        show_summary: Whether to include summary statistics

    Returns:
        Complete formatted report as string
    """
    output = ""

    if group_by_severity:
        output += format_findings_by_severity(findings, verbose, show_remediation)
    else:
        output += format_findings_by_file(findings, verbose, show_remediation)

    if show_summary:
        output += format_summary(stats)

    return output


def print_console_report(
    findings: List[Finding],
    stats: Dict[str, Any],
    verbose: bool = False,
    group_by_severity: bool = False,
    show_remediation: bool = True,
    show_summary: bool = True,
    output_stream: Optional[TextIO] = None,
) -> None:
    """
    Print console report to output stream

    Args:
        findings: List of findings
        stats: Statistics dictionary
        verbose: Whether to include additional details
        group_by_severity: Whether to group findings by severity instead of by file
        show_remediation: Whether to include remediation advice
        show_summary: Whether to include summary statistics
        output_stream: Output stream to write to (defaults to sys.stdout)
    """
    report = format_console_report(
        findings,
        stats,
        verbose=verbose,
        group_by_severity=group_by_severity,
        show_remediation=show_remediation,
        show_summary=show_summary,
    )

    if output_stream is None:
        output_stream = sys.stdout

    output_stream.write(report)
    output_stream.flush()
