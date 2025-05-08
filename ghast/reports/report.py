"""
report.py - Main reporting interface for ghast

This module provides a unified interface for generating reports in different formats.
"""

import os
import sys
from typing import List, Dict, Any, Optional
import io

from ..core import Finding

from .console import format_console_report, print_console_report
from .json import generate_json_report, generate_json_summary
from .sarif import generate_sarif_report


def generate_report(
    findings: List[Finding],
    stats: Dict[str, Any],
    format: str = "text",
    repo_path: str = None,
    verbose: bool = False,
    group_by_severity: bool = False,
    show_remediation: bool = True,
    show_summary: bool = True,
    summary_only: bool = False,
) -> str:
    """
    Generate a report in the specified format

    Args:
        findings: List of findings
        stats: Statistics dictionary
        format: Output format ('text', 'json', 'sarif', 'html')
        repo_path: Repository path (for resolving relative paths)
        verbose: Whether to include additional details
        group_by_severity: Whether to group findings by severity (for text format)
        show_remediation: Whether to include remediation advice
        show_summary: Whether to include summary statistics
        summary_only: Whether to only include summary information

    Returns:
        Generated report as a string

    Raises:
        ValueError: If an invalid format is specified
    """

    if summary_only:
        if format == "json":
            return generate_json_summary(stats)

    if format == "text":
        return format_console_report(
            findings,
            stats,
            verbose=verbose,
            group_by_severity=group_by_severity,
            show_remediation=show_remediation,
            show_summary=show_summary,
        )
    elif format == "json":
        return generate_json_report(findings, stats, include_stats=show_summary)
    elif format == "sarif":
        return generate_sarif_report(findings, stats, repo_root=repo_path)
    elif format == "html":
        return generate_html_report(findings, stats, repo_path)
    else:
        raise ValueError(f"Invalid report format: {format}")


def save_report(
    findings: List[Finding],
    stats: Dict[str, Any],
    output_path: str,
    format: str = "text",
    repo_path: str = None,
    verbose: bool = False,
    group_by_severity: bool = False,
    show_remediation: bool = True,
    show_summary: bool = True,
    summary_only: bool = False,
) -> None:
    """
    Generate a report and save it to a file

    Args:
        findings: List of findings
        stats: Statistics dictionary
        output_path: Path to save the report to
        format: Output format ('text', 'json', 'sarif', 'html')
        repo_path: Repository path (for resolving relative paths)
        verbose: Whether to include additional details
        group_by_severity: Whether to group findings by severity (for text format)
        show_remediation: Whether to include remediation advice
        show_summary: Whether to include summary statistics
        summary_only: Whether to only include summary information

    Raises:
        IOError: If the file cannot be written
        ValueError: If an invalid format is specified
    """

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    report = generate_report(
        findings,
        stats,
        format=format,
        repo_path=repo_path,
        verbose=verbose,
        group_by_severity=group_by_severity,
        show_remediation=show_remediation,
        show_summary=show_summary,
        summary_only=summary_only,
    )

    with open(output_path, "w") as f:
        f.write(report)


def print_report(
    findings: List[Finding],
    stats: Dict[str, Any],
    format: str = "text",
    repo_path: str = None,
    verbose: bool = False,
    group_by_severity: bool = False,
    show_remediation: bool = True,
    show_summary: bool = True,
    summary_only: bool = False,
) -> None:
    """
    Generate a report and print it to stdout

    Args:
        findings: List of findings
        stats: Statistics dictionary
        format: Output format ('text', 'json', 'sarif', 'html')
        repo_path: Repository path (for resolving relative paths)
        verbose: Whether to include additional details
        group_by_severity: Whether to group findings by severity (for text format)
        show_remediation: Whether to include remediation advice
        show_summary: Whether to include summary statistics
        summary_only: Whether to only include summary information

    Raises:
        ValueError: If an invalid format is specified
    """

    if format == "text":
        print_console_report(
            findings,
            stats,
            verbose=verbose,
            group_by_severity=group_by_severity,
            show_remediation=show_remediation,
            show_summary=show_summary,
            output_stream=sys.stdout,
        )
    else:

        report = generate_report(
            findings,
            stats,
            format=format,
            repo_path=repo_path,
            verbose=verbose,
            group_by_severity=group_by_severity,
            show_remediation=show_remediation,
            show_summary=show_summary,
            summary_only=summary_only,
        )
        print(report)


def generate_html_report(
    findings: List[Finding], stats: Dict[str, Any], repo_path: str = None
) -> str:
    """
    Generate an HTML report (placeholder for future implementation)

    Args:
        findings: List of findings
        stats: Statistics dictionary
        repo_path: Repository path

    Returns:
        HTML report as a string
    """

    text_report = format_console_report(
        findings, stats, verbose=True, show_remediation=True, show_summary=True
    )

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ghast Security Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        h1, h2, h3 {{
            color: #2d3748;
        }}
        .critical {{
            color: #e53e3e;
        }}
        .high {{
            color: #dd6b20;
        }}
        .medium {{
            color: #d69e2e;
        }}
        .low {{
            color: #3182ce;
        }}
        pre {{
            background-color: #f7fafc;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        .summary-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        .summary-table th, .summary-table td {{
            border: 1px solid #e2e8f0;
            padding: 8px 12px;
            text-align: left;
        }}
        .summary-table th {{
            background-color: #edf2f7;
        }}
        .finding {{
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 5px;
            border-left: 5px solid #ccc;
        }}
        .finding.critical {{
            border-left-color: #e53e3e;
            background-color: #fff5f5;
        }}
        .finding.high {{
            border-left-color: #dd6b20;
            background-color: #fffaf0;
        }}
        .finding.medium {{
            border-left-color: #d69e2e;
            background-color: #fffff0;
        }}
        .finding.low {{
            border-left-color: #3182ce;
            background-color: #ebf8ff;
        }}
    </style>
</head>
<body>
    <h1>ghast GitHub Actions Security Report</h1>
    
    <h2>Summary</h2>
    <table class="summary-table">
        <tr>
            <th>Total Files</th>
            <td>{stats.get('total_files', 0)}</td>
        </tr>
        <tr>
            <th>Total Findings</th>
            <td>{stats.get('total_findings', 0)}</td>
        </tr>
        <tr>
            <th>Critical</th>
            <td>{stats.get('severity_counts', {}).get('CRITICAL', 0)}</td>
        </tr>
        <tr>
            <th>High</th>
            <td>{stats.get('severity_counts', {}).get('HIGH', 0)}</td>
        </tr>
        <tr>
            <th>Medium</th>
            <td>{stats.get('severity_counts', {}).get('MEDIUM', 0)}</td>
        </tr>
        <tr>
            <th>Low</th>
            <td>{stats.get('severity_counts', {}).get('LOW', 0)}</td>
        </tr>
    </table>
    
    <h2>Findings</h2>
    <pre>{text_report.replace('<', '&lt;').replace('>', '&gt;')}</pre>
</body>
</html>
"""

    return html


def generate_full_report(
    repo_path: str,
    output_format: str = "html",
    output_path: Optional[str] = None,
    verbose: bool = True,
    strict: bool = False,
    config: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Scan a repository and generate a comprehensive report

    Args:
        repo_path: Path to the repository
        output_format: Output format ('text', 'json', 'sarif', 'html')
        output_path: Path to save the report to
        verbose: Whether to include additional details
        strict: Whether to use strict scanning mode
        config: Configuration dictionary

    Returns:
        Generated report as a string

    Raises:
        ValueError: If an invalid format is specified
        IOError: If the file cannot be written
    """

    from ..core import scan_repository

    findings, stats = scan_repository(repo_path, strict=strict, config=config)

    report = generate_report(
        findings,
        stats,
        format=output_format,
        repo_path=repo_path,
        verbose=verbose,
        show_remediation=True,
        show_summary=True,
    )

    if output_path:
        save_report(
            findings,
            stats,
            output_path,
            format=output_format,
            repo_path=repo_path,
            verbose=verbose,
            show_remediation=True,
            show_summary=True,
        )

    return report
