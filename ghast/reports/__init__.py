"""
reports package for ghast - GitHub Actions Security Tool

This package contains reporting functionality for presenting scan results
in various formats including console, JSON, SARIF, and HTML.
"""

from .report import generate_report, save_report, print_report, generate_full_report

from .console import (
    format_console_report,
    print_console_report,
    format_finding,
    format_summary,
)

from .json import generate_json_report, generate_json_summary, save_json_report

from .sarif import (
    generate_sarif_report,
    save_sarif_report,
    generate_sarif_suppression_file,
)

__all__ = [
    "generate_report",
    "save_report",
    "print_report",
    "generate_full_report",
    "format_console_report",
    "print_console_report",
    "format_finding",
    "format_summary",
    "generate_json_report",
    "generate_json_summary",
    "save_json_report",
    "generate_sarif_report",
    "save_sarif_report",
    "generate_sarif_suppression_file",
]
