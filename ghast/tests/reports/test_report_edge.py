"""
test_report_edge.py - Edge-case coverage for report generation

Covers the summary-only JSON path, the invalid-format error, and the
duration-formatting fallbacks when timestamps are malformed.
"""

import json

import pytest

from ghast.reports.console import format_summary
from ghast.reports.json import generate_json_summary
from ghast.reports.report import generate_report


def test_generate_report_summary_only_json(mock_findings, mock_stats):
    output = generate_report(mock_findings, mock_stats, format="json", summary_only=True)
    data = json.loads(output)
    assert "summary" in data


def test_generate_report_invalid_format(mock_findings, mock_stats):
    with pytest.raises(ValueError, match="Invalid report format"):
        generate_report(mock_findings, mock_stats, format="does-not-exist")


def test_json_summary_handles_bad_timestamps():
    stats = {
        "total_findings": 0,
        "severity_counts": {},
        "rule_counts": {},
        "start_time": "not-a-timestamp",
        "end_time": "also-bad",
    }
    # Should not raise despite malformed timestamps; duration stays unset.
    data = json.loads(generate_json_summary(stats))
    assert data["summary"]["scan_duration_seconds"] is None


def test_console_summary_handles_bad_timestamps():
    stats = {
        "total_files": 1,
        "total_findings": 0,
        "severity_counts": {},
        "rule_counts": {"check_timeout": 1},
        "start_time": "bad",
        "end_time": "worse",
    }
    output = format_summary(stats)
    assert "Scan duration" not in output
