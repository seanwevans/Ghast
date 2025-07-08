"""
test_html.py - Tests for HTML report generation
"""

from ghast.core import Finding
from ghast.reports.report import generate_html_report


def test_generate_html_report_basic():
    """Test generating a basic HTML report."""
    findings = [
        Finding(
            rule_id="test_rule",
            severity="HIGH",
            message="Test issue",
            file_path="workflow.yml",
        )
    ]
    stats = {
        "total_files": 1,
        "total_findings": 1,
        "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
    }

    html = generate_html_report(findings, stats)

    assert "<html>" in html
    assert "<body>" in html
    assert '<table class="summary-table">' in html
