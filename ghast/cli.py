"""
cli.py - Command-line interface for ghast

This module provides the command-line interface for the ghast tool,
allowing users to scan GitHub Actions workflows for security issues.
"""

import json
import os
import sys
from pathlib import Path
from typing import Optional, Tuple

import click

from .core import (
    WorkflowScanner,
    fix_repository,
    generate_default_config,
    load_config,
    scan_repository,
)
from .reports import generate_full_report, print_report, save_report
from .rules import create_rule_engine
from .utils.banner import _BANNER
from .utils.version import __version__

OUTPUT_FORMATS = ["text", "json", "sarif", "html"]


@click.group(invoke_without_command=True)
@click.version_option(version=__version__)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """ghast ☠ GitHub Actions Security Tool

    A security scanner for GitHub Actions workflows.
    Detects misconfigurations, security vulnerabilities, and provides remediation advice.
    """
    if ctx.invoked_subcommand is None:
        click.echo(_BANNER)
        click.echo("Use `ghast --help` for available commands.")


@cli.command()
@click.argument("repo_path", type=click.Path())
@click.option("--strict", is_flag=True, help="Enable strict mode (extra warnings)")
@click.option("--config", type=click.Path(), help="Path to YAML config file for check settings")
@click.option("--disable", multiple=True, help="Disable specific rule(s)")
@click.option(
    "--output",
    type=click.Choice(OUTPUT_FORMATS),
    default="text",
    help="Output format for results",
)
@click.option(
    "--output-file",
    type=click.Path(),
    help="Write output to file instead of stdout",
)
@click.option(
    "--severity-threshold",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="LOW",
    help="Minimum severity level to report",
)
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option("--verbose", is_flag=True, help="Show detailed information for each finding")
def scan(
    repo_path: str,
    strict: bool,
    config: Optional[str],
    disable: Tuple[str, ...],
    output: str,
    output_file: Optional[str],
    severity_threshold: str,
    no_color: bool,
    verbose: bool,
) -> None:
    """Audit GitHub Actions workflows for security issues (read-only)

    REPO_PATH: Path to the repository root or specific workflow file
    """

    if config:
        config_path = Path(config)
        if not config_path.exists():
            click.echo(f"Error loading config file: {config} not found", err=True)
            sys.exit(1)
        try:
            config_data = load_config(config)
        except Exception as e:
            click.echo(f"Error loading config file: {e}", err=True)
            sys.exit(1)
    else:
        config_data = None

    if no_color:
        os.environ["NO_COLOR"] = "1"

    path = Path(repo_path)
    if path.is_file() and path.suffix in [".yml", ".yaml"]:
        if output == "text":
            click.echo(f"Scanning single workflow file: {path}")
        scanner = WorkflowScanner(strict=strict, config=config_data)
        findings = scanner.scan_file(str(path), severity_threshold)
        from .core import SEVERITY_LEVELS

        stats = {
            "total_files": 1,
            "total_findings": len(findings),
            "severity_counts": {level: 0 for level in SEVERITY_LEVELS},
            "rule_counts": {},
            "fixable_findings": sum(1 for f in findings if f.can_fix),
        }
        for finding in findings:
            stats["severity_counts"][finding.severity] = (
                stats["severity_counts"].get(finding.severity, 0) + 1
            )
            stats["rule_counts"][finding.rule_id] = stats["rule_counts"].get(finding.rule_id, 0) + 1
    else:
        if output == "text":
            click.echo(f"Scanning repository: {path}")
        workflow_dir = path / ".github" / "workflows"
        if not workflow_dir.exists():
            click.echo(f"No workflows found at {workflow_dir}", err=True)
            sys.exit(1)
        files_to_scan = list(workflow_dir.glob("*.y*ml"))
        if not files_to_scan:
            click.echo(f"No workflows found at {workflow_dir}", err=True)
            sys.exit(1)

        if output == "text":
            click.echo(f"Found {len(files_to_scan)} workflow file(s) to scan")

        findings, stats = scan_repository(
            repo_path=repo_path,
            strict=strict,
            config=config_data,
            severity_threshold=severity_threshold,
        )

    if output_file:
        save_report(
            findings,
            stats,
            output_path=output_file,
            format=output,
            repo_path=repo_path,
            verbose=verbose,
        )
        click.echo(f"Results written to {output_file}")

        summary = f"Scan complete: {stats['total_findings']} issues found ("
        summary += f"CRITICAL: {stats.get('severity_counts', {}).get('CRITICAL', 0)}, "
        summary += f"HIGH: {stats.get('severity_counts', {}).get('HIGH', 0)}, "
        summary += f"MEDIUM: {stats.get('severity_counts', {}).get('MEDIUM', 0)}, "
        summary += f"LOW: {stats.get('severity_counts', {}).get('LOW', 0)})"
        click.echo(summary)
    else:
        print_report(findings, stats, format=output, repo_path=repo_path, verbose=verbose)

    from .core import SEVERITY_LEVELS

    threshold_index = SEVERITY_LEVELS.index(severity_threshold)
    severe_findings = sum(
        stats.get("severity_counts", {}).get(lvl, 0) for lvl in SEVERITY_LEVELS[threshold_index:]
    )

    if severe_findings > 0:
        sys.exit(1)


@cli.command()
@click.argument("repo_path", type=click.Path(exists=True))
@click.option("--strict", is_flag=True, help="Enable strict mode (extra warnings)")
@click.option(
    "--config", type=click.Path(exists=True), help="Path to YAML config file for check settings"
)
@click.option("--disable", multiple=True, help="Disable specific rule(s)")
@click.option("--interactive", is_flag=True, help="Confirm each fix individually")
@click.option("--dry-run", is_flag=True, help="Show what would be fixed without making changes")
@click.option(
    "--severity-threshold",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="LOW",
    help="Minimum severity level to fix",
)
def fix(
    repo_path: str,
    strict: bool,
    config: Optional[str],
    disable: Tuple[str, ...],
    interactive: bool,
    dry_run: bool,
    severity_threshold: str,
) -> None:
    """Audit and apply safe fixes to GitHub Actions workflows

    REPO_PATH: Path to the repository root or specific workflow file
    """
    if dry_run:
        click.echo("Running in dry-run mode. No changes will be made.")

    if interactive and dry_run:
        click.echo("Note: --interactive has no effect in dry-run mode.")

    if config:
        try:
            config_data = load_config(config)
        except Exception as e:
            click.echo(f"Error loading config file: {e}", err=True)
            sys.exit(1)
    else:
        config_data = {}

    if disable and len(disable) > 0:
        for rule in disable:
            config_data[rule] = False

    path = Path(repo_path)

    if path.is_file() and path.suffix in [".yml", ".yaml"]:
        click.echo(f"Scanning single workflow file: {path}")
        scanner = WorkflowScanner(strict=strict, config=config_data)
        findings = scanner.scan_file(str(path), severity_threshold)

        stats = {
            "total_files": 1,
            "total_findings": len(findings),
            "severity_counts": {},
            "rule_counts": {},
            "fixable_findings": 0,
        }

        for finding in findings:
            stats["severity_counts"][finding.severity] = (
                stats["severity_counts"].get(finding.severity, 0) + 1
            )
            stats["rule_counts"][finding.rule_id] = stats["rule_counts"].get(finding.rule_id, 0) + 1
            if finding.can_fix:
                stats["fixable_findings"] += 1

    else:
        click.echo(f"Scanning repository: {path}")
        workflow_dir = path / ".github" / "workflows"
        if not workflow_dir.exists():
            click.echo(f"No workflows found at {workflow_dir}", err=True)
            sys.exit(1)

        findings, stats = scan_repository(
            repo_path=repo_path,
            strict=strict,
            config=config_data,
            severity_threshold=severity_threshold,
        )

    findings_by_file = {}
    for finding in findings:
        if finding.file_path not in findings_by_file:
            findings_by_file[finding.file_path] = []
        findings_by_file[finding.file_path].append(finding)

    if not dry_run:
        fixes_applied, fixes_skipped = fix_repository(
            repo_path=repo_path,
            findings_by_file=findings_by_file,
            config=config_data,
            interactive=interactive,
        )

        stats["fixes_applied"] = fixes_applied
        stats["fixes_skipped"] = fixes_skipped
    else:
        fixable_count = sum(1 for finding in findings if finding.can_fix)
        stats["fixes_applied"] = 0
        stats["fixes_skipped"] = 0
        stats["fixable_findings"] = fixable_count

    click.echo("\n----- Fix Summary -----")
    click.echo(f"Total issues found: {stats['total_findings']}")

    if not dry_run:
        click.echo(f"Issues fixed: {stats['fixes_applied']}")
        click.echo(f"Issues skipped: {stats['fixes_skipped']}")

        if stats["fixes_applied"] > 0:
            click.echo("\n✅ Fixes applied successfully!")
        elif stats["total_findings"] == 0:
            click.echo("\n✅ No issues found!")
        else:
            click.echo("\n⚠️ Some issues could not be automatically fixed")
    else:
        click.echo(f"Fixable issues: {stats.get('fixable_findings', 0)}")

        if stats.get("fixable_findings", 0) > 0:
            click.echo("\n✅ Issues can be fixed (run without --dry-run to apply)")
        elif stats["total_findings"] == 0:
            click.echo("\n✅ No issues found!")
        else:
            click.echo("\n⚠️ Some issues cannot be automatically fixed")


@cli.command()
@click.option("--config", type=click.Path(exists=True), help="Path to YAML config file to validate")
@click.option("--generate", is_flag=True, help="Generate a default config file")
@click.option("--output", type=click.Path(), help="Output path for generated config")
def config(config: Optional[str], generate: bool, output: Optional[str]) -> None:
    """View or validate current config"""
    if generate:
        config_str = generate_default_config(output_path=output)

        if output:
            click.echo(f"Default config written to {output}")
        else:
            click.echo(config_str)
        return

    try:
        config_data = load_config(config)
        click.echo("✅ Config loaded and valid.")

        rule_engine = create_rule_engine(config_data)
        for rule_info in rule_engine.list_rules():
            click.echo(
                f" - {rule_info['id']}: "
                f"{'enabled' if rule_info['enabled'] else 'disabled'} "
                f"[{rule_info['severity']}]"
            )
    except Exception as e:
        click.echo(f"❌ Config validation failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def rules(format: str) -> None:
    """List all available rules and what they do"""

    rule_engine = create_rule_engine()
    rules_list = rule_engine.list_rules()

    if format == "json":
        click.echo(json.dumps(rules_list, indent=2))
    else:
        click.echo("🔍 ghast supports the following rules:")

        by_category = {}
        for rule in rules_list:
            category = rule.get("category", "other")
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(rule)

        for category, category_rules in by_category.items():
            click.echo(f"\n{category.upper()}:")

            for rule in sorted(category_rules, key=lambda r: r["id"]):
                severity_colors = {
                    "LOW": "blue",
                    "MEDIUM": "yellow",
                    "HIGH": "red",
                    "CRITICAL": "bright_red",
                }

                enabled_text = "✅ enabled" if rule["enabled"] else "❌ disabled"
                severity_text = click.style(
                    f"[{rule['severity']}]", fg=severity_colors.get(rule["severity"], "white")
                )

                click.echo(f" - {rule['id']}: {enabled_text} {severity_text}")
                click.echo(f"   {rule['description']}")


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
def analyze(file_path: str) -> None:
    """Analyze a single workflow file with detailed explanation"""
    from .utils.yaml_handler import is_github_actions_workflow, load_yaml_file_with_positions

    try:
        workflow = load_yaml_file_with_positions(file_path)

        if not is_github_actions_workflow(workflow):
            click.echo(f"⚠️ The file {file_path} does not appear to be a GitHub Actions workflow")
            sys.exit(1)

        rule_engine = create_rule_engine()

        findings = rule_engine.scan_workflow(workflow, file_path)

        click.echo(f"Analysis of {file_path}:\n")

        if not findings:
            click.echo("✅ No issues found!")
            return

        by_severity = {}
        for finding in findings:
            if finding.severity not in by_severity:
                by_severity[finding.severity] = []
            by_severity[finding.severity].append(finding)

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if severity in by_severity:
                severity_findings = by_severity[severity]
                click.echo(f"{severity} issues ({len(severity_findings)}):")

                for finding in severity_findings:
                    click.echo(f"  - {finding.message}")
                    click.echo(f"    Rule: {finding.rule_id}")
                    if finding.remediation:
                        click.echo(f"    Remediation: {finding.remediation}")
                click.echo("")

    except Exception as e:
        click.echo(f"Error analyzing file: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("repo_path", type=click.Path(exists=True))
@click.option("--output", type=click.Path(), help="Output file path for report", required=True)
@click.option(
    "--format",
    type=click.Choice(OUTPUT_FORMATS),
    default="html",
    help="Report format",
)
def report(repo_path: str, output: str, format: str) -> None:
    """Generate a comprehensive security report"""
    click.echo(f"Analyzing repository: {repo_path}")

    generate_full_report(
        repo_path=repo_path, output_format=format, output_path=output, verbose=True
    )

    click.echo(f"Report generated at: {output}")


if __name__ == "__main__":
    cli()
