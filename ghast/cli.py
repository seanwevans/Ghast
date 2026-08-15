"""
cli.py - Command-line interface for ghast

This module provides the command-line interface for the ghast tool,
allowing users to scan GitHub Actions workflows for security issues.
"""

import copy
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast

import click

from .core import (
    Finding,
    WorkflowScanner,
    disable_rules,
    fix_repository,
    generate_default_config,
    load_config,
    scan_repository,
    unknown_rule_names,
)
from .core.discovery import TargetKind, discover_targets
from .core.scanner import ScannerError, normalize_severity
from .core.suppressions import BaselineError, apply_baseline, build_baseline, load_baseline
from .reports import generate_full_report, print_report, save_report
from .rules import create_rule_engine
from .utils.banner import _BANNER
from .utils.version import __version__

OUTPUT_FORMATS = ["text", "json", "sarif", "html"]

#: Findings at or above the severity threshold were reported.
EXIT_FINDINGS = 1
#: ghast could not complete the run: bad config, no workflows, unreadable file.
EXIT_ERROR = 2


class GhastError(click.ClickException):
    """A failure to run, as distinct from a successful run that found issues.

    Both used to raise plain ``ClickException`` and exit 1, so a CI job could
    not tell "your workflows have problems" from "the scanner broke".
    """

    exit_code = EXIT_ERROR


def _reject_unknown_rules(disable: Tuple[str, ...]) -> None:
    """Fail loudly when --disable names a rule that does not exist.

    Silently accepting a typo here is how a user ends up believing a rule is
    off when it is still running.
    """
    unknown = unknown_rule_names(list(disable))
    if not unknown:
        return

    from .rules.registry import all_rule_ids

    raise click.ClickException(
        f"Unknown rule(s) passed to --disable: {', '.join(unknown)}. "
        f"Valid rules: {', '.join(all_rule_ids())}"
    )


def _apply_baseline_to_scan(
    findings: List[Finding],
    stats: Dict[str, Any],
    baseline_path: str,
    repo_path: str,
) -> Tuple[List[Finding], Dict[str, Any]]:
    """Drop baselined findings and recompute the statistics that describe them.

    The counts in ``stats`` are produced before filtering, so they have to be
    rebuilt or the summary would describe findings that were not reported.
    """
    from .core import SEVERITY_LEVELS

    try:
        fingerprints = load_baseline(baseline_path)
    except BaselineError as error:
        raise click.ClickException(str(error))

    kept, suppressed = apply_baseline(findings, fingerprints, repo_path)

    stats = dict(stats)
    stats["total_findings"] = len(kept)
    stats["baselined_findings"] = suppressed
    stats["severity_counts"] = {level: 0 for level in SEVERITY_LEVELS}
    stats["rule_counts"] = {}
    stats["fixable_findings"] = sum(1 for finding in kept if finding.can_fix)

    for finding in kept:
        severity = normalize_severity(finding.severity)
        stats["severity_counts"][severity] = stats["severity_counts"].get(severity, 0) + 1
        stats["rule_counts"][finding.rule_id] = stats["rule_counts"].get(finding.rule_id, 0) + 1

    return kept, stats


def _prepare_scan(
    repo_path: str,
    strict: bool,
    config: Optional[str],
    severity_threshold: str,
    *,
    disable: Tuple[str, ...] = (),
    config_default: Optional[Dict[str, Any]] = None,
    show_file_count: bool = False,
    echo: bool = True,
) -> Tuple[List[Finding], Dict[str, Any], Optional[Dict[str, Any]]]:
    """Load config, discover workflow files, and perform a scan.

    Args:
        repo_path: Path to the repository root or a specific workflow file.
        strict: Enable strict mode.
        config: Optional path to a YAML config file.
        severity_threshold: Minimum severity level to report.
        disable: Rules to disable before scanning.
        config_default: Default config to use if no config file is provided.
        show_file_count: Print the number of discovered workflow files.

    Returns:
        A tuple of (findings, stats, config_data) where config_data is the
        configuration dictionary used for scanning.
    """

    severity_threshold = normalize_severity(severity_threshold)

    if config:
        config_path = Path(config)
        if not config_path.exists():
            raise GhastError(f"Error loading config file: {config} not found")
        try:
            config_data = load_config(config)
        except Exception as e:
            raise GhastError(f"Error loading config file: {e}")

    else:
        config_data = copy.deepcopy(config_default) if config_default is not None else {}

    if disable:
        if config_data is None:
            config_data = {}
        _reject_unknown_rules(disable)
        config_data = disable_rules(config_data, list(disable))

    path = Path(repo_path)
    if path.is_file() and path.suffix in [".yml", ".yaml"]:
        if echo:
            click.echo(f"Scanning single workflow file: {path}")
        scanner = WorkflowScanner(strict=strict, config=config_data)
        try:
            findings = scanner.scan_file(str(path), severity_threshold)
        except ScannerError as error:
            raise GhastError(str(error))

        from .core import SEVERITY_LEVELS

        stats: Dict[str, Any] = {
            "total_files": 1,
            "total_findings": len(findings),
            "severity_counts": {level: 0 for level in SEVERITY_LEVELS},
            "rule_counts": {},
            "fixable_findings": sum(1 for f in findings if f.can_fix),
        }

        for finding in findings:
            severity_counts = cast(Dict[str, int], stats["severity_counts"])
            finding_severity = normalize_severity(finding.severity)
            severity_counts[finding_severity] = severity_counts.get(finding_severity, 0) + 1
            rule_counts = cast(Dict[str, int], stats["rule_counts"])
            rule_counts[finding.rule_id] = rule_counts.get(finding.rule_id, 0) + 1
    else:
        if echo:
            click.echo(f"Scanning repository: {path}")
        files_to_scan = discover_targets(repo_path)
        if not files_to_scan:
            raise GhastError(f"No workflows or actions found under {path}")

        if echo and show_file_count:
            actions = sum(1 for t in files_to_scan if t.kind is TargetKind.ACTION)
            summary = f"Found {len(files_to_scan)} file(s) to scan"
            if actions:
                summary += f" ({actions} composite action(s))"
            click.echo(summary)

        try:
            findings, stats = scan_repository(
                repo_path=repo_path,
                strict=strict,
                config=config_data,
                severity_threshold=severity_threshold,
            )
        except ScannerError as error:
            # A bug in ghast must exit 2, not be reported as a finding about
            # the user's workflow.
            raise GhastError(str(error))

    return findings, stats, config_data


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
@click.option(
    "--baseline",
    type=click.Path(),
    help="Ignore findings recorded in this baseline file; report only new ones",
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
    baseline: Optional[str],
    no_color: bool,
    verbose: bool,
) -> None:
    """Audit GitHub Actions workflows for security issues (read-only)

    REPO_PATH: Path to the repository root or specific workflow file
    """

    if no_color:
        os.environ["NO_COLOR"] = "1"
    findings, stats, _ = _prepare_scan(
        repo_path,
        strict,
        config,
        severity_threshold,
        disable=disable,
        show_file_count=output == "text",
        echo=output == "text",
    )

    if baseline:
        findings, stats = _apply_baseline_to_scan(findings, stats, baseline, repo_path)
        if output == "text" and stats["baselined_findings"]:
            click.echo(f"Ignored {stats['baselined_findings']} finding(s) recorded in {baseline}")

    if stats.get("suppressed_findings") and output == "text":
        click.echo(
            f"Ignored {stats['suppressed_findings']} finding(s) via inline "
            "'# ghast: ignore' comments"
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
        sev_counts = cast(Dict[str, int], stats.get("severity_counts", {}))
        summary += f"CRITICAL: {sev_counts.get('CRITICAL', 0)}, "
        summary += f"HIGH: {sev_counts.get('HIGH', 0)}, "
        summary += f"MEDIUM: {sev_counts.get('MEDIUM', 0)}, "
        summary += f"LOW: {sev_counts.get('LOW', 0)})"
        click.echo(summary)
    else:
        print_report(findings, stats, format=output, repo_path=repo_path, verbose=verbose)

    from .core import SEVERITY_LEVELS

    normalized_threshold = normalize_severity(severity_threshold)
    threshold_index = SEVERITY_LEVELS.index(normalized_threshold)
    sev_counts = cast(Dict[str, int], stats.get("severity_counts", {}))
    severe_findings = sum(sev_counts.get(lvl, 0) for lvl in SEVERITY_LEVELS[threshold_index:])

    if severe_findings > 0:
        # A successful scan that found problems is not a tool error. Reporting
        # it as `Error: Severe findings detected` made a normal, expected
        # outcome look like a crash, and shared exit 1 with real failures.
        click.echo(
            f"Found {severe_findings} finding(s) at or above {normalized_threshold}.",
            err=True,
        )
        raise SystemExit(EXIT_FINDINGS)


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
            raise GhastError(f"Error loading config file: {e}")
    else:
        config_data = {}

    if disable and len(disable) > 0:
        _reject_unknown_rules(disable)
        config_data = disable_rules(config_data, list(disable))

    path = Path(repo_path)

    if path.is_file() and path.suffix in [".yml", ".yaml"]:
        click.echo(f"Scanning single workflow file: {path}")
        scanner = WorkflowScanner(strict=strict, config=config_data)
        findings = scanner.scan_file(str(path), severity_threshold)

        from .core import SEVERITY_LEVELS

        stats: Dict[str, Any] = {
            "total_files": 1,
            "total_findings": len(findings),
            "severity_counts": {level: 0 for level in SEVERITY_LEVELS},
            "rule_counts": {},
            "fixable_findings": 0,
        }

        for finding in findings:
            severity_counts = cast(Dict[str, int], stats["severity_counts"])
            finding_severity = normalize_severity(finding.severity)
            severity_counts[finding_severity] = severity_counts.get(finding_severity, 0) + 1
            rule_counts = cast(Dict[str, int], stats["rule_counts"])
            rule_counts[finding.rule_id] = rule_counts.get(finding.rule_id, 0) + 1
            if finding.can_fix:
                stats["fixable_findings"] = cast(int, stats["fixable_findings"]) + 1

    else:
        click.echo(f"Scanning repository: {path}")
        if not discover_targets(repo_path):
            raise GhastError(f"No workflows or actions found under {path}")

        findings, stats = scan_repository(
            repo_path=repo_path,
            strict=strict,
            config=config_data,
            severity_threshold=severity_threshold,
        )

    findings_by_file: Dict[str, List[Finding]] = {}
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

        fixes_applied = cast(int, stats["fixes_applied"])
        total_findings = cast(int, stats["total_findings"])
        if fixes_applied > 0:
            click.echo("\n✅ Fixes applied successfully!")
        elif total_findings == 0:
            click.echo("\n✅ No issues found!")
        else:
            click.echo("\n⚠️ Some issues could not be automatically fixed")
    else:
        fixable_findings = cast(int, stats.get("fixable_findings", 0))
        click.echo(f"Fixable issues: {fixable_findings}")

        total_findings = cast(int, stats["total_findings"])
        if fixable_findings > 0:
            click.echo("\n✅ Issues can be fixed (run without --dry-run to apply)")
        elif total_findings == 0:
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
        raise GhastError(f"❌ Config validation failed: {e}")


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

        by_category: Dict[str, List[Dict[str, Any]]] = {}
        for rule in rules_list:
            category = cast(str, rule.get("category", "other"))
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
@click.argument("repo_path", type=click.Path(exists=True))
@click.option("--strict", is_flag=True, help="Enable strict mode (extra warnings)")
@click.option("--config", type=click.Path(), help="Path to YAML config file for check settings")
@click.option("--disable", multiple=True, help="Disable specific rule(s)")
@click.option(
    "--severity-threshold",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="LOW",
    help="Minimum severity level to record",
)
@click.option(
    "--output",
    type=click.Path(),
    default="ghast-baseline.json",
    show_default=True,
    help="Where to write the baseline file",
)
def baseline(
    repo_path: str,
    strict: bool,
    config: Optional[str],
    disable: Tuple[str, ...],
    severity_threshold: str,
    output: str,
) -> None:
    """Record current findings so future scans report only new ones

    REPO_PATH: Path to the repository root or specific workflow file

    Commit the generated file and pass it to `ghast scan --baseline`. A
    repository with existing findings can then gate on regressions
    immediately, rather than having to fix everything before it can turn
    ghast on at all.
    """
    findings, _, _ = _prepare_scan(
        repo_path,
        strict,
        config,
        severity_threshold,
        disable=disable,
        echo=False,
    )

    document = build_baseline(findings, repo_path)

    with open(output, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")

    click.echo(f"Recorded {len(document['findings'])} finding(s) in {output}")
    if findings:
        click.echo("Commit this file, then run: ghast scan . --baseline " + output)


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
def analyze(file_path: str) -> None:
    """Analyze a single workflow file with detailed explanation"""
    from .utils.yaml_handler import is_github_actions_workflow, load_yaml_file_with_positions

    try:
        workflow = load_yaml_file_with_positions(file_path)

        if not is_github_actions_workflow(workflow):
            raise GhastError(
                f"⚠️ The file {file_path} does not appear to be a GitHub Actions workflow"
            )

        rule_engine = create_rule_engine()

        findings = rule_engine.scan_workflow(workflow, file_path)

        click.echo(f"Analysis of {file_path}:\n")

        if not findings:
            click.echo("✅ No issues found!")
            return

        by_severity: Dict[str, List[Finding]] = {}
        for finding in findings:
            finding_severity = normalize_severity(finding.severity)
            if finding_severity not in by_severity:
                by_severity[finding_severity] = []
            by_severity[finding_severity].append(finding)

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
        raise GhastError(f"Error analyzing file: {e}")


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


if __name__ == "__main__":  # pragma: no cover
    cli()
