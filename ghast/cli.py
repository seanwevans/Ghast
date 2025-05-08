#!/usr/bin/env python3

"""
ghast.py ☠ GitHub Actions Security Tool - CLI Interface

This module provides the command-line interface for the ghast tool,
allowing users to scan GitHub Actions workflows for security issues.
"""

import os
import sys
from pathlib import Path
import click
import yaml

# Import internal modules
from banner import _BANNER
from soul import scan_repo, load_config_file, default_checks
from report import generate_report

# Output formats
OUTPUT_FORMATS = ["text", "json", "sarif", "html"]


@click.group(invoke_without_command=True)
@click.version_option(version="0.2.0")
@click.pass_context
def cli(ctx):
    """ghast ☠ GitHub Actions Security Tool

    A security scanner for GitHub Actions workflows.
    Detects misconfigurations, security vulnerabilities, and provides remediation advice.
    """
    if ctx.invoked_subcommand is None:
        click.echo(_BANNER)
        click.echo("Use `ghast --help` for available commands.")


@cli.command()
@click.argument("repo_path", type=click.Path(exists=True))
@click.option("--strict", is_flag=True, help="Enable strict mode (extra warnings)")
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Path to YAML config file for check settings",
)
@click.option(
    "--disable",
    type=click.Choice(list(default_checks.keys())),
    multiple=True,
    help="Disable specific check(s)",
)
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
@click.option(
    "--verbose", is_flag=True, help="Show detailed information for each finding"
)
def scan(
    repo_path,
    strict,
    config,
    disable,
    output,
    output_file,
    severity_threshold,
    no_color,
    verbose,
):
    """Audit GitHub Actions workflows for security issues (read-only)

    REPO_PATH: Path to the repository root or specific workflow file
    """
    # Load config
    if config:
        try:
            load_config_file(config)
        except Exception as e:
            click.echo(f"Error loading config file: {e}", err=True)
            sys.exit(1)

    # Set colored output preference
    if no_color:
        os.environ["NO_COLOR"] = "1"

    # Ensure repo_path is a directory
    path = Path(repo_path)
    if path.is_file() and path.suffix in [".yml", ".yaml"]:
        click.echo(f"Scanning single workflow file: {path}")
        files_to_scan = [path]
    else:
        click.echo(f"Scanning repository: {path}")
        workflow_dir = path / ".github" / "workflows"
        if not workflow_dir.exists():
            click.echo(f"No workflows found at {workflow_dir}", err=True)
            sys.exit(1)
        files_to_scan = list(workflow_dir.glob("*.y*ml"))

    click.echo(f"Found {len(files_to_scan)} workflow file(s) to scan")

    # Run scan
    findings, stats = scan_repo(
        repo_path,
        fix=False,
        strict=strict,
        config=config,
        disable=disable,
        severity_threshold=severity_threshold,
        files=files_to_scan,
    )

    # Generate report
    report = generate_report(
        findings, stats, format=output, repo_path=repo_path, verbose=verbose
    )

    # Output results
    if output_file:
        with open(output_file, "w") as f:
            f.write(report)
        click.echo(f"Results written to {output_file}")

        # Print summary to console
        summary = f"Scan complete: {stats['total_findings']} issues found ("
        summary += f"CRITICAL: {stats['severity_counts'].get('CRITICAL', 0)}, "
        summary += f"HIGH: {stats['severity_counts'].get('HIGH', 0)}, "
        summary += f"MEDIUM: {stats['severity_counts'].get('MEDIUM', 0)}, "
        summary += f"LOW: {stats['severity_counts'].get('LOW', 0)})"
        click.echo(summary)
    else:
        click.echo(report)

    # Exit with non-zero code if issues found above severity threshold
    severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threshold_index = severity_levels.index(severity_threshold)

    # Count findings at or above threshold
    severe_findings = sum(
        stats["severity_counts"].get(lvl, 0)
        for lvl in severity_levels[threshold_index:]
    )

    if severe_findings > 0:
        sys.exit(1)


@cli.command()
@click.argument("repo_path", type=click.Path(exists=True))
@click.option("--strict", is_flag=True, help="Enable strict mode (extra warnings)")
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Path to YAML config file for check settings",
)
@click.option(
    "--disable",
    type=click.Choice(list(default_checks.keys())),
    multiple=True,
    help="Disable specific check(s)",
)
@click.option("--interactive", is_flag=True, help="Confirm each fix individually")
@click.option(
    "--dry-run", is_flag=True, help="Show what would be fixed without making changes"
)
@click.option(
    "--severity-threshold",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="LOW",
    help="Minimum severity level to fix",
)
def fix(repo_path, strict, config, disable, interactive, dry_run, severity_threshold):
    """Audit and apply safe fixes to GitHub Actions workflows

    REPO_PATH: Path to the repository root or specific workflow file
    """
    if dry_run:
        click.echo("Running in dry-run mode. No changes will be made.")

    if interactive and dry_run:
        click.echo("Note: --interactive has no effect in dry-run mode.")

    # Load config
    if config:
        try:
            load_config_file(config)
        except Exception as e:
            click.echo(f"Error loading config file: {e}", err=True)
            sys.exit(1)

    # Ensure repo_path is a directory
    path = Path(repo_path)
    if path.is_file() and path.suffix in [".yml", ".yaml"]:
        click.echo(f"Scanning single workflow file: {path}")
        files_to_scan = [path]
    else:
        click.echo(f"Scanning repository: {path}")
        workflow_dir = path / ".github" / "workflows"
        if not workflow_dir.exists():
            click.echo(f"No workflows found at {workflow_dir}", err=True)
            sys.exit(1)
        files_to_scan = list(workflow_dir.glob("*.y*ml"))

    click.echo(f"Found {len(files_to_scan)} workflow file(s) to scan")

    # Run fix
    findings, stats = scan_repo(
        repo_path,
        fix=not dry_run,
        strict=strict,
        config=config,
        disable=disable,
        interactive=interactive,
        severity_threshold=severity_threshold,
        files=files_to_scan,
    )

    # Print summary
    click.echo("\n----- Fix Summary -----")
    click.echo(f"Total issues found: {stats['total_findings']}")
    click.echo(f"Issues fixed: {stats['fixes_applied']}")

    if stats["fixes_applied"] > 0 and not dry_run:
        click.echo("\n✅ Fixes applied successfully!")
    elif stats["fixes_applied"] > 0 and dry_run:
        click.echo("\n✅ Issues can be fixed (run without --dry-run to apply)")
    elif stats["total_findings"] == 0:
        click.echo("\n✅ No issues found!")
    else:
        click.echo("\n⚠️  Some issues could not be automatically fixed")


@cli.command()
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Path to YAML config file to validate",
)
@click.option("--generate", is_flag=True, help="Generate a default config file")
@click.option("--output", type=click.Path(), help="Output path for generated config")
def config(config, generate, output):
    """View or validate current config"""
    if generate:
        default_config = {k: v for k, v in default_checks.items()}
        # Add additional configurable settings
        default_config.update(
            {
                "severity_thresholds": {
                    "check_timeout": "LOW",
                    "check_shell": "LOW",
                    "check_deprecated": "MEDIUM",
                    "check_runs_on": "MEDIUM",
                    "check_workflow_name": "LOW",
                    "check_continue_on_error": "MEDIUM",
                    "check_tokens": "HIGH",
                    "check_inline_bash": "LOW",
                    "check_reusable_inputs": "MEDIUM",
                    "check_ppe_vulnerabilities": "CRITICAL",
                    "check_command_injection": "HIGH",
                    "check_env_injection": "HIGH",
                }
            }
        )

        if output:
            with open(output, "w") as f:
                yaml.dump(default_config, f, sort_keys=False, default_flow_style=False)
            click.echo(f"Default config written to {output}")
        else:
            click.echo(
                yaml.dump(default_config, sort_keys=False, default_flow_style=False)
            )
        return

    try:
        load_config_file(config)
        click.echo("✅ Config loaded and valid.")
        for k, v in default_checks.items():
            click.echo(f" - {k}: {'enabled' if v else 'disabled'}")
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
def rules(format):
    """List all available checks and what they do"""
    rule_descriptions = {
        "check_timeout": "Ensures long jobs have timeout-minutes to prevent hanging",
        "check_shell": "Adds shell: bash for multiline run: blocks to prevent unexpected behavior",
        "check_deprecated": "Warns on old actions like actions/checkout@v1",
        "check_runs_on": "Warns on ambiguous/self-hosted runners which can be security risks",
        "check_workflow_name": "Encourages top-level name: for visibility in GitHub UI",
        "check_continue_on_error": "Warns if continue-on-error: true is used which can hide issues",
        "check_tokens": "Flags hardcoded access tokens which should be in secrets",
        "check_inline_bash": "Alias for check_shell",
        "check_reusable_inputs": "Ensures uses: workflows define inputs: and don't abuse with:",
        "check_ppe_vulnerabilities": "Detects Poisoned Pipeline Execution vulnerabilities",
        "check_command_injection": "Finds potential command injection vulnerabilities",
        "check_env_injection": "Detects unsafe modifications to GITHUB_ENV and GITHUB_PATH",
        "check_untrusted_checkouts": "Flags checkout of untrusted code in privileged contexts",
    }

    severity_levels = {
        "check_timeout": "LOW",
        "check_shell": "LOW",
        "check_deprecated": "MEDIUM",
        "check_runs_on": "MEDIUM",
        "check_workflow_name": "LOW",
        "check_continue_on_error": "MEDIUM",
        "check_tokens": "HIGH",
        "check_inline_bash": "LOW",
        "check_reusable_inputs": "MEDIUM",
        "check_ppe_vulnerabilities": "CRITICAL",
        "check_command_injection": "HIGH",
        "check_env_injection": "HIGH",
        "check_untrusted_checkouts": "HIGH",
    }

    if format == "json":
        rules_data = {
            rule: {
                "enabled": default_checks.get(rule, False),
                "description": rule_descriptions.get(rule, "No description available"),
                "severity": severity_levels.get(rule, "MEDIUM"),
            }
            for rule in sorted(
                list(set(list(default_checks.keys()) + list(rule_descriptions.keys())))
            )
        }
        click.echo(json.dumps(rules_data, indent=2))
    else:
        click.echo("🔍 ghast supports the following rules:")
        for rule in sorted(
            list(set(list(default_checks.keys()) + list(rule_descriptions.keys())))
        ):
            enabled = default_checks.get(rule, False)
            description = rule_descriptions.get(rule, "No description available")
            severity = severity_levels.get(rule, "MEDIUM")

            # Add color based on severity
            severity_colors = {
                "LOW": "blue",
                "MEDIUM": "yellow",
                "HIGH": "red",
                "CRITICAL": "bright_red",
            }

            enabled_text = "✅ enabled" if enabled else "❌ disabled"
            severity_text = click.style(
                f"[{severity}]", fg=severity_colors.get(severity, "white")
            )

            click.echo(f" - {rule}: {enabled_text} {severity_text}")
            click.echo(f"   {description}")


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
def analyze(file_path):
    """Analyze a single workflow file with detailed explanation"""
    from workflow_analyzer import analyze_workflow_file

    results = analyze_workflow_file(file_path)
    click.echo(results)


@cli.command()
@click.argument("repo_path", type=click.Path(exists=True))
@click.option(
    "--output", type=click.Path(), help="Output file path for report", required=True
)
def report(repo_path, output):
    """Generate a comprehensive security report"""
    from report import generate_full_report

    click.echo(f"Analyzing repository: {repo_path}")
    report_data = generate_full_report(repo_path)

    with open(output, "w") as f:
        f.write(report_data)

    click.echo(f"Report generated at: {output}")


if __name__ == "__main__":
    cli()
