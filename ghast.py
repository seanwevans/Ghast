#!/usr/bin/env python3

""" ghast.py ☠ GitHub Actions Security Tool"""

from pathlib import Path

import click

from banner import _BANNER
from soul import scan_repo, load_config_file, default_checks


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """ghast ☠ GitHub Actions Security Tool"""
    if ctx.invoked_subcommand is None:
        click.echo(_BANNER)
        click.echo("Use `ghast --help` for available commands.")


@cli.command()
@click.argument("repo_path", type=click.Path(exists=True))
@click.option("--strict", is_flag=True, help="Enable strict mode (extra warnings)")
@click.option(
    "--config", type=click.Path(), help="Path to YAML config file for check settings"
)
@click.option(
    "--disable",
    type=click.Choice(list(default_checks.keys())),
    multiple=True,
    help="Disable specific check(s)",
)
def scan(repo_path, strict, config, disable):
    """Audit GitHub Actions workflows (read-only)"""
    scan_repo(repo_path, fix=False, strict=strict, config=config, disable=disable)


@cli.command()
@click.argument("repo_path", type=click.Path(exists=True))
@click.option("--strict", is_flag=True, help="Enable strict mode (extra warnings)")
@click.option(
    "--config", type=click.Path(), help="Path to YAML config file for check settings"
)
@click.option(
    "--disable",
    type=click.Choice(list(default_checks.keys())),
    multiple=True,
    help="Disable specific check(s)",
)
def fix(repo_path, strict, config, disable):
    """Audit and apply safe fixes to GitHub Actions workflows"""
    scan_repo(repo_path, fix=True, strict=strict, config=config, disable=disable)


@cli.command()
@click.option(
    "--config", type=click.Path(), help="Path to YAML config file to validate"
)
def config(config):
    """View or validate current config"""
    load_config_file(config)
    click.echo("✅ Config loaded and valid.")
    for k, v in default_checks.items():
        click.echo(f" - {k}: {'enabled' if v else 'disabled'}")


@cli.command()
def rules():
    """List all available checks and what they do"""
    click.echo("🔍 ghast supports the following rules:")
    for rule, enabled in default_checks.items():
        click.echo(f" - {rule}: {'✅ enabled' if enabled else '❌ disabled'}")


if __name__ == "__main__":
    cli()
