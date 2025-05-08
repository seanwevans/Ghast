""" soul.py - the core of ghast """

import os
from pathlib import Path
import re
import yaml

import click

GITHUB_WORKFLOW_DIR = ".github/workflows"
SHA_PATTERN = re.compile(r"@([0-9a-f]{40})$")
INSECURE_ENV_PATTERN = re.compile(r"\${{\s*toJson\(\s*secrets\s*\)\s*}}")
TOKEN_PATTERN = re.compile(r".*token.*=[\"']?[A-Za-z0-9_\-]{20,}[\"']?")
UNSAFE_TRIGGERS = {"pull_request_target", "workflow_run"}
TRUSTED_ACTION_PREFIXES = ["actions/", "github/"]
DEPRECATED_ACTIONS = ["actions/setup-python@v1", "actions/checkout@v1"]
DEFAULT_TIMEOUT_MINUTES = 15

default_checks = {
    "check_timeout": True,
    "check_shell": True,
    "check_deprecated": True,
    "check_runs_on": True,
    "check_workflow_name": True,
    "check_continue_on_error": True,
    "check_tokens": True,
    "check_inline_bash": True,
    "check_reusable_inputs": True,
}

checks = default_checks.copy()


def is_hash_pinned(uses_value):
    return bool(SHA_PATTERN.search(uses_value))


def is_trusted_action(uses_value):
    return any(
        uses_value.strip().startswith(prefix) for prefix in TRUSTED_ACTION_PREFIXES
    )


def fix_permissions(workflow):
    if "permissions" not in workflow:
        workflow["permissions"] = "read-all"
        return True
    return False


def fix_checkout_persist_credentials(step):
    if isinstance(step, dict) and step.get("uses", "").startswith("actions/checkout"):
        if "with" not in step:
            step["with"] = {}
        if "persist-credentials" not in step["with"]:
            step["with"]["persist-credentials"] = False
            return True
    return False


def load_config_file(path):
    if path and os.path.isfile(path):
        with open(path, "r") as f:
            config = yaml.safe_load(f)
            if isinstance(config, dict):
                for key in checks:
                    if key in config:
                        checks[key] = config[key]


def scan_workflow(path, fix=False, strict=False):
    updated = False
    with open(path, "r") as f:
        content = yaml.safe_load(f)

    findings = []
    if not content:
        return findings, updated

    if fix_permissions(content):
        findings.append("Added 'permissions: read-all' at workflow level.")
        updated = True

    if checks["check_workflow_name"] and "name" not in content:
        findings.append("Missing workflow name (top-level 'name' field).")

    jobs = content.get("jobs", {})
    for job_id, job in jobs.items():
        steps = job.get("steps", [])
        if checks["check_timeout"] and "timeout-minutes" not in job and len(steps) > 5:
            job["timeout-minutes"] = DEFAULT_TIMEOUT_MINUTES
            findings.append(
                f"Added 'timeout-minutes: {DEFAULT_TIMEOUT_MINUTES}' to job '{job_id}'."
            )
            updated = True

        if checks["check_runs_on"]:
            runs_on = job.get("runs-on", "")
            if not runs_on or runs_on == "self-hosted":
                findings.append(
                    f"runs-on uses ambiguous or self-hosted runner in job '{job_id}'."
                )

        for step in steps:
            uses = step.get("uses", "")
            if uses:
                if not is_hash_pinned(uses):
                    findings.append(f"Unpinned action usage in job '{job_id}': {uses}")
                if not is_trusted_action(uses):
                    findings.append(
                        f"Untrusted third-party action in job '{job_id}': {uses}"
                    )
                if checks["check_deprecated"] and uses in DEPRECATED_ACTIONS:
                    findings.append(f"Deprecated action used in job '{job_id}': {uses}")

            if INSECURE_ENV_PATTERN.search(str(step.get("env", ""))):
                findings.append(f"Insecure toJson(secrets) usage in job '{job_id}'.")

            if checks["check_tokens"] and TOKEN_PATTERN.search(str(step)):
                findings.append(f"Hardcoded token detected in job '{job_id}'.")

            if fix_checkout_persist_credentials(step):
                findings.append(
                    f"Added 'persist-credentials: false' to actions/checkout in job '{job_id}'."
                )
                updated = True

            if (
                checks["check_continue_on_error"]
                and step.get("continue-on-error") is True
            ):
                findings.append(
                    f"Usage of 'continue-on-error: true' in job '{job_id}'."
                )

            if checks["check_shell"]:
                if (
                    "run" in step
                    and isinstance(step["run"], str)
                    and "\n" in step["run"]
                ):
                    if "shell" not in step:
                        step["shell"] = "bash"
                        findings.append(
                            f"Added 'shell: bash' for multiline script in job '{job_id}'."
                        )
                        updated = True

        if job.get("permissions") is None:
            job["permissions"] = "read-all"
            findings.append(f"Added 'permissions: read-all' to job '{job_id}'.")
            updated = True

    on_section = content.get("on", {})
    triggers = on_section if isinstance(on_section, list) else list(on_section.keys())
    for trigger in triggers:
        if trigger in UNSAFE_TRIGGERS:
            findings.append(f"Use of unsafe trigger: '{trigger}'")

    if "secrets" in str(content) and "inherit" in str(content):
        findings.append("Detected 'secrets: inherit' (manual review recommended)")

    if checks["check_reusable_inputs"]:
        for job_id, job in jobs.items():
            if job.get("uses"):
                if "with" in job and not job.get("inputs"):
                    findings.append(
                        f"Reusable workflow in job '{job_id}' uses broad 'with:' without explicit inputs block."
                    )

    if fix and updated:
        with open(path, "w") as f:
            yaml.dump(content, f, sort_keys=False)

    return findings, updated


def scan_repo(repo_path, fix=False, strict=False, config=None, disable=()):
    if config:
        load_config_file(config)
    for rule in disable:
        checks[rule] = False

    workflow_dir = Path(repo_path) / GITHUB_WORKFLOW_DIR
    if not workflow_dir.exists():
        click.echo(f"No workflows found at {workflow_dir}")
        return

    for wf_file in workflow_dir.glob("*.y*ml"):
        click.echo(f"\n🔍 Scanning {wf_file.relative_to(repo_path)}...")
        findings, updated = scan_workflow(wf_file, fix=fix, strict=strict)
        for finding in findings:
            click.echo(f"  - {finding}")
        if fix and updated:
            click.echo("  ✅ Fixes applied.")
        elif fix:
            click.echo("  ✅ No changes needed.")
