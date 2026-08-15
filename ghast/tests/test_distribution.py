"""Tests for the packaged GitHub Action and pre-commit hook definitions.

These are shipped interfaces: `uses: seanwevans/ghast@v1` and a
`.pre-commit-hooks.yaml` entry are how most people will run ghast, and both
break silently if an input name or an entry command drifts from the CLI.
"""

from pathlib import Path

import pytest
import yaml

from ghast.cli import OUTPUT_FORMATS, cli

ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "action.yml"
HOOKS = ROOT / ".pre-commit-hooks.yaml"


@pytest.fixture(scope="module")
def action():
    with open(ACTION) as handle:
        return yaml.safe_load(handle)


@pytest.fixture(scope="module")
def hooks():
    with open(HOOKS) as handle:
        return yaml.safe_load(handle)


# --- action.yml ---------------------------------------------------------------


def test_action_is_a_composite_action(action):
    assert action["runs"]["using"] == "composite"
    assert action["name"] == "ghast"
    assert action["description"]


def test_action_declares_the_expected_inputs(action):
    assert set(action["inputs"]) == {
        "path",
        "severity-threshold",
        "config",
        "disable",
        "output",
        "output-file",
        "fail-on-findings",
        "strict",
        "version",
        "python-version",
    }


def test_every_action_input_has_a_description_and_default(action):
    for name, spec in action["inputs"].items():
        assert spec.get("description"), f"input {name} has no description"
        assert "default" in spec, f"input {name} has no default"


def test_action_default_severity_is_a_real_threshold(action):
    from ghast.core import SEVERITY_LEVELS

    assert action["inputs"]["severity-threshold"]["default"] in SEVERITY_LEVELS


def test_action_default_output_is_a_supported_format(action):
    assert action["inputs"]["output"]["default"] in OUTPUT_FORMATS


def test_action_exposes_the_exit_code(action):
    """Callers need the code to distinguish findings from a broken run."""
    assert set(action["outputs"]) == {"exit-code", "findings"}


def test_action_steps_pin_third_party_actions_by_sha(action):
    """ghast flags unpinned actions; its own action must not be unpinned."""
    import re

    for step in action["runs"]["steps"]:
        uses = step.get("uses")
        if uses is None:
            continue
        assert re.search(r"@[0-9a-f]{40}$", uses), f"{uses} is not pinned to a SHA"


def test_action_passes_inputs_through_the_environment(action):
    """Interpolating inputs into the script would make them executable."""
    run_step = next(s for s in action["runs"]["steps"] if s.get("id") == "scan")

    assert "${{" not in run_step["run"], "inputs are interpolated into the shell script"
    assert run_step["env"], "inputs should reach the script via env"


def test_action_install_step_does_not_interpolate_inputs(action):
    install = next(s for s in action["runs"]["steps"] if s["name"] == "Install ghast")

    assert "${{" not in install["run"]


def test_action_every_step_declares_a_shell(action):
    for step in action["runs"]["steps"]:
        if "uses" in step:
            continue
        assert step.get("shell") == "bash"


def test_action_would_pass_ghasts_own_scanner(action):
    """The action file is not a workflow, but the pinning rule still applies."""
    from ghast.rules.security import ActionPinningRule

    steps = [s for s in action["runs"]["steps"] if "uses" in s]
    workflow = {"on": "push", "jobs": {"action": {"steps": steps}}}

    assert ActionPinningRule().check(workflow, str(ACTION)) == []


# --- .pre-commit-hooks.yaml ---------------------------------------------------


def test_hooks_file_defines_the_expected_hooks(hooks):
    assert [hook["id"] for hook in hooks] == ["ghast", "ghast-strict"]


def test_every_hook_has_the_required_keys(hooks):
    for hook in hooks:
        for key in ("id", "name", "description", "entry", "language"):
            assert hook.get(key), f"hook {hook.get('id')} is missing {key}"


def test_hooks_use_the_python_language(hooks):
    """pre-commit installs the package from this repo to get the entry point."""
    for hook in hooks:
        assert hook["language"] == "python"


def test_hooks_do_not_pass_filenames(hooks):
    """ghast takes one repository path, not a file list."""
    for hook in hooks:
        assert hook["pass_filenames"] is False


def test_hooks_only_run_for_workflow_files(hooks):
    import re

    for hook in hooks:
        pattern = re.compile(hook["files"])
        assert pattern.search(".github/workflows/ci.yml")
        assert pattern.search(".github/workflows/ci.yaml")
        assert not pattern.search("README.md")
        assert not pattern.search("ghast/cli.py")


def test_hook_entries_invoke_a_real_cli_command(hooks):
    """A typo in `entry` would only surface when someone installs the hook."""
    commands = cli.commands

    for hook in hooks:
        parts = hook["entry"].split()
        assert parts[0] == "ghast"
        assert parts[1] in commands, f"{parts[1]} is not a ghast command"


def test_strict_hook_uses_a_valid_threshold(hooks):
    from ghast.core import SEVERITY_LEVELS

    strict = next(hook for hook in hooks if hook["id"] == "ghast-strict")
    parts = strict["entry"].split()

    assert "--severity-threshold" in parts
    assert parts[parts.index("--severity-threshold") + 1] in SEVERITY_LEVELS


def test_hook_entry_options_are_accepted_by_the_cli(hooks):
    """Every long option in an entry must exist on the `scan` command."""
    known = set()
    for param in cli.commands["scan"].params:
        known.update(param.opts)

    for hook in hooks:
        for part in hook["entry"].split():
            if part.startswith("--"):
                assert part in known, f"{part} is not a `ghast scan` option"
