"""
expressions.py - Which ``${{ }}`` contexts carry attacker-controlled data

GitHub Actions interpolates ``${{ ... }}`` into the shell script *before* the
shell runs, so any untrusted value reaching a ``run:`` block is a command
injection. The set of untrusted contexts is a property of the platform rather
than of any one rule, so it lives here as data instead of being spelled out as
bespoke regexes inside a check.

Reference: "Understanding the risk of script injections" in GitHub's own
security-hardening guide.
"""

import re
from typing import Iterator, List, NamedTuple, Optional

#: Matches a ``${{ ... }}`` interpolation and captures the expression inside.
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)


class UntrustedContext(NamedTuple):
    """An expression context an attacker can influence."""

    #: Regex matched against the inside of a ``${{ }}`` expression.
    pattern: str
    #: Short description of where the value comes from.
    description: str


#: Contexts whose values come from an attacker-controllable source.
#:
#: Ordered most specific first so the reported description is the useful one.
#: `github.event.*` fields are populated from the webhook payload, which for
#: pull requests, issues, comments and pushes is authored by whoever opened
#: them. `inputs.*` is supplied by whoever triggered a `workflow_dispatch` or
#: called a reusable workflow.
UNTRUSTED_CONTEXTS: List[UntrustedContext] = [
    UntrustedContext(
        r"github\.event\.issue\.(title|body)",
        "issue title/body",
    ),
    UntrustedContext(
        r"github\.event\.(comment|discussion_comment|review_comment)\.body",
        "comment body",
    ),
    UntrustedContext(
        r"github\.event\.discussion\.(title|body)",
        "discussion title/body",
    ),
    UntrustedContext(
        r"github\.event\.review\.body",
        "review body",
    ),
    UntrustedContext(
        r"github\.event\.pull_request\.(title|body)",
        "pull request title/body",
    ),
    UntrustedContext(
        r"github\.event\.pull_request\.head\.(ref|label)",
        "pull request branch name",
    ),
    UntrustedContext(
        r"github\.event\.pull_request\.head\.repo\.(default_branch|description|homepage)",
        "fork repository metadata",
    ),
    UntrustedContext(
        r"github\.event\.head_commit\.(message|author\.(name|email))",
        "commit message or author",
    ),
    UntrustedContext(
        r"github\.event\.commits\[[^\]]*\]\.(message|author\.(name|email))",
        "commit message or author",
    ),
    UntrustedContext(
        r"github\.event\.workflow_run\.(head_branch|display_title)",
        "triggering workflow run metadata",
    ),
    UntrustedContext(
        r"github\.event\.workflow_run\.head_commit\.message",
        "commit message from the triggering run",
    ),
    UntrustedContext(
        r"github\.event\.pages\[[^\]]*\]\.page_name",
        "wiki page name",
    ),
    UntrustedContext(
        r"github\.head_ref",
        "source branch name",
    ),
    UntrustedContext(
        r"github\.event\.inputs\.[A-Za-z0-9_-]+",
        "workflow_dispatch input",
    ),
    UntrustedContext(
        # The lookbehind must exclude `.` as well as word characters, or
        # `steps.x.outputs.inputs.name` matches on its trailing `inputs.`.
        r"(?<![\w.])inputs\.[A-Za-z0-9_-]+",
        "workflow input",
    ),
]

#: Actions whose named input is executed as code, so interpolating untrusted
#: data into it is as dangerous as interpolating into `run:`.
CODE_EXECUTING_ACTION_INPUTS = {
    "actions/github-script": ("script",),
}


class UntrustedUse(NamedTuple):
    """An untrusted expression found inside a string."""

    expression: str
    description: str


def iter_expressions(value: str) -> Iterator[str]:
    """Yield the inside of each ``${{ }}`` interpolation in ``value``."""
    for match in EXPRESSION.finditer(value):
        yield match.group(1)


def find_untrusted(value: str) -> List[UntrustedUse]:
    """Find attacker-controllable expressions interpolated into a string.

    Args:
        value: Any workflow string, typically a ``run:`` body.

    Returns:
        One entry per untrusted interpolation, in the order they appear.
        A single ``${{ }}`` reports at most once, using its most specific
        matching context.
    """
    uses: List[UntrustedUse] = []

    for expression in iter_expressions(value):
        for context in UNTRUSTED_CONTEXTS:
            if re.search(context.pattern, expression):
                uses.append(UntrustedUse(expression.strip(), context.description))
                break

    return uses


#: Piping a downloaded script straight into a shell. Whatever the remote host
#: serves at run time executes with the job's privileges, so a compromise of
#: that host is a compromise of the workflow.
REMOTE_SCRIPT_EXECUTION = re.compile(
    r"\b(curl|wget)\b[^|;&\n]*\|[^|\n]*\b(bash|sh|zsh|python[0-9.]*)\b",
)


def find_remote_script_execution(value: str) -> Optional[str]:
    """Return the offending command if ``value`` pipes a download into a shell."""
    match = REMOTE_SCRIPT_EXECUTION.search(value)
    return match.group(0).strip() if match else None


#: Expressions that serialize a whole context, exposing every value in it.
#: `toJSON(secrets)` dumps every secret; `toJSON(github.event)` dumps the
#: entire attacker-controlled webhook payload into whatever consumes it.
DANGEROUS_SERIALIZATIONS = re.compile(
    r"toJSON\s*\(\s*(secrets|github\.event|github)\s*\)",
    re.IGNORECASE,
)


def find_dangerous_serialization(value: str) -> Optional[str]:
    """Return the offending expression if ``value`` serializes a whole context."""
    match = DANGEROUS_SERIALIZATIONS.search(value)
    return match.group(0).strip() if match else None
