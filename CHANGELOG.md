# Changelog

All notable changes to ghast are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This release fixes several problems that made previous versions unsafe or
ineffective. Read the *Fixed* section before upgrading.

### Fixed

- **The published package could not be imported.** `packages` was a literal
  list, so the wheel shipped only `__init__.py`, `cli.py` and `py.typed`;
  every subpackage was dropped and `import ghast` raised `ModuleNotFoundError`.
  A CI job now installs the built wheel into a clean environment outside the
  checkout and runs it.
- **`ghast fix` corrupted the workflows it edited.** A PyYAML load/dump cycle
  rewrote `on:` as `true:` under YAML 1.1 — leaving a workflow with no
  triggers that could never run — discarded every comment, and re-emitted
  block scalars as folded strings. Rewriting now uses ruamel.yaml in
  round-trip mode, and the result is re-parsed and checked before it replaces
  anything.
- **Most rules could not be configured.** Rule identity was spelled three
  different ways, so seven of twelve rules ignored their config entirely,
  `permissions` and `action_pinning` had no config key at all, and
  `environment_injection` could never be enabled.
- **Scanning silently did nothing** in one interim state, because an internal
  error was reported as a `file_error` finding about the user's file. Bugs in
  ghast now exit 2 instead of masquerading as findings.
- **SARIF output was not valid SARIF.** `fixes` entries lacked the required
  `artifactChanges`, and `helpText` is not a SARIF property, so remediation
  never reached anyone reading the alerts.
- `ghast fix` no longer leaves a `.bak` file beside every workflow it changes.

### Added

- **Composite actions are scanned.** An `action.yml` runs steps with the same
  supply-chain exposure as a workflow; step-level rules now apply to them.
- **Inline suppressions** — `# ghast: ignore`, `# ghast: ignore[rule_id]` and
  `# ghast: ignore-file` — so a deliberate exception can be justified in place.
- **Baseline files** — `ghast baseline` records what is currently outstanding
  and `ghast scan --baseline` reports only new findings, so a repository with
  existing issues can gate on regressions without fixing everything first.
- **Distinct exit codes**: `0` clean, `1` findings at or above the threshold,
  `2` ghast could not run. Machine-readable output is now clean on stdout.
- **A GitHub Action** (`uses: seanwevans/ghast@v1`) and **pre-commit hooks**
  (`ghast`, `ghast-strict`).
- **Wider injection detection.** The untrusted-expression set grew from four
  hardcoded patterns to fifteen contexts covering issue, comment, discussion,
  review, pull request, commit, `workflow_run`, `github.head_ref` and
  `inputs.*` values, plus remote scripts piped into a shell.
- More high-risk triggers for poisoned pipeline execution: `issue_comment`,
  `pull_request_review`, `pull_request_review_comment`, `discussion_comment`.
- Scanning a bare directory of workflow files, not just a repository root.
- SARIF `partialFingerprints`, so GitHub Code Scanning can follow a finding
  across commits rather than reopening it whenever a file moves.
- CodeQL analysis and Dependabot for this repository.

### Changed

- **Config keys are rule IDs.** The old `check_*` names still load and now do
  what they always claimed to, with a warning naming the replacement.
  `check_runs_on` and `check_inline_bash` named rules that were never
  implemented and have no effect.
- **Findings report bare rule IDs.** `check_token_security` is now
  `token_security` in JSON and SARIF output.
- Poisoned pipeline execution reports once per job rather than once per step;
  a single root cause previously produced six near-identical findings.
- The duplicate credential-persistence finding is gone; it was reported by two
  rules at once.
- Python 3.10 is the minimum. The declared floor of 3.8 was never true —
  `yaml_handler` uses syntax that cannot be imported before 3.10 — and CI only
  ever tested 3.10+. 3.12 and 3.13 are now tested.
- SARIF remediation moved from the invalid `fixes` array to
  `properties.remediation`.

### Removed

- `TriggerRule`, along with `JobRule.check_job_runner`,
  `WorkflowRule.check_workflow_permissions`, `JobRule.check_job_permissions`
  and `Fixer.fix_runs_on`. None were reachable: no rule inherited or called
  them, and the two permission helpers were shadowed at every call site.

### Security

- `toJSON(secrets)` is matched case-insensitively. The check was a
  case-sensitive test for the exact string `toJson(secrets)`, so GitHub's own
  spelling went undetected, as did `toJSON(github.event)`.
- Actions are checked for credential persistence, unpinned `uses` and
  untrusted interpolation, which was never looked at before.
- The SARIF suppression-file hash moved from MD5 to SHA-256.

## [0.1.0]

Initial release.

[Unreleased]: https://github.com/seanwevans/ghast/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/seanwevans/ghast/releases/tag/v0.1.0
