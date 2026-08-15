# ghast ☠️ GitHub Actions Security Tool
<img width="256" alt="Friendly Ghost on Purple Background" src="https://github.com/user-attachments/assets/4c517c50-8688-4bcb-9399-c17e4a8f375e" />

**ghast** is a security auditing and remediation tool for GitHub Actions workflows. It detects misconfigurations, security vulnerabilities, and anti-patterns in your workflows based on industry best practices.

Inspired by [this security guide](https://www.wiz.io/blog/github-actions-security-guide) from Wiz, ghast helps prevent recent high-profile supply chain attacks like those affecting tj-actions.

---

## 🔍 Key Features

- **Security Scanning**: Detect critical security vulnerabilities like Poisoned Pipeline Execution (PPE)
- **Workflow Hardening**: Enforce least-privilege permissions and proper action pinning
- **Auto-Remediation**: Fix common security issues automatically
- **Multiple Output Formats**: Console, JSON, SARIF (for GitHub Code Scanning), and HTML reports
- **CI/CD Integration**: Run in CI/CD pipelines with configurable severity thresholds
- **Interactive Mode**: Review and approve fixes one by one
- **Comprehensive Rules**: 15+ security rules based on industry best practices

---

## 🚨 Key Security Checks

| Category | Rules |
|----------|-------|
| **Critical** | Poisoned Pipeline Execution (PPE), Exposed Secrets, Token Security |
| **High** | Command Injection, Environment Variable Injection, Overly Permissive Permissions |
| **Medium** | Action Pinning, Deprecated Actions, Reusable Workflow Safety |
| **Low** | Timeouts, Shell Specifications, Workflow Names |

### Built-in Rules

| ID | Category | Default Severity |
|----|----------|------------------|
| `permissions` | security | HIGH |
| `poisoned_pipeline_execution` | security | CRITICAL |
| `command_injection` | security | HIGH |
| `environment_injection` | security | HIGH |
| `token_security` | security | HIGH |
| `action_pinning` | security | MEDIUM |
| `timeout` | best-practice | LOW |
| `shell_specification` | best-practice | LOW |
| `workflow_name` | best-practice | LOW |
| `deprecated_actions` | best-practice | MEDIUM |
| `continue_on_error` | best-practice | MEDIUM |
| `reusable_workflow_inputs` | best-practice | MEDIUM |

---

## 📋 Installation

Install the latest release from PyPI:

```bash
pip install ghast
```

To install from source:

```bash
git clone https://github.com/seanwevans/ghast.git
cd ghast
pip install -e .
```

---

## 🧰 Quick Start

Scan your GitHub Actions workflows for security issues:

```bash
# Scan a repository
ghast scan /path/to/repo

# Apply automatic fixes
ghast fix /path/to/repo

# Generate a comprehensive security report
ghast report /path/to/repo --output security-report.html

# Integration with GitHub Code Scanning
ghast scan /path/to/repo --output sarif --output-file ghast-results.sarif
```

---

## 🤖 Use as a GitHub Action

```yaml
name: Workflow security
on: [push, pull_request]

permissions: read-all

jobs:
  ghast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: seanwevans/ghast@v1
        with:
          severity-threshold: HIGH
```

### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Repository root, or a single workflow file, to scan |
| `severity-threshold` | `LOW` | Minimum severity to report and fail on |
| `config` | — | Path to a ghast YAML config file |
| `disable` | — | Whitespace-separated rule ids to disable |
| `output` | `text` | `text`, `json`, `sarif` or `html` |
| `output-file` | — | Write results here instead of stdout |
| `fail-on-findings` | `true` | Fail the step when findings are reported |
| `strict` | `false` | Enable strict mode |
| `version` | — | PyPI version to install; defaults to the action's own source |
| `python-version` | — | Set up this Python; defaults to the runner's |

### Action outputs

| Output | Description |
|--------|-------------|
| `exit-code` | `0` clean, `1` findings, `2` ghast failed to run |
| `findings` | `true` when findings at or above the threshold were reported |

### Upload to GitHub Code Scanning

```yaml
      - uses: seanwevans/ghast@v1
        with:
          output: sarif
          output-file: ghast.sarif
          fail-on-findings: false     # let Code Scanning own the gate
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ghast.sarif
```

That job needs `security-events: write`.

---

## 🪝 Use as a pre-commit hook

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/seanwevans/ghast
    rev: v0.2.0
    hooks:
      - id: ghast
```

Use `ghast-strict` instead to fail only on `HIGH` and above. Both hooks run
whenever a file under `.github/workflows/` changes and scan the whole
repository, since rules like `permissions` reason about a complete workflow
rather than a changed line.

---

## 🧪 Testing

Install test dependencies and run the suite with:

```bash
pip install -e .[test]
pytest
```

## 🛠️ Contributing to ghast

Set up the project's own pre-commit hooks to format and lint before each commit:

```bash
pip install pre-commit
pre-commit install
```

Run all hooks against the entire codebase with:

```bash
pre-commit run --all-files
```

---

## 📊 Example Output

```
🔍 Scanning .github/workflows/ci.yml...

File: .github/workflows/ci.yml
🚨 CRITICAL: Poisoned Pipeline Execution vulnerability: job 'build' uses pull_request_target trigger with checkout of untrusted code
  Rule: poisoned_pipeline_execution
  File: .github/workflows/ci.yml:15
  Remediation: Use pull_request trigger instead, or if pull_request_target is required, do not check out untrusted code

❗ HIGH: Missing explicit permissions at workflow level
  Rule: permissions
  File: .github/workflows/ci.yml
  Remediation: Add 'permissions: read-all' at the top level of the workflow

⚠️ MEDIUM: Step 2 in job 'build' is not pinned to a specific commit SHA: actions/checkout@v3
  Rule: action_pinning
  File: .github/workflows/ci.yml:18
  Remediation: Pin to a specific commit SHA for better security

✅ Fixed permissions issue in .github/workflows/ci.yml
```

---

## 🛠️ Detailed Usage

### Scanning Workflows

```bash
# Basic scan
ghast scan /path/to/repo

# Only show high and critical issues
ghast scan /path/to/repo --severity-threshold HIGH

# Output as JSON
ghast scan /path/to/repo --output json

# Write results to a file
ghast scan /path/to/repo --output-file results.txt

# Show detailed information for each finding
ghast scan /path/to/repo --verbose
```

### Exit codes

`ghast scan` distinguishes "your workflows have problems" from "ghast could
not run", so it can be used as a required CI check:

| Code | Meaning |
|------|---------|
| `0` | No findings at or above the severity threshold |
| `1` | Findings at or above the severity threshold |
| `2` | ghast could not complete the run — bad config, no workflows found, unreadable file, invalid arguments |

The findings notice is written to stderr, so `--output json` and
`--output sarif` write clean, parseable documents to stdout:

```bash
ghast scan . --output json | jq '.findings[] | select(.severity == "CRITICAL")'
```

To fail a build only on serious issues while still printing everything:

```bash
ghast scan . --severity-threshold HIGH
```

### Fixing Issues

```bash
# Apply automatic fixes
ghast fix /path/to/repo

# Preview fixes without applying
ghast fix /path/to/repo --dry-run

# Interactively review and apply fixes
ghast fix /path/to/repo --interactive

# Fix only critical issues
ghast fix /path/to/repo --severity-threshold CRITICAL
```

### Configuration

```bash
# Use a custom config file
ghast scan /path/to/repo --config ghast.yml

# Generate a default config file
ghast config --generate --output ghast.yml

# Disable specific rules (by rule ID; run `ghast rules` to list them)
ghast scan /path/to/repo --disable token_security --disable deprecated_actions
```

### Reporting

```bash
# List all available rules
ghast rules

# Generate a comprehensive report
ghast report /path/to/repo --output report.html

```

---

## ⚙️ Configuration File

ghast can be configured using a YAML configuration file.

**Config keys are rule IDs** — the same names shown in findings and listed by
`ghast rules`. There is one name per rule, everywhere.

A complete example with default settings is available in `examples/ghast.yml`.
Generate a fresh one at any time with `ghast config --generate --output ghast.yml`.

```yaml
# Enable/disable rules, keyed by rule ID
permissions: true
poisoned_pipeline_execution: true
command_injection: true
environment_injection: false   # off by default; set true to enable
token_security: true
action_pinning: true
timeout: true
shell_specification: true
workflow_name: true
deprecated_actions: true
continue_on_error: true
reusable_workflow_inputs: true

# Configure severity thresholds
severity_thresholds:
  timeout: "LOW"
  token_security: "HIGH"
  poisoned_pipeline_execution: "CRITICAL"

# Auto-fix settings
auto_fix:
  enabled: true
  rules:
    timeout: true
    shell_specification: true
    deprecated_actions: true
    workflow_name: true

# Default timeouts for auto-fix
default_timeout_minutes: 15

# Default version replacements for deprecated actions
default_action_versions:
  actions/checkout@v1: actions/checkout@v3
  actions/setup-python@v1: actions/setup-python@v4
```

### Migrating from `check_*` names

Earlier versions used a separate set of `check_*` config keys that did not
match the rule IDs. Most of them silently had no effect. The old names are
still accepted and now do what they always claimed to, but ghast prints a
warning telling you what to rename them to:

| Old key | Rule ID |
|---------|---------|
| `check_timeout` | `timeout` |
| `check_shell` | `shell_specification` |
| `check_deprecated` | `deprecated_actions` |
| `check_workflow_name` | `workflow_name` |
| `check_continue_on_error` | `continue_on_error` |
| `check_tokens` | `token_security` |
| `check_reusable_inputs` | `reusable_workflow_inputs` |
| `check_ppe_vulnerabilities` | `poisoned_pipeline_execution` |
| `check_command_injection` | `command_injection` |
| `check_env_injection` | `environment_injection` |

`check_runs_on` and `check_inline_bash` named rules that were never
implemented. They still load, with a warning, and can be deleted.

---

## 🔒 Understanding GitHub Actions Security Risks

GitHub Actions workflows can introduce security risks if not properly configured:

1. **Poisoned Pipeline Execution (PPE)**: Occurs when high-privilege triggers run untrusted code with access to secrets. ghast treats `pull_request_target`, `workflow_run`, `issue_comment`, `pull_request_review`, `pull_request_review_comment` and `discussion_comment` as high-privilege.
2. **Over-privileged Workflows**: Workflows with unnecessary write permissions increase attack surface
3. **Unpinned Actions**: Non-SHA-pinned actions can change unexpectedly, introducing malicious code
4. **Command Injection**: `${{ }}` is substituted into a `run:` script *before* the shell sees it, so untrusted values are executed rather than passed as data
5. **Token Exposure**: Hardcoded tokens or `toJSON(secrets)` usage can leak sensitive credentials

### Untrusted expression contexts

The `command_injection` rule flags attacker-controllable values interpolated
into a `run:` block or into an action input that is executed as code (such as
`actions/github-script`'s `script`). The tracked contexts are:

`github.event.issue.title`/`.body` · `github.event.comment.body` ·
`github.event.discussion.title`/`.body` · `github.event.discussion_comment.body` ·
`github.event.review.body` · `github.event.review_comment.body` ·
`github.event.pull_request.title`/`.body` ·
`github.event.pull_request.head.ref`/`.label` ·
`github.event.pull_request.head.repo.default_branch`/`.description`/`.homepage` ·
`github.event.head_commit.message`/`.author.*` · `github.event.commits[*].message`/`.author.*` ·
`github.event.workflow_run.head_branch`/`.display_title`/`.head_commit.message` ·
`github.event.pages[*].page_name` · `github.head_ref` ·
`github.event.inputs.*` · `inputs.*`

Passing untrusted data through `env:` and referencing it as a quoted shell
variable is GitHub's recommended mitigation, so ghast deliberately does **not**
flag that pattern.

ghast helps identify and remediate these risks before they can be exploited.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

Please note that this project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🙏 Acknowledgements

- [Wiz](https://www.wiz.io/) for their comprehensive [GitHub Actions security guide](https://www.wiz.io/blog/github-actions-security-guide)
- The security researchers who documented GitHub Actions vulnerabilities
- The open source community for various security tools and libraries that inspired this project

## Disclaimer

This project is not affiliated with GitHub, and results produced by **ghast** do not guarantee complete security of your workflows.
