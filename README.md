# ghast ☠️ GitHub Actions Security Tool

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

# Disable specific rules
ghast scan /path/to/repo --disable check_tokens --disable check_deprecated
```

### Reporting

```bash
# List all available rules
ghast rules

# Generate a comprehensive report
ghast report /path/to/repo --output report.html

# Generate SARIF output for GitHub Code Scanning
ghast scan /path/to/repo --output sarif --output-file ghast-results.sarif
```

---

## ⚙️ Configuration File

ghast can be configured using a YAML configuration file:

```yaml
# Enable/disable rules
check_timeout: true
check_shell: true
check_deprecated: true
check_runs_on: true
check_workflow_name: true
check_continue_on_error: true
check_tokens: true
check_inline_bash: true
check_reusable_inputs: true
check_ppe_vulnerabilities: true
check_command_injection: true
check_env_injection: true

# Configure severity thresholds
severity_thresholds:
  check_timeout: "LOW"
  check_tokens: "HIGH"
  check_ppe_vulnerabilities: "CRITICAL"

# Auto-fix settings
auto_fix:
  enabled: true
  rules:
    check_timeout: true
    check_shell: true
    check_deprecated: true
    check_workflow_name: true

# Default timeouts for auto-fix
default_timeout_minutes: 15

# Default version replacements for deprecated actions
default_action_versions:
  actions/checkout@v1: actions/checkout@v3
  actions/setup-python@v1: actions/setup-python@v4
```

---

## 🔒 Understanding GitHub Actions Security Risks

GitHub Actions workflows can introduce security risks if not properly configured:

1. **Poisoned Pipeline Execution (PPE)**: Occurs when high-privilege triggers like `pull_request_target` run untrusted code with access to secrets
2. **Over-privileged Workflows**: Workflows with unnecessary write permissions increase attack surface
3. **Unpinned Actions**: Non-SHA-pinned actions can change unexpectedly, introducing malicious code
4. **Command Injection**: Untrusted inputs interpolated into shell commands can lead to code execution
5. **Token Exposure**: Hardcoded tokens or `toJson(secrets)` usage can leak sensitive credentials

ghast helps identify and remediate these risks before they can be exploited.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

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
