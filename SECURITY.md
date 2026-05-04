# Security Policy

## Supported Versions

`ghast` is actively maintained on the latest released version.

| Version | Supported |
| --- | --- |
| Latest release on PyPI | ✅ |
| Older releases | ❌ |
| `main` branch (development snapshots) | Best effort |

If you are unsure whether your version is supported, please upgrade to the latest release before reporting.

---

## Reporting a Vulnerability

If you discover a security vulnerability in **ghast** itself (for example: code execution, unsafe file handling, dependency risks, or report-generation issues that could impact users), please report it privately.

### Preferred disclosure method

- Open a **private GitHub security advisory** in this repository ("Report a vulnerability" in the Security tab).

### If private advisory is unavailable

- Open a regular GitHub issue with minimal details and request a private follow-up channel from the maintainers.
- Do **not** publish exploit details, proof-of-concept payloads, or sensitive data publicly before a fix is available.

### What to include

Please include as much of the following as possible:

- A clear description of the issue and impact.
- Affected version(s) and installation method (PyPI/source).
- Reproduction steps and minimal proof of concept.
- Whether exploitation requires user interaction or special repository/workflow conditions.
- Any suggested mitigation or patch.

---

## Response Process

Maintainers will aim to:

1. Acknowledge the report within **5 business days**.
2. Validate and triage severity.
3. Develop and test a fix.
4. Coordinate a release and disclosure timeline with the reporter.

For high-impact vulnerabilities, maintainers may prioritize an out-of-band patch release.

---

## Disclosure Policy

- Please follow **responsible disclosure**.
- We request at least **90 days** before public disclosure, or until a patch is released (whichever comes first), unless otherwise coordinated with maintainers.

---

## Scope

This policy covers vulnerabilities in this repository's source code, packaging, and release artifacts.

This policy does **not** cover:

- Misconfigurations in third-party repositories scanned by `ghast`.
- Best-practice findings in user workflows that are expected outputs of the tool.

---

## Security Best Practices for Users

When using `ghast`:

- Keep `ghast` and dependencies up to date.
- Run scans in CI on trusted runners.
- Review auto-remediation changes before merging.
- Use SARIF/JSON outputs as inputs to your secure development lifecycle and code scanning workflows.
