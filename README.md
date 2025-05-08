# ghast ☠ GitHub Actions Security Tool

**ghast** is a command-line tool that audits and fixes misconfigurations in GitHub Actions workflows. 
It catches security footguns, enforces CI/CD best practices, and can even repair common issues automatically.
Inspired by this [article](https://www.wiz.io/blog/github-actions-security-guide) from this [thread](https://news.ycombinator.com/item?id=43901190).

---

## 🚀 Features

- 🔍 Static analysis of `.github/workflows/*.yml`
- 🛠️ Auto-fix mode for safe remediations
- ✅ Configurable rules via YAML or CLI flags
- 🧩 Subcommand CLI (`ghast scan`, `ghast fix`, etc.)
- 🕵️ CI-friendly and scriptable

---

## 📦 Installation

```bash
pip install .
```

Or with local editable mode for development:

```bash
pip install -e .
```

---

## 🧰 Usage

### 🔎 Scan for problems (read-only)

```bash
ghast scan /path/to/repo
```

### 🛠️ Apply safe fixes

```bash
ghast fix /path/to/repo
```

### 🧪 Strict mode (enforce extra warnings)

```bash
ghast scan /path/to/repo --strict
```

### ⚙️ Use a custom config file

```bash
ghast scan /path/to/repo --config ghast.yml
```

### 🚫 Disable specific rules

```bash
ghast scan /path/to/repo --disable check_tokens --disable check_deprecated
```

---

## 📋 Available Subcommands

| Command       | Purpose                                    |
|---------------|---------------------------------------------|
| `scan`        | Audit workflows for misconfigurations       |
| `fix`         | Apply safe, automatic remediations          |
| `config`      | View or validate current config             |
| `rules`       | List all supported security checks          |

---

## ✅ Rules

| Rule                     | Description                                                               |
|--------------------------|---------------------------------------------------------------------------|
| `check_timeout`          | Ensures long jobs have `timeout-minutes:`                                 |
| `check_shell`            | Adds `shell: bash` for multiline `run:` blocks                            |
| `check_deprecated`       | Warns on old actions like `actions/checkout@v1`                           |
| `check_runs_on`          | Warns on ambiguous/self-hosted runners                                    |
| `check_workflow_name`    | Encourages top-level `name:` for visibility                               |
| `check_continue_on_error`| Warns if `continue-on-error: true` is used                                |
| `check_tokens`           | Flags hardcoded access tokens                                             |
| `check_inline_bash`      | (Alias for `check_shell`)                                                 |
| `check_reusable_inputs`  | Ensures `uses:` workflows define `inputs:` and don't abuse `with:`        |
