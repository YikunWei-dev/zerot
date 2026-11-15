> [中文](README_zh.md) |  English

# zerot

> Detect dangerous Unicode characters hiding in your source code.

[![CI](https://github.com/YikunWei-dev/zerot/actions/workflows/ci.yml/badge.svg)](https://github.com/YikunWei-dev/zerot/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/zerot.svg)](https://pypi.org/project/zerot/)
[![Python](https://img.shields.io/pypi/pyversions/zerot.svg)](https://pypi.org/project/zerot/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-blue.svg)](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support)

`zerot` scans code for the Unicode tricks that silently break, spoof, or
backdoor software:

| Category | Risk | Severity |
|---|---|---|
| **Zero-width** (`U+200B`, …) | Invisible characters that hide or alter code logic | high |
| **Bidirectional override** (`U+202A`–`U+202E`, `U+2066`–`U+2069`) | Make the *displayed* order differ from the *executed* order — the classic *Trojan Source* attack | critical |
| **Unbalanced bidi** | A directional control that was never closed | critical |
| **Confusable / homoglyph** | Visually mimics an ASCII letter but is a different code point (Cyrillic, Greek, fullwidth, …) | high |
| **Fullwidth / compatibility** | Fullwidth / compatibility-form characters | medium |
| **Compatibility masquerade** | Collapses to a single ASCII character under NFKC normalization (e.g. mathematical bold / circled letters) | medium |
| **Suspicious whitespace** | Looks like a space but isn't | medium |
| **Control character** | Non-printable control characters | high |
| **Noncharacter** | Permanently reserved non-character code points | medium |
| **Mixed-script token** | An identifier mixing ASCII with a non-ASCII script (e.g. the Cyrillic а/р in `арр = 1`) | high |

`zerot` reports every issue as a **Markdown report**, with line/column, code
point, category and a "looks like" annotation.

---

## Two modes

### 1. Lite mode — zero-install, single file

`zerot_lite.py` is a fully self-contained single-file script (standard library
only). Drop it into any repo and run it — no `pip install` required.

```bash
# Scan the current directory (recursive)
python3 zerot_lite.py scan .

# Scan a specific file
python3 zerot_lite.py scan src/app.py

# Write a Markdown report
python3 zerot_lite.py scan . --md report.md

# Scan only certain extensions, exclude directories
python3 zerot_lite.py scan . --include "*.py" --exclude "*.min.js" --no-recursive
```

Exit codes: `0` = clean, `1` = issues found (useful for CI), `2` = usage error.

### 2. Software mode — installable, more features

```bash
pip install .            # or: pip install zerot
```

You then get:

- a `zerot` command (no more `python3 zerot_lite.py`)
- richer options: JSON / text / Markdown output
- a `.zerot.json` config file (commit it to share the scanning policy with your team)
- the `zerot check` sub-command, designed for CI (non-zero exit on issues)

```bash
# Write a Markdown report to a file
zerot scan . --format md -o report.md

# Emit JSON for other tools
zerot scan . --format json -o report.json

# CI: fail on high/critical (default)
zerot check .

# Fail only at a given severity
zerot check . --fail-on critical

# Use a config file
zerot scan . --config .zerot.json
```

#### Example `.zerot.json`

```json
{
  "exclude": ["vendor", "*.min.js"],
  "include": ["*.py", "*.js", "*.go", "*.c", "*.rs"],
  "max_size": 2097152,
  "fail_on": "high",
  "format": "md"
}
```

---

## Detection details

### Trojan Source (directional-control attacks)
`zerot` doesn't just find directional controls like `U+202E` (RTL Override) — it
also **tracks their stack-based pairing**: if an embedding/isolate is still open
at end of file, it additionally reports `bidi_unbalanced` and prints a prominent
warning banner at the top of the report.

### Homoglyphs / confusables
Ships large tables of "looks like ASCII" characters (Cyrillic, Greek, fullwidth,
…). Every hit is annotated with "looks like `a` / `e` / `o` …". **Mixed-script
identifiers** (ASCII and non-ASCII letters in the same token) get extra
highlighting — these are the most dangerous because they're nearly impossible to
spot by eye.

### Zero-width characters
Covers the whole family of zero-width / invisible characters
(`U+200B/200C/200D/2060/FEFF`, …) including variation selectors VS-1..VS-32.

---

## Using it in CI

### As a GitHub Action (recommended — lands in the Security tab)

zerot ships an `action.yml` you can drop into a workflow. Results are uploaded as
**SARIF** to GitHub code scanning (Security tab):

```yaml
# .github/workflows/zerot.yml
name: Zerot
on: [push, pull_request]
jobs:
  unicode-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: YikunWei-dev/zerot@v1        # or pin to a specific commit
        with:
          targets: "src tests"
          fail-on: high
```

### As a CLI (any CI)

```yaml
# Software mode
- name: Scan for Unicode tricks
  run: |
    pip install .
    zerot check . --fail-on critical
```

Or use the single file with no install:

```yaml
- name: Scan with zerot lite
  run: python3 zerot_lite.py scan . --no-recursive
```

---

## Report formats

The default output is a **Markdown** report. Also supported:

- `--format json` — structured data for other tools.
- `--format text` — compact terminal view (auto-colored; disable with `--no-color`).
- `--format sarif` — **SARIF 2.1.0**, ready to upload to GitHub code scanning:

```bash
zerot scan . --format sarif -o zerot.sarif
# then upload with github/codeql-action/upload-sarif in GitHub Actions
```

---

## As a pre-commit hook

This project provides pre-commit hooks (see `.pre-commit-hooks.yaml`). Add to your
repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/YikunWei-dev/zerot
    rev: v1.0.0
    hooks:
      - id: zerot            # requires: pip install zerot
      # - id: zerot-lite     # no install; runs the standalone zerot_lite.py
```

Changed files are scanned automatically on commit; high/critical findings block
the commit.

---

## Configuration (`.zerot.json`)

```json
{
  "exclude": ["vendor", "*.min.js"],
  "include": ["*.py", "*.js", "*.go", "*.c", "*.rs"],
  "ignore":  ["tests/fixtures/known_bad.py"],
  "skip_strings": true,
  "max_size": 2097152,
  "fail_on": "high",
  "format": "md"
}
```

| Key | Description |
|---|---|
| `exclude` | Files/directories to skip (fnmatch, repeatable) |
| `include` | Only scan files matching this pattern |
| `ignore` | Ignore *findings* whose file path matches (whitelist) |
| `skip_strings` | Whether to skip comments and string literals (default `true`) |
| `max_size` | Skip files larger than this many bytes |
| `fail_on` | Exit non-zero once a finding reaches this severity (`low/medium/high/critical`) |
| `format` | Default report format |

---

## Comments and string literals are skipped by default

`zerot` is **read-only**: it only reports findings and never modifies your source
files (some "suspicious" characters may be intentional, e.g. circled letters in a
brand name).

Moreover, the characters that actually matter are the ones written in **code
logic**; text inside comments and string literals (e.g. a C `printf("…")`, a
`# comment`) is just data and does not affect how the program executes — it is
usually intentional. Therefore `zerot` **does not scan** comments and string
content by default:

```bash
# Default: skip comments / strings, scan only code
zerot scan .

# Also scan what's inside comments and strings (--scan-strings)
zerot scan . --scan-strings
```

Supported languages: C/C++/C#/Java/JS/TS/Go/Rust/Swift/Kotlin/PHP/Objective-C,
etc. (using `//`, `/* */`, quoted strings); Python/Ruby/Shell/YAML/TOML, etc.
(using `#` comments and triple-quoted strings). Files with other extensions are
scanned verbatim as plain text.

---

## Project structure

```
zerot/
├── pyproject.toml
├── action.yml              # GitHub Action (composite)
├── .pre-commit-hooks.yaml  # pre-commit hook definitions
├── zerot_lite.py           # Lite mode: single-file, zero-dependency
├── src/zerot/              # Software-mode package source
│   ├── catalog.py          # Dangerous code-point catalog (single source of truth)
│   ├── engine.py           # Scanning engine
│   ├── report.py           # Markdown / JSON / text / SARIF reports
│   ├── cli.py              # Command-line interface
│   ├── config.py           # Config loading
│   └── __main__.py
├── tests/                  # pytest tests + fixtures
├── examples/               # Sample report
└── README.md               # this file (English)
```

## License

MIT © zerot contributors
