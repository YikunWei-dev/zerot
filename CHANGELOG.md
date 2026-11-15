# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- **Read-only by design**: zerot only reports findings and never modifies your
  source files (some "suspicious" characters may be intentional, e.g. circled
  letters in a brand name).
- **Comments and string literals are no longer scanned by default**, since text
  there (e.g. C `printf("…")`, Python `"""…"""`, `# comments`) does not affect
  how the code executes. A code-aware masker blanks comments and string spans
  (preserving line/column positions) before classification.
- New `--scan-strings` / `skip_strings` config option to opt back into scanning
  comment and string content.

### Fixed
- Added the missing `.pre-commit-hooks.yaml` that the README already documented
  (hooks `zerot` and `zerot-lite`).
- **GitHub Action** now installs zerot from its own checkout
  (`pip install "${{ github.action_path }}"`) instead of pulling from PyPI, so
  the action uses the exact code at the referenced ref (previously it would fail
  or scan with a stale published version).
- Unified the package version to a single source of truth
  (`zerot.__version__`), read via `project.dynamic`.
- **Fewer false positives**: fullwidth *punctuation* (`，；：（）` …) is no longer
  flagged — only fullwidth *letters/digits* (which actually spoof ASCII) keep the
  `fullwidth` category. This stops Chinese documentation from flooding the report
  (a recursive self-scan dropped from 232 to ~40 findings).
- **Virtual environments are now excluded by default**: `.venv` / `venv` were
  added to `DEFAULT_EXCLUDE`, so third-party dependencies are no longer scanned.
  Both fixes apply to the package engine and to `zerot_lite.py`.
- **Multi-line block comments are now masked correctly**: `mask_non_code` carries
  `/* ... */` state across lines, so dangerous characters *inside* a comment that
  spans several lines are no longer false-positively reported. Previously each line
  was masked independently, leaking the comment's interior.
- **All unclosed bidi controls are now reported**: the EOF balance check used to
  flag only the first unclosed `U+202A`–`U+202E`/`U+2066`–`U+2068`. The bidi stack
  now records positions, so every unterminated override/isolate is flagged. Each is
  folded into its own opening finding (no duplicate entry at the same position).

### Added
- Unit tests for `report` (markdown/json/sarif), `cli` (option merge, fail
  thresholds, end-to-end run) and `config`; plus a `zerot_lite.py` smoke test.
- **Bilingual README**: `README.md` is now English (GitHub default) with a
  `README_zh.md` Chinese version, cross-linked at the top.

### Removed
- Dead code: `config.KNOWN_KEYS` (defined but never referenced) and
  `catalog.cp_name` (defined but never called).

## [1.0.0] - 2026-11-14

### Added
- First stable release.
- **Lite mode**: a single, dependency-free file `zerot_lite.py` (standard
  library only) that can be dropped into any repository and run with
  `python3 zerot_lite.py scan .`.
- **Software mode**: an installable `zerot` package with `scan` and `check`
  sub-commands (CI-friendly, non-zero exit on findings).
- Detection of nine categories of dangerous Unicode:
  - zero-width / invisible characters (including variation selectors VS-1..32),
  - bidirectional overrides / isolates (**Trojan Source**) with **stack-based
    balance checking** (unclosed controls are flagged separately),
  - homoglyph / confusable characters (Cyrillic, Greek, fullwidth, …) with a
    "looks like" annotation,
  - fullwidth / compatibility forms,
  - suspicious whitespace,
  - control characters (C0/C1),
  - non-characters,
  - mixed-script identifiers (ASCII + non-ASCII in the same token),
  - **compatibility masquerade** (NFKC form collapses to a single ASCII char,
    e.g. mathematical bold / circled letters).
- Markdown, JSON, plain-text and **SARIF 2.1.0** report formats (SARIF uploads
  to GitHub code scanning).
- Colorized terminal output (auto-detected, `--no-color` to disable).
- Configuration file `.zerot.json` with `exclude`, `include`, `ignore`,
  `max_size`, `fail_on` and `format`.
- Optional GitHub Action (`action.yml`), pre-commit hooks, and a CI workflow
  that tests on Python 3.8–3.13 and self-scans via code scanning.

[Unreleased]: https://github.com/YikunWei-dev/zerot/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/YikunWei-dev/zerot/releases/tag/v1.0.0
