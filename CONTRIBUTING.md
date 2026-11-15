# Contributing to zerot

Thanks for your interest in improving zerot! This document explains how to
set up a development environment and where the important logic lives.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]      # installs zerot + pytest + ruff
```

Run the test suite and linter:

```bash
pytest                     # runs tests/ (sample lives in tests/samples)
ruff check src tests zerot_lite.py
```

## Project layout

| Path | Responsibility |
| --- | --- |
| `src/zerot/catalog.py` | **The source of truth** for which code points are dangerous and why. |
| `src/zerot/engine.py` | File reading, per-character classification, bidi balance, mixed-script. |
| `src/zerot/report.py` | Markdown / JSON / text / SARIF renderers. |
| `src/zerot/cli.py` | The `zerot` command (scan / check). |
| `zerot_lite.py` | A **self-contained** single-file build of the engine (no install). |

## Adding a new category

1. Add an entry to `CATEGORIES` in `catalog.py` with
   `(label, severity, description)`. Severities: `low < medium < high < critical`.
2. Extend `classify()` (and helper predicates) to attach the category to the
   relevant code points.
3. Mirror the change in `zerot_lite.py` — the lite file embeds the same logic
   and must stay in sync.
4. Add a test in `tests/test_engine.py` and, if useful, a fixture character to
   `tests/samples/evil_sample.py`.

## Code style

- `ruff` is the linter (`select = E, F, W, I`).
- Keep `zerot_lite.py` dependency-free (standard library only).
- All user-facing text and reports are written in English; the README also
  contains a Chinese section.

## Pull requests

- Keep changes focused and add tests.
- Update `CHANGELOG.md` under *Unreleased*.
- Ensure `pytest` and `ruff` pass in CI.
