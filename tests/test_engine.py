"""Tests for the zerot detection engine and lite CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from zerot import catalog
from zerot.engine import scan, scan_file
from zerot.report import render_json, render_markdown, render_sarif, render_text

SAMPLE = Path(__file__).parent / "samples" / "evil_sample.py"
LITE = Path(__file__).parent.parent / "zerot_lite.py"


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "sample.py"
    p.write_text(text, encoding="utf-8")
    return p


# --------------------------------------------------------------------------
# Catalog unit tests
# --------------------------------------------------------------------------
def test_zero_width_classification():
    for cp in (0x200B, 0xFEFF, 0x200D, 0x2060):
        cats = catalog.classify(cp)
        assert "zero_width" in cats or "bidi" in cats


def test_bidi_classification():
    assert "bidi" in catalog.classify(0x202E)
    assert "bidi" in catalog.classify(0x2066)


def test_confusable_lookalikes():
    assert catalog.CONFUSABLES[0x0430] == "a"  # Cyrillic а
    assert catalog.CONFUSABLES[0x03BF] == "o"  # Greek ο
    assert catalog.CONFUSABLES[0xFF41] == "a"  # fullwidth a


def test_control_detection():
    assert catalog.is_control(0x01)      # SOH
    assert catalog.is_control(0x7F)      # DEL
    assert catalog.is_control(0x9C)      # C1
    assert not catalog.is_control(0x09)  # TAB whitelisted
    assert not catalog.is_control(0x0A)  # LF whitelisted


def test_fullwidth_block():
    assert catalog.is_fullwidth(0xFF41)
    assert not catalog.is_fullwidth(0x0041)


def test_fullwidth_punctuation_not_flagged():
    # CJK punctuation is normal in prose; it must not produce "fullwidth" noise.
    assert "fullwidth" not in catalog.classify(0xFF0C)  # fullwidth comma
    assert "fullwidth" not in catalog.classify(0xFF08)  # fullwidth left paren
    assert "fullwidth" not in catalog.classify(0xFF1A)  # fullwidth colon
    # but fullwidth letters/digits are still flagged (they spoof ASCII)
    assert "fullwidth" in catalog.classify(0xFF41)      # fullwidth 'a'
    assert "fullwidth" in catalog.classify(0xFF10)      # fullwidth '0'


# --------------------------------------------------------------------------
# Engine tests
# --------------------------------------------------------------------------
def test_scan_sample_finds_categories():
    # scan with string/comment masking disabled so every category is exercised
    findings, skip = scan_file(str(SAMPLE), skip_strings=False)
    assert skip is None
    cats = set()
    for f in findings:
        cats.update(f.categories)
    # we expect at least these to be detected
    for expected in ("zero_width", "bidi", "confusable", "mixed_script",
                     "fullwidth", "suspicious_space", "bidi_unbalanced"):
        assert expected in cats, f"missing category {expected}: {cats}"


def test_mixed_script_points_at_nonascii():
    findings, _ = scan_file(str(SAMPLE))
    ms = [f for f in findings if "mixed_script" in f.categories]
    assert ms, "expected mixed_script findings"
    # the flagged char must be non-ASCII
    assert any(ord(f.char) > 127 for f in ms)


def test_bidi_unbalanced_detected():
    findings, _ = scan_file(str(SAMPLE))
    assert any("bidi_unbalanced" in f.categories for f in findings)


def test_multiline_block_comment_is_masked(tmp_path):
    # A /* */ comment spanning several lines must mask its interior, so
    # dangerous characters inside it are NOT reported.
    src = "/* a \u200b b\n   c \u200b d */\nint x = 1;\n"
    findings, _ = scan_file(_write(tmp_path, src))
    assert not any("zero_width" in f.categories for f in findings)


def test_multiple_unclosed_bidi_all_reported(tmp_path):
    # Every unclosed bidi control must be flagged, not just the first one.
    src = "a = 1 \u202e; b = 2 \u202e; c = 3;\n"
    findings, _ = scan_file(_write(tmp_path, src))
    unbalanced = [f for f in findings if "bidi_unbalanced" in f.categories]
    assert len(unbalanced) == 2


def test_skip_strings_masks_comments_and_literals():
    # dangerous chars inside comments and string literals must be ignored,
    # because they do not affect program execution.
    src = (
        "x = 1\u200b\n"                      # zero-width in code -> detected
        "# comment with zero-width \u200b here\n"   # inside comment -> ignored
        "s = 'fullwidth inside \uff41'\n"    # inside string -> ignored
        "y = \u0430\u0440\u0440rove()\n"     # Cyrillic in code -> detected
    )
    findings, _ = scan_file(_write_source(src))
    cats = set()
    for f in findings:
        cats.update(f.categories)
    assert "zero_width" in cats
    assert "confusable" in cats and "mixed_script" in cats
    # nothing from the comment / string literal should appear
    assert not any(f.char == "\uff41" for f in findings)


def test_scan_strings_flag_includes_literals():
    src = "s = 'fullwidth inside \uff41'\n"
    # by default skipped
    f1, _ = scan_file(_write_source(src))
    assert not any("fullwidth" in c.categories for c in f1)
    # with skip_strings=False the literal is scanned
    f2, _ = scan_file(_write_source(src), skip_strings=False)
    assert any("fullwidth" in c.categories for c in f2)


def _write_source(text: str) -> str:
    fd, name = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return name


def test_scan_directory_recursive(tmp_path):
    _write(tmp_path, "x = 1\u200b\n")           # zero-width
    sub = tmp_path / "sub"
    sub.mkdir()
    _write(sub, "y = 2\u0430\n")                 # Cyrillic a (confusable)
    res = scan([str(tmp_path)], recursive=True)
    assert res.files_scanned == 2
    assert any("zero_width" in f.categories for f in res.findings)
    assert any("confusable" in f.categories for f in res.findings)


def test_binary_skipped(tmp_path):
    p = tmp_path / "blob.bin"
    p.write_bytes(b"\x00\x01\x02\x03\x00\x00\x00\x00\x00\x00")
    res = scan([str(p)], skip_binary=True)
    assert res.files_scanned == 1
    assert res.files_skipped


# --------------------------------------------------------------------------
# Reporting tests
# --------------------------------------------------------------------------
def test_markdown_report_contains_sections():
    res = scan([str(SAMPLE)])
    md = render_markdown(res)
    assert "# Zerot Scan Report" in md
    assert "## Summary" in md
    assert "## Findings" in md
    assert "Trojan Source" in md  # because bidi present
    # every finding line should mention a code point
    assert "U+" in md


def test_json_report_roundtrip():
    res = scan([str(SAMPLE)])
    payload = json.loads(render_json(res))
    assert payload["highest_severity"] in catalog.SEVERITY_ORDER
    assert isinstance(payload["findings"], list)
    assert payload["findings"][0]["codepoint"].startswith("U+")


def test_text_report():
    res = scan([str(SAMPLE)])
    txt = render_text(res)
    assert "finding" in txt.lower()


# --------------------------------------------------------------------------
# Lite single-file CLI smoke test (no install required)
# --------------------------------------------------------------------------
@pytest.mark.skipif(not LITE.exists(), reason="zerot_lite.py missing")
def test_lite_cli_scan(tmp_path):
    out_md = tmp_path / "report.md"
    r = subprocess.run(
        [sys.executable, str(LITE), "scan", str(SAMPLE), "--md", str(out_md)],
        capture_output=True, text=True,
    )
    assert r.returncode == 1, r.stderr  # issues found
    assert out_md.exists()
    content = out_md.read_text(encoding="utf-8")
    assert "Zerot Scan Report" in content
    assert "Trojan Source" in content


# --------------------------------------------------------------------------
# SARIF, NFKC masquerade, ignore, color
# --------------------------------------------------------------------------
def test_sarif_renderer_structure():
    res = scan([str(SAMPLE)])
    sarif = json.loads(render_sarif(res))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "zerot"
    # one SARIF result is emitted per (finding, category)
    expected = sum(len(f.categories) for f in res.findings)
    assert len(sarif["runs"][0]["results"]) == expected
    # every result must reference a defined rule
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    for r in sarif["runs"][0]["results"]:
        assert r["ruleId"] in rule_ids
        assert "physicalLocation" in r["locations"][0]


def test_nfkc_masquerade_detected(tmp_path):
    # Mathematical bold capital A (U+1D400) normalizes via NFKC to ASCII 'A'
    # placed in code (not a string) so the default scanner still sees it
    p = _write(tmp_path, "secret = \U0001D400BC\n")
    findings, _ = scan_file(str(p))
    cats = set()
    for f in findings:
        cats.update(f.categories)
    assert "compat_masquerade" in cats


def test_ignore_skips_path(tmp_path):
    _write(tmp_path, "x = 1\u200b\n")
    res = scan([str(tmp_path)], ignore=["*.py"])
    assert res.findings == []  # all .py findings ignored
    # without ignore, we find the zero-width char
    res2 = scan([str(tmp_path)])
    assert any("zero_width" in f.categories for f in res2.findings)


def test_color_text_contains_findings():
    res = scan([str(SAMPLE)])
    colored = render_text(res, color=True)
    assert "U+200B" in colored
    plain = render_text(res, color=False)
    assert "\x1b[" not in plain


@pytest.mark.skipif(not LITE.exists(), reason="zerot_lite.py missing")
def test_lite_sarif(tmp_path):
    out = tmp_path / "report.sarif"
    r = subprocess.run(
        [sys.executable, str(LITE), "scan", str(SAMPLE),
         "--format", "sarif", "--md", str(out)],
        capture_output=True, text=True,
    )
    assert r.returncode == 1, r.stderr
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) > 0


@pytest.mark.skipif(not LITE.exists(), reason="zerot_lite.py missing")
def test_lite_skip_strings(tmp_path):
    # fullwidth char inside a string literal is skipped by default
    p = _write(tmp_path, "s = 'fullwidth inside \uff41'\n")
    r = subprocess.run(
        [sys.executable, str(LITE), "scan", str(p), "--format", "json"],
        capture_output=True, text=True,
    )
    payload = json.loads(r.stdout)
    assert not any("fullwidth" in c["categories"] for c in payload["findings"])
    # but --scan-strings re-includes it
    r2 = subprocess.run(
        [sys.executable, str(LITE), "scan", str(p), "--format", "json",
         "--scan-strings"],
        capture_output=True, text=True,
    )
    payload2 = json.loads(r2.stdout)
    assert any("fullwidth" in c["categories"] for c in payload2["findings"])
