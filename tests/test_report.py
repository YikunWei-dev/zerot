"""Tests for the report renderers (markdown / json / text / sarif)."""

import json

from zerot import report
from zerot.engine import Finding, ScanResult


def _result():
    f1 = Finding(path="a.py", line=1, col=2, char="\u200b", cp=0x200B,
                 categories=["zero_width"])
    f2 = Finding(path="a.py", line=3, col=1, char="\u202e", cp=0x202E,
                 categories=["bidi"])
    return ScanResult(targets=["a.py"], files_scanned=1, findings=[f1, f2])


def test_render_json_keys():
    data = json.loads(report.render_json(_result()))
    assert data["files_scanned"] == 1
    assert len(data["findings"]) == 2
    cps = {f["codepoint"] for f in data["findings"]}
    assert cps == {"U+200B", "U+202E"}


def test_render_markdown_contains_report_and_codepoints():
    md = report.render_markdown(_result())
    assert "Zerot Scan Report" in md
    assert "U+200B" in md
    assert "U+202E" in md


def test_render_sarif_structure():
    data = json.loads(report.render_sarif(_result()))
    assert data["version"] == "2.1.0"
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "zerot"
    rule_ids = {r["ruleId"] for r in data["runs"][0]["results"]}
    assert rule_ids == {"zerot.zero_width", "zerot.bidi"}


def test_sarif_level_mapping():
    assert report._sarif_level("critical") == "error"
    assert report._sarif_level("high") == "error"
    assert report._sarif_level("medium") == "warning"
    assert report._sarif_level("low") == "note"
