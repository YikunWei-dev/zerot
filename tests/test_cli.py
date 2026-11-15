"""Tests for the CLI option merging, fail thresholds and end-to-end run."""

import argparse

from zerot import cli
from zerot.engine import DEFAULT_MAX_SIZE, Finding, ScanResult


def _args(**kw):
    a = argparse.Namespace(
        recursive=None, exclude=None, include=None, max_size=None,
        skip_binary=None, ignore=None, format=None, fail_on=None,
        scan_strings=False, config=None,
    )
    for k, v in kw.items():
        setattr(a, k, v)
    return a


def test_merge_defaults():
    opts = cli._merge(_args(), {})
    assert opts["skip_strings"] is True
    assert opts["fail_severity"] == "high"
    assert opts["format"] == "md"
    assert opts["recursive"] is True
    assert opts["max_size"] == DEFAULT_MAX_SIZE


def test_merge_config_overrides():
    cfg = {"skip_strings": False, "fail_on": "critical", "format": "json"}
    opts = cli._merge(_args(), cfg)
    assert opts["skip_strings"] is False
    assert opts["fail_severity"] == "critical"
    assert opts["format"] == "json"


def test_merge_scan_strings_flag_wins():
    opts = cli._merge(_args(scan_strings=True), {"skip_strings": True})
    assert opts["skip_strings"] is False


def test_should_fail_thresholds():
    f = Finding(path="x", line=1, col=1, char="a", cp=0x43E,
                categories=["confusable"])  # high
    res = ScanResult(findings=[f])
    assert cli._should_fail(res, "high") is True
    assert cli._should_fail(res, "critical") is False
    assert cli._should_fail(ScanResult(findings=[]), "low") is False


def test_run_scan_json_emits_finding(tmp_path, capsys):
    p = tmp_path / "a.py"
    p.write_text("x = 1\u200b\n", encoding="utf-8")
    rc = cli.run(["scan", str(p), "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 1
    data = __import__("json").loads(out)
    assert any(f["codepoint"] == "U+200B" for f in data["findings"])
