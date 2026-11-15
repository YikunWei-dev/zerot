"""Tests for configuration loading."""

import json

from zerot.config import load_config


def test_load_config_reads_file(tmp_path):
    cfg = {"exclude": ["vendor"], "skip_strings": False, "fail_on": "critical"}
    f = tmp_path / ".zerot.json"
    f.write_text(json.dumps(cfg), encoding="utf-8")
    assert load_config(str(f)) == cfg


def test_load_config_missing_returns_empty():
    assert load_config("/nonexistent/path/.zerot.json") == {}


def test_load_config_invalid_json_returns_empty(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{not valid json", encoding="utf-8")
    assert load_config(str(f)) == {}
