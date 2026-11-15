"""Smoke test for the standalone zerot_lite.py (exercised via subprocess)."""

import json
import subprocess
import sys
from pathlib import Path

LITE = str(Path(__file__).resolve().parent.parent / "zerot_lite.py")


def test_lite_finds_zero_width(tmp_path):
    p = tmp_path / "s.py"
    p.write_text("x = 1\u200b\n", encoding="utf-8")
    out = subprocess.run(
        [sys.executable, LITE, "scan", str(p), "--format", "json"],
        capture_output=True, text=True,
    )
    assert out.returncode == 1
    data = json.loads(out.stdout)
    assert any(f["codepoint"] == "U+200B" for f in data["findings"])
