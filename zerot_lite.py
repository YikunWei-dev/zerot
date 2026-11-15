#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zerot lite — single-file, zero-dependency Unicode trick scanner.

Drop this file into any repository and run it with nothing but Python 3.8+:

    python3 zerot_lite.py scan .
    python3 zerot_lite.py scan src/app.py --md report.md

It detects, in source code:
  * zero-width / invisible characters   (U+200B, U+FEFF, VS-1..32, ...)
  * bidirectional overrides / isolates  (Trojan Source: U+202A..U+202E, U+2066..U+2069)
  * unbalanced bidi controls
  * homoglyph / confusable characters   (Cyrillic, Greek, fullwidth, ...)
  * fullwidth / compatibility forms
  * suspicious whitespace               (no-break space, ideographic space, ...)
  * control characters                  (C0/C1)
  * non-characters
  * mixed-script identifiers            (e.g. Cyrillic lookalikes mixed with ASCII)

Output is a Markdown report (default to stdout, or --md FILE).
Exit codes: 0 = clean, 1 = issues found, 2 = usage error.

This file embeds the zerot detection engine so it can run without `pip install`.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
import unicodedata
from datetime import datetime, timezone

# ==========================================================================
# CATALOG  (single source of truth for dangerous code points)
# ==========================================================================
CATEGORIES = {
    "zero_width": ("Zero-width character", "high",
                   "Invisible character that hides or alters code semantics."),
    "bidi": ("Bidirectional override", "critical",
             "Direction control that can reorder how text is displayed "
             "(classic 'Trojan Source' attack)."),
    "bidi_unbalanced": ("Unbalanced bidi control", "critical",
                        "A bidirectional embedding/isolate was opened but never closed."),
    "confusable": ("Homoglyph / confusable", "high",
                   "A character that visually resembles an ASCII letter but is a "
                   "different code point."),
    "fullwidth": ("Fullwidth / compatibility form", "medium",
                  "Fullwidth or compatibility-form character; often a confusable of ASCII."),
    "suspicious_space": ("Suspicious whitespace", "medium",
                         "Looks like a space but is a different whitespace code point."),
    "control": ("Control character", "high",
                "Non-printable control character embedded in source."),
    "noncharacter": ("Unicode noncharacter", "medium",
                     "Permanently reserved non-character code point."),
    "mixed_script": ("Mixed-script token", "high",
                     "Identifier mixing ASCII with a non-ASCII script (e.g. Cyrillic)."),
    "compat_masquerade": ("Compatibility masquerade", "medium",
                          "Character whose compatibility (NFKC) form is a single "
                          "ASCII character; often used to spoof identifiers."),
}
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

ZERO_WIDTH = {
    0x00AD: "SOFT HYPHEN", 0x034F: "COMBINING GRAPHEME JOINER",
    0x061C: "ARABIC LETTER MARK", 0x115F: "HANGUL CHOSEONG FILLER",
    0x1160: "HANGUL JUNGSEONG FILLER", 0x17B4: "KHMER VOWEL INHERENT AQ",
    0x17B5: "KHMER VOWEL INHERENT AA", 0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x200B: "ZERO WIDTH SPACE", 0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER", 0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK", 0x2028: "LINE SEPARATOR",
    0x2029: "PARAGRAPH SEPARATOR", 0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING", 0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE", 0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2060: "WORD JOINER", 0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES", 0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS", 0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE", 0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE", 0x206A: "INHIBIT SYMMETRIC SWAPPING",
    0x206B: "ACTIVATE SYMMETRIC SWAPPING", 0x206C: "INHIBIT ARABIC FORM SHAPING",
    0x206D: "ACTIVATE ARABIC FORM SHAPING", 0x206E: "NATIONAL DIGIT SHAPES",
    0x206F: "NOMINAL DIGIT SHAPES", 0x3164: "HANGUL FILLER",
    0xFE00: "VARIATION SELECTOR-1", 0xFE01: "VARIATION SELECTOR-2",
    0xFE02: "VARIATION SELECTOR-3", 0xFE03: "VARIATION SELECTOR-4",
    0xFE04: "VARIATION SELECTOR-5", 0xFE05: "VARIATION SELECTOR-6",
    0xFE06: "VARIATION SELECTOR-7", 0xFE07: "VARIATION SELECTOR-8",
    0xFE08: "VARIATION SELECTOR-9", 0xFE09: "VARIATION SELECTOR-10",
    0xFE0A: "VARIATION SELECTOR-11", 0xFE0B: "VARIATION SELECTOR-12",
    0xFE0C: "VARIATION SELECTOR-13", 0xFE0D: "VARIATION SELECTOR-14",
    0xFE0E: "VARIATION SELECTOR-15", 0xFE0F: "VARIATION SELECTOR-16",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)", 0xFFA0: "HALFWIDTH HANGUL FILLER",
    0xE0100: "VARIATION SELECTOR-17", 0xE0101: "VARIATION SELECTOR-18",
    0xE0102: "VARIATION SELECTOR-19", 0xE011F: "VARIATION SELECTOR-32",
}
BIDI_OPEN = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING", 0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE", 0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE", 0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
}
BIDI_POP = {0x202C: "POP DIRECTIONAL FORMATTING", 0x2069: "POP DIRECTIONAL ISOLATE"}
BIDI_ALL = set(BIDI_OPEN) | set(BIDI_POP)
_CONTROL_WHITELIST = {0x09, 0x0A, 0x0D}
SUSPICIOUS_SPACE = {
    0x00A0: "NO-BREAK SPACE", 0x1680: "OGHAM SPACE MARK", 0x2000: "EN QUAD",
    0x2001: "EM QUAD", 0x2002: "EN SPACE", 0x2003: "EM SPACE",
    0x2004: "THREE-PER-EM SPACE", 0x2005: "FOUR-PER-EM SPACE",
    0x2006: "SIX-PER-EM SPACE", 0x2007: "FIGURE SPACE", 0x2008: "PUNCTUATION SPACE",
    0x2009: "THIN SPACE", 0x200A: "HAIR SPACE", 0x202F: "NARROW NO-BREAK SPACE",
    0x205F: "MEDIUM MATHEMATICAL SPACE", 0x3000: "IDEOGRAPHIC SPACE",
}
FULLWIDTH_BLOCK = (0xFF00, 0xFFEF)
CONFUSABLES = {
    # Cyrillic lowercase
    0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p", 0x0441: "c", 0x0443: "y",
    0x0445: "x", 0x0451: "e", 0x0456: "i", 0x0457: "i", 0x0455: "s", 0x0458: "j",
    0x0459: "q", 0x045B: "h", 0x045C: "p", 0x045E: "e", 0x0463: "e", 0x0471: "d",
    0x0489: "q", 0x04BB: "h", 0x04C0: "I", 0x04CF: "O",
    # Cyrillic uppercase
    0x0410: "A", 0x0412: "B", 0x0415: "E", 0x041A: "K", 0x041C: "M", 0x041D: "H",
    0x041E: "O", 0x0420: "P", 0x0421: "C", 0x0422: "T", 0x0423: "Y", 0x0425: "X",
    0x0406: "I", 0x0408: "J", 0x0490: "G", 0x04AE: "Y",
    # Greek lowercase
    0x03B1: "a", 0x03B2: "B", 0x03B5: "e", 0x03B7: "n", 0x03B9: "i", 0x03BA: "k",
    0x03BD: "v", 0x03BF: "o", 0x03C1: "p", 0x03C4: "t", 0x03C5: "u", 0x03C7: "x",
    0x03C9: "w", 0x03F2: "c", 0x03D0: "B", 0x03D1: "v", 0x03DD: "G", 0x03F0: "k",
    0x03F1: "p", 0x03F4: "O",
    # Greek uppercase
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0397: "H", 0x0399: "I", 0x039A: "K",
    0x039C: "M", 0x039D: "N", 0x039F: "O", 0x03A1: "P", 0x03A4: "T", 0x03A5: "Y",
    0x03A7: "X", 0x03A9: "W",
    # Misc
    0x212A: "K", 0x212B: "A", 0x00AA: "a", 0x00B5: "u", 0x00BA: "o",
}
for _cp in list(range(0xFF10, 0xFF1A)) + list(range(0xFF21, 0xFF3B)) + \
        list(range(0xFF41, 0xFF5B)):
    if 0xFF10 <= _cp < 0xFF1A:
        CONFUSABLES.setdefault(_cp, chr(_cp - 0xFF10 + ord("0")))
    elif 0xFF21 <= _cp < 0xFF3B:
        CONFUSABLES.setdefault(_cp, chr(_cp - 0xFF21 + ord("A")))
    else:
        CONFUSABLES.setdefault(_cp, chr(_cp - 0xFF41 + ord("a")))


def is_control(cp):
    if 0x00 <= cp <= 0x1F and cp not in _CONTROL_WHITELIST:
        return True
    if cp == 0x7F:
        return True
    if 0x80 <= cp <= 0x9F:
        return True
    return False


def is_noncharacter(cp):
    if 0xFDD0 <= cp <= 0xFDEF:
        return True
    if cp & 0xFFFE in (0xFFFE, 0xFFFF):
        return True
    return False


def is_fullwidth(cp):
    return FULLWIDTH_BLOCK[0] <= cp <= FULLWIDTH_BLOCK[1]


def script_of(cp):
    if 0x0410 <= cp <= 0x04FF or 0x0500 <= cp <= 0x052F or 0x2DE0 <= cp <= 0x2DFF \
            or 0xA640 <= cp <= 0xA69F:
        return "cyrillic"
    if 0x0370 <= cp <= 0x03FF:
        return "greek"
    if is_fullwidth(cp):
        return "fullwidth"
    return "other"


def is_letter(cp):
    try:
        return unicodedata.category(chr(cp))[0] == "L"
    except Exception:
        return False


def is_nfkc_masquerade(cp):
    if cp < 0x80:
        return False
    try:
        nf = unicodedata.normalize("NFKC", chr(cp))
    except Exception:
        return False
    return len(nf) == 1 and nf.isascii() and nf.isalnum()


def classify(cp):
    cats = []
    if cp in ZERO_WIDTH:
        cats.append("bidi" if cp in BIDI_ALL else "zero_width")
    if is_control(cp):
        cats.append("control")
    if is_noncharacter(cp):
        cats.append("noncharacter")
    if cp in SUSPICIOUS_SPACE:
        cats.append("suspicious_space")
    # Only fullwidth *letters/digits* are a real spoofing risk (they look like
    # ASCII). Fullwidth punctuation (，；：（）) is normal in CJK prose and only
    # produces false positives, so it is no longer flagged.
    if is_fullwidth(cp) and (0xFF10 <= cp <= 0xFF19
                             or 0xFF21 <= cp <= 0xFF3A
                             or 0xFF41 <= cp <= 0xFF5A):
        cats.append("fullwidth")
    if cp in CONFUSABLES:
        cats.append("confusable")
    if "confusable" not in cats and "fullwidth" not in cats and is_nfkc_masquerade(cp):
        cats.append("compat_masquerade")
    return cats

# ==========================================================================
# ENGINE
# ==========================================================================
DEFAULT_MAX_SIZE = 5 * 1024 * 1024
DEFAULT_EXCLUDE = [
    ".git", ".hg", ".svn", "node_modules", "__pycache__", "venv", ".venv",
    "*.pyc", "*.egg-info", "build", "dist",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico",
    "*.pdf", "*.zip", "*.tar", "*.gz", "*.woff", "*.woff2",
    "*.ttf", "*.eot", "*.mp3", "*.mp4", "*.mov", "*.bin",
    "*.exe", "*.dll", "*.so", "*.dylib", "*.o", "*.a",
]


class Finding:
    __slots__ = ("path", "line", "col", "char", "cp", "categories",
                 "looks_like", "context")

    def __init__(self, path, line, col, char, cp, categories, looks_like="",
                 context=""):
        self.path = path
        self.line = line
        self.col = col
        self.char = char
        self.cp = cp
        self.categories = categories
        self.looks_like = looks_like
        self.context = context


class ScanResult:
    def __init__(self):
        self.targets = []
        self.files_scanned = 0
        self.files_skipped = []
        self.findings = []

    def counts_by_category(self):
        out = {}
        for f in self.findings:
            for c in f.categories:
                out[c] = out.get(c, 0) + 1
        return out

    def max_severity(self):
        worst = "low"
        for f in self.findings:
            for c in f.categories:
                sev = CATEGORIES.get(c, ("", "low", ""))[1]
                if SEVERITY_ORDER[sev] > SEVERITY_ORDER[worst]:
                    worst = sev
        return worst


def _is_binary(data):
    if b"\x00" in data:
        return True
    sample = data[:8192]
    if not sample:
        return False
    bad = sum(1 for b in sample if b < 0x09 or (0x0E <= b <= 0x1F) or b == 0x7F)
    return bad / len(sample) > 0.30


def _match_any(name, patterns):
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def _iter_files(targets, recursive, exclude, include, max_size):
    out = []
    for target in targets:
        if os.path.isdir(target):
            if recursive:
                for root, dirs, files in os.walk(target):
                    dirs[:] = [d for d in dirs if not _match_any(d, exclude)]
                    for fn in files:
                        if _match_any(fn, exclude):
                            continue
                        if include and not _match_any(fn, include):
                            continue
                        full = os.path.join(root, fn)
                        try:
                            if os.path.getsize(full) > max_size:
                                continue
                        except OSError:
                            continue
                        out.append(full)
            else:
                for fn in sorted(os.listdir(target)):
                    full = os.path.join(target, fn)
                    if not os.path.isfile(full):
                        continue
                    if _match_any(fn, exclude):
                        continue
                    if include and not _match_any(fn, include):
                        continue
                    try:
                        if os.path.getsize(full) > max_size:
                            continue
                    except OSError:
                        continue
                    out.append(full)
        elif os.path.isfile(target):
            out.append(target)
    return out


def _tokenize(line):
    i = 0
    n = len(line)
    while i < n:
        if (line[i].isascii() and (line[i].isalnum() or line[i] == "_")) or \
                is_letter(ord(line[i])):
            j = i
            while j < n and (is_letter(ord(line[j])) or line[j].isdigit()
                             or line[j] == "_"):
                j += 1
            yield (i, j)
            i = j
        else:
            i += 1


def _check_mixed_script(line, path, lineno, existing):
    """Flag mixed-script tokens, merging into any existing finding at the
    same position so a confusable char is not reported twice."""
    for (start, end) in _tokenize(line):
        token = line[start:end]
        has_ascii_letter = any(c.isascii() and c.isalpha() for c in token)
        scripts = {script_of(ord(c)) for c in token if is_letter(ord(c))}
        nonascii = scripts - {"other"}
        if has_ascii_letter and nonascii:
            for k, c in enumerate(token):
                if not c.isascii() and is_letter(ord(c)):
                    col = start + k + 1
                    merged = False
                    for f in existing:
                        if f.line == lineno and f.col == col:
                            if "mixed_script" not in f.categories:
                                f.categories.append("mixed_script")
                            merged = True
                            break
                    if not merged:
                        existing.append(Finding(
                            path, lineno, col, c, ord(c),
                            ["mixed_script"], context=line))
                    break
    return None


_C_LIKE = {
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".cs", ".java",
    ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".swift", ".m", ".mm",
    ".kt", ".kts", ".scala", ".php", ".dart",
}
_HASH_LIKE = {
    ".py", ".pyw", ".rb", ".sh", ".bash", ".zsh", ".yml", ".yaml",
    ".toml", ".cfg", ".ini", ".r", ".pl", ".pm",
}


def _code_mode_for(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in _C_LIKE:
        return "c"
    if ext in _HASH_LIKE:
        return "hash"
    return None


def mask_non_code(text, mode, in_block=False):
    """Replace comment and string-literal spans with spaces.

    Comments and string content (e.g. C ``printf(...)``) are data, not code,
    so dangerous Unicode there rarely affects execution and is usually
    intentional. Masking keeps line/column numbers valid.

    ``in_block`` carries ``/* ... */`` block-comment state across calls so a
    comment that spans several lines is masked correctly. Returns
    ``(masked_text, still_in_block)``.
    """
    if not mode:
        return text, False
    use_hash = (mode == "hash")
    use_c = (mode in ("c", "hash"))
    use_backtick = (mode == "c")
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_block:
            # We are already inside a /* ... */ comment: mask until we find the
            # closing delimiter.
            j = text.find("*/", i)
            if j == -1:
                out.append(" " * (n - i))
                i = n
                break
            out.append(" " * (j + 2 - i))
            i = j + 2
            in_block = False
            continue
        if text[i:i + 2] == "//":
            j = text.find("\n", i)
            end = n if j == -1 else j
            out.append(" " * (end - i))
            i = end
            continue
        if use_hash and c == "#":
            j = text.find("\n", i)
            end = n if j == -1 else j
            out.append(" " * (end - i))
            i = end
            continue
        if use_c and text[i:i + 2] == "/*":
            j = text.find("*/", i + 2)
            end = n if j == -1 else j + 2
            out.append(" " * (end - i))
            i = end
            if j == -1:
                in_block = True
            continue
        if c == '"' or c == "'" or (use_backtick and c == "`"):
            quote = c
            is_triple = (quote in ('"', "'") and use_hash
                         and text[i:i + 3] == quote * 3)
            if is_triple:
                j = text.find(quote * 3, i + 3)
                end = n if j == -1 else j + 3
            else:
                j = i + 1
                while j < n:
                    d = text[j]
                    if d == "\\":
                        j += 2
                        continue
                    if d == quote:
                        j += 1
                        break
                    if d == "\n":
                        break
                    j += 1
                end = j
            out.append(" " * (end - i))
            i = end
            continue
        out.append(c)
        i += 1
    return "".join(out), in_block


def scan_file(path, skip_strings=True):
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        return [], "unreadable: %s" % exc
    if _is_binary(raw):
        return [], "binary file"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")

    mask_mode = _code_mode_for(path) if skip_strings else None
    in_block = False

    findings = []
    bidi_stack = []
    lines = text.split("\n")
    for lineno, line in enumerate(lines, start=1):
        scan_line = line
        if mask_mode:
            scan_line, in_block = mask_non_code(line, mask_mode, in_block)
        line_findings = []
        for col, ch in enumerate(scan_line, start=1):
            cp = ord(ch)
            cats = classify(cp)
            if not cats:
                continue
            fnd = Finding(
                path, lineno, col, ch, cp, cats,
                looks_like=CONFUSABLES.get(cp, ""), context=line)
            line_findings.append(fnd)
            if cp in BIDI_OPEN:
                bidi_stack.append(fnd)
            elif cp in BIDI_POP:
                if bidi_stack:
                    bidi_stack.pop()
                else:
                    line_findings.append(Finding(
                        path, lineno, col, ch, cp, ["bidi_unbalanced"],
                        context=line))
        _check_mixed_script(scan_line, path, lineno, line_findings)
        findings.extend(line_findings)
    # unclosed bidi at EOF: fold the imbalance into the opening's own finding
    # instead of emitting a second finding at the same position.
    for fnd in bidi_stack:
        if "bidi_unbalanced" not in fnd.categories:
            fnd.categories.append("bidi_unbalanced")
    return findings, None


def scan(targets, recursive=True, exclude=None, include=None,
         max_size=DEFAULT_MAX_SIZE, skip_binary=True, ignore=None,
         skip_strings=True):
    result = ScanResult()
    result.targets = list(targets)
    exc = list(DEFAULT_EXCLUDE)
    if exclude:
        exc = exc + list(exclude)
    files = _iter_files(targets, recursive, exc, include, max_size)
    ignore = list(ignore or [])
    for f in files:
        result.files_scanned += 1
        findings, skip = scan_file(f, skip_strings=skip_strings)
        if skip and skip_binary:
            result.files_skipped.append({"path": f, "reason": skip})
            continue
        if ignore:
            findings = [fd for fd in findings if not _match_any(fd.path, ignore)]
        result.findings.extend(findings)
    return result

# ==========================================================================
# REPORT (Markdown)
# ==========================================================================
def _escape(s):
    return s.replace("\\", "\\\\").replace("`", "\\`")


def render_markdown(result):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    L = []
    L.append("# Zerot Scan Report")
    L.append("")
    L.append("- **Generated:** %s" % now)
    L.append("- **Targets:** %s" % ", ".join(result.targets))
    L.append("- **Files scanned:** %d  **Skipped:** %d  **Findings:** %d" % (
        result.files_scanned, len(result.files_skipped), len(result.findings)))
    L.append("- **Highest severity:** `%s`" % result.max_severity().upper())
    L.append("")
    if result.counts_by_category().get("bidi") or \
            result.counts_by_category().get("bidi_unbalanced"):
        L.append("> :warning: **Trojan Source risk detected** — bidirectional "
                 "controls can make code display differently from how it executes.")
        L.append("")
    L.append("## Summary")
    L.append("")
    L.append("| Category | Severity | Count |")
    L.append("| --- | --- | ---: |")
    counts = result.counts_by_category()
    for cat_id, (label, sev, _desc) in CATEGORIES.items():
        n = counts.get(cat_id, 0)
        if n:
            L.append("| %s | %s | %d |" % (label, sev, n))
    if not counts:
        L.append("| _none_ | - | 0 |")
    L.append("")
    if result.files_skipped:
        L.append("## Skipped files")
        L.append("")
        L.append("| Path | Reason |")
        L.append("| --- | --- |")
        for s in result.files_skipped:
            L.append("| `%s` | %s |" % (s["path"], _escape(s["reason"])))
        L.append("")
    L.append("## Findings")
    L.append("")
    if not result.findings:
        L.append("_No dangerous characters were detected. :tada_")
        L.append("")
        return "\n".join(L)
    by_file = {}
    for f in result.findings:
        by_file.setdefault(f.path, []).append(f)
    for path, flist in by_file.items():
        L.append("### `%s`" % path)
        L.append("")
        L.append("| Line:Col | Code point | Category | Looks like |")
        L.append("| --- | --- | --- | --- |")
        for f in sorted(flist, key=lambda x: (x.line, x.col)):
            cats = ", ".join(CATEGORIES.get(c, (c, "", ""))[0] for c in f.categories)
            looks = "`%s`" % f.looks_like if f.looks_like else "—"
            L.append("| %d:%d | `U+%04X` | %s | %s |" % (
                f.line, f.col, f.cp, cats, looks))
        L.append("")
        L.append("<details><summary>Context</summary>")
        L.append("")
        seen = set()
        for f in sorted(flist, key=lambda x: (x.line, x.col)):
            key = (f.line, f.context)
            if key in seen:
                continue
            seen.add(key)
            L.append("L%d: `%s`" % (f.line, _escape(f.context)))
            L.append("      %s" % (" " * (f.col - 1) + "^"))
            L.append("")
        L.append("</details>")
        L.append("")
    L.append("## Category legend")
    L.append("")
    for cat_id, (label, sev, desc) in CATEGORIES.items():
        L.append("- **%s** (`%s`): %s" % (label, sev, desc))
    L.append("")
    L.append("---")
    L.append("")
    L.append("_zerot is **read-only**: it only reports findings and never "
             "modifies your files. By default, comments and string literals "
             "are not scanned, since text there (e.g. `printf(\"...\")`) does "
             "not affect how code executes — use `--scan-strings` to include them._")
    L.append("")
    L.append("_Generated by zerot lite._")
    L.append("")
    return "\n".join(L)


_ANSI = {"reset": "\x1b[0m", "bold": "\x1b[1m", "red": "\x1b[31m",
         "yellow": "\x1b[33m", "cyan": "\x1b[36m", "green": "\x1b[32m"}


def _sev_color(sev):
    return {"critical": "red", "high": "red",
            "medium": "yellow", "low": "cyan"}.get(sev, "reset")


def render_text(result, color=False):
    def c(code, s):
        return ("%s%s%s" % (_ANSI.get(code, ""), s, _ANSI["reset"])) if color else s

    out = []
    n = len(result.findings)
    head = "zerot: %d finding(s) across %d file(s)" % (
        n, result.files_scanned)
    out.append(c("bold", head) if n else c("green", head))
    for f in sorted(result.findings, key=lambda x: (x.path, x.line, x.col)):
        cats = ",".join(f.categories)
        looks = " looks_like=%r" % f.looks_like if f.looks_like else ""
        sev = "low"
        for cat in f.categories:
            s = CATEGORIES.get(cat, ("", "low", ""))[1]
            if SEVERITY_ORDER[s] > SEVERITY_ORDER[sev]:
                sev = s
        line = ("  %s:%d:%d %s [%s]%s" % (
            f.path, f.line, f.col,
            c(_sev_color(sev), "U+%04X" % f.cp),
            c(_sev_color(sev), cats), looks))
        out.append(line)
    return "\n".join(out)


VERSION = "1.0.0"


def _sarif_level(severity):
    if severity in ("critical", "high"):
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def render_sarif(result):
    """Render results in SARIF 2.1.0 for GitHub code scanning / Security tab."""
    used_rules = {}
    results = []
    for f in sorted(result.findings, key=lambda x: (x.path, x.line, x.col)):
        for cat in f.categories:
            label, sev, desc = CATEGORIES.get(cat, (cat, "low", ""))
            rid = "zerot." + cat
            if rid not in used_rules:
                used_rules[rid] = {
                    "id": rid,
                    "name": cat,
                    "shortDescription": {"text": label},
                    "fullDescription": {"text": desc},
                    "defaultConfiguration": {"level": _sarif_level(sev)},
                    "helpUri": "https://github.com/YikunWei-dev/zerot#readme",
                }
            msg = "Unicode %s (%s)" % (label, "U+%04X" % f.cp)
            if f.looks_like:
                msg += " looks like '%s'" % f.looks_like
            results.append({
                "ruleId": rid,
                "level": _sarif_level(sev),
                "message": {"text": msg},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.path},
                        "region": {
                            "startLine": f.line,
                            "startColumn": f.col,
                            "snippet": {"text": f.context},
                        },
                    }
                }],
            })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "zerot",
                    "version": VERSION,
                    "informationUri": "https://github.com/YikunWei-dev/zerot",
                    "rules": list(used_rules.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)

# ==========================================================================
# CLI
# ==========================================================================
def _sev_rank(s):
    return SEVERITY_ORDER.get(s, 0)


def _should_fail(result, fail_severity):
    """Fail if any finding has severity >= the given threshold."""
    thr = _sev_rank(fail_severity)
    for f in result.findings:
        for c in f.categories:
            if _sev_rank(CATEGORIES.get(c, ("", "low", ""))[1]) >= thr:
                return True
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="zerot_lite.py",
        description="Detect dangerous Unicode characters in source code.")
    sub = parser.add_subparsers(dest="command")
    sp = sub.add_parser("scan", help="scan targets and print a Markdown report")
    sp.add_argument("targets", nargs="+", help="files or directories")
    sp.add_argument("-r", "--recursive", dest="recursive", action="store_true",
                    default=True, help="recurse into directories (default)")
    sp.add_argument("--no-recursive", dest="recursive", action="store_false",
                    help="do not recurse into directories")
    sp.add_argument("-e", "--exclude", action="append", default=None,
                    help="fnmatch pattern to skip (repeatable)")
    sp.add_argument("-i", "--include", action="append", default=None,
                    help="only scan files matching fnmatch pattern")
    sp.add_argument("--ignore", action="append", default=None,
                    help="ignore findings whose file path matches this fnmatch "
                         "pattern (repeatable)")
    sp.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE,
                    help="skip files larger than N bytes")
    sp.add_argument("--no-binary", dest="skip_binary", action="store_false",
                    help="do not skip binary files")
    sp.add_argument("--md", default=None, help="write Markdown report to FILE")
    sp.add_argument("--format", choices=["md", "json", "text", "sarif"], default="md",
                    help="output format")
    sp.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                    default="high", help="fail if any finding's severity is at "
                    "least this (default: high)")
    sp.add_argument("--no-color", action="store_true",
                    help="disable colored text output")
    sp.add_argument("--scan-strings", action="store_true",
                    help="also scan text inside comments and string literals "
                         "(default: skip them, since they do not affect execution)")
    sp.add_argument("-q", "--quiet", action="store_true",
                    help="suppress report, only set exit code")
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2

    result = scan(
        targets=args.targets,
        recursive=args.recursive,
        exclude=args.exclude,
        include=args.include,
        max_size=args.max_size,
        skip_binary=args.skip_binary,
        ignore=args.ignore,
        skip_strings=not args.scan_strings,
    )

    if not args.quiet:
        if args.format == "json":
            payload = {
                "targets": result.targets,
                "files_scanned": result.files_scanned,
                "files_skipped": result.files_skipped,
                "highest_severity": result.max_severity(),
                "counts_by_category": result.counts_by_category(),
                "findings": [
                    {"path": f.path, "line": f.line, "col": f.col,
                     "char": f.char, "codepoint": "U+%04X" % f.cp,
                     "categories": f.categories, "looks_like": f.looks_like,
                     "context": f.context} for f in result.findings],
            }
            text = json.dumps(payload, indent=2, ensure_ascii=False)
        elif args.format == "text":
            use_color = (not args.no_color) and sys.stdout.isatty()
            text = render_text(result, color=use_color)
        elif args.format == "sarif":
            text = render_sarif(result)
        else:
            text = render_markdown(result)

        if args.md:
            with open(args.md, "w", encoding="utf-8") as fh:
                fh.write(text)
            print("zerot: wrote report to %s" % args.md, file=sys.stderr)
        else:
            print(text)

    return 1 if _should_fail(result, args.fail_on) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
