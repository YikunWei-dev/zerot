"""zerot — catalog of dangerous Unicode code points for source code.

This module is the single source of truth for *which* characters are
considered dangerous in source code and *why*.  It is intentionally
dependency-free (standard library only) so the very same logic can be
inlined into the single-file ``zerot_lite.py`` build.

Categories
----------
zero_width        Invisible characters that hide or alter code semantics.
bidi              Bidirectional overrides / isolates (Trojan Source attack).
bidi_unbalanced  A bidi embedding/isolate that was never closed.
confusable       Homoglyphs that visually mimic an ASCII letter.
fullwidth        Fullwidth / compatibility-form characters.
suspicious_space Whitespace that *looks* like a normal space but is not.
control          Non-printable C0/C1 control characters.
noncharacter     Permanently reserved Unicode non-characters.
mixed_script     An identifier mixing ASCII with a non-ASCII script.
"""

from __future__ import annotations

import unicodedata
from typing import Dict, Tuple

# --------------------------------------------------------------------------
# Category metadata: id -> (label, severity, description)
# severity is one of: critical > high > medium > low
# --------------------------------------------------------------------------
CATEGORIES: Dict[str, Tuple[str, str, str]] = {
    "zero_width": (
        "Zero-width character",
        "high",
        "Invisible character that hides or alters code semantics.",
    ),
    "bidi": (
        "Bidirectional override",
        "critical",
        "Direction control that can reorder how text is displayed "
        "(classic 'Trojan Source' attack).",
    ),
    "bidi_unbalanced": (
        "Unbalanced bidi control",
        "critical",
        "A bidirectional embedding/isolate was opened but never closed.",
    ),
    "confusable": (
        "Homoglyph / confusable",
        "high",
        "A character that visually resembles an ASCII letter but is a "
        "different code point.",
    ),
    "fullwidth": (
        "Fullwidth / compatibility form",
        "medium",
        "Fullwidth or compatibility-form character; often a confusable of ASCII.",
    ),
    "suspicious_space": (
        "Suspicious whitespace",
        "medium",
        "Whitespace that looks like a normal space but is a different code point.",
    ),
    "control": (
        "Control character",
        "high",
        "Non-printable control character embedded in source.",
    ),
    "noncharacter": (
        "Unicode noncharacter",
        "medium",
        "Permanently reserved non-character code point.",
    ),
    "mixed_script": (
        "Mixed-script token",
        "high",
        "Identifier mixing ASCII with a non-ASCII script (e.g. Cyrillic).",
    ),
    "compat_masquerade": (
        "Compatibility masquerade",
        "medium",
        "Character whose compatibility (NFKC) form is a single ASCII character; "
        "often used to spoof identifiers.",
    ),
}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# --------------------------------------------------------------------------
# Zero-width / invisible
# --------------------------------------------------------------------------
ZERO_WIDTH = {
    0x00AD: "SOFT HYPHEN",
    0x034F: "COMBINING GRAPHEME JOINER",
    0x061C: "ARABIC LETTER MARK",
    0x115F: "HANGUL CHOSEONG FILLER",
    0x1160: "HANGUL JUNGSEONG FILLER",
    0x17B4: "KHMER VOWEL INHERENT AQ",
    0x17B5: "KHMER VOWEL INHERENT AA",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x2028: "LINE SEPARATOR",
    0x2029: "PARAGRAPH SEPARATOR",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
    0x206A: "INHIBIT SYMMETRIC SWAPPING",
    0x206B: "ACTIVATE SYMMETRIC SWAPPING",
    0x206C: "INHIBIT ARABIC FORM SHAPING",
    0x206D: "ACTIVATE ARABIC FORM SHAPING",
    0x206E: "NATIONAL DIGIT SHAPES",
    0x206F: "NOMINAL DIGIT SHAPES",
    0x3164: "HANGUL FILLER",
    0xFE00: "VARIATION SELECTOR-1",
    0xFE01: "VARIATION SELECTOR-2",
    0xFE02: "VARIATION SELECTOR-3",
    0xFE03: "VARIATION SELECTOR-4",
    0xFE04: "VARIATION SELECTOR-5",
    0xFE05: "VARIATION SELECTOR-6",
    0xFE06: "VARIATION SELECTOR-7",
    0xFE07: "VARIATION SELECTOR-8",
    0xFE08: "VARIATION SELECTOR-9",
    0xFE09: "VARIATION SELECTOR-10",
    0xFE0A: "VARIATION SELECTOR-11",
    0xFE0B: "VARIATION SELECTOR-12",
    0xFE0C: "VARIATION SELECTOR-13",
    0xFE0D: "VARIATION SELECTOR-14",
    0xFE0E: "VARIATION SELECTOR-15",
    0xFE0F: "VARIATION SELECTOR-16",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
    0xFFA0: "HALFWIDTH HANGUL FILLER",
    # variation selectors beyond 16 (still invisible modifiers)
    0xE0100: "VARIATION SELECTOR-17",
    0xE0101: "VARIATION SELECTOR-18",
    0xE0102: "VARIATION SELECTOR-19",
    0xE011F: "VARIATION SELECTOR-32",
}

# --------------------------------------------------------------------------
# Bidirectional formatting controls (Trojan Source)
# --------------------------------------------------------------------------
BIDI_OPEN = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
}
BIDI_POP = {
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x2069: "POP DIRECTIONAL ISOLATE",
}
BIDI_ALL = set(BIDI_OPEN) | set(BIDI_POP)

# --------------------------------------------------------------------------
# Control characters (C0 + C1 + DEL). Whitespace-y ones are excluded because
# they are legitimate/expected in source files.
# --------------------------------------------------------------------------
_CONTROL_WHITELIST = {0x09, 0x0A, 0x0D}  # TAB, LF, CR


def is_control(cp: int) -> bool:
    if 0x00 <= cp <= 0x1F and cp not in _CONTROL_WHITELIST:
        return True
    if cp == 0x7F:  # DEL
        return True
    if 0x80 <= cp <= 0x9F:  # C1
        return True
    return False


# --------------------------------------------------------------------------
# Non-characters (permanently reserved)
# --------------------------------------------------------------------------
def is_noncharacter(cp: int) -> bool:
    if 0xFDD0 <= cp <= 0xFDEF:
        return True
    # code points ending in FDDD / FFFF in each plane
    if cp & 0xFFFE in (0xFFFE, 0xFFFF):
        return True
    return False


# --------------------------------------------------------------------------
# Suspicious whitespace (looks like a normal space)
# --------------------------------------------------------------------------
SUSPICIOUS_SPACE = {
    0x00A0: "NO-BREAK SPACE",
    0x1680: "OGHAM SPACE MARK",
    0x2000: "EN QUAD",
    0x2001: "EM QUAD",
    0x2002: "EN SPACE",
    0x2003: "EM SPACE",
    0x2004: "THREE-PER-EM SPACE",
    0x2005: "FOUR-PER-EM SPACE",
    0x2006: "SIX-PER-EM SPACE",
    0x2007: "FIGURE SPACE",
    0x2008: "PUNCTUATION SPACE",
    0x2009: "THIN SPACE",
    0x200A: "HAIR SPACE",
    0x202F: "NARROW NO-BREAK SPACE",
    0x205F: "MEDIUM MATHEMATICAL SPACE",
    0x3000: "IDEOGRAPHIC SPACE",
}

# --------------------------------------------------------------------------
# Fullwidth / Halfwidth and Fullwidth Forms block (U+FF00–U+FFEF)
# --------------------------------------------------------------------------
FULLWIDTH_BLOCK = (0xFF00, 0xFFEF)


def is_fullwidth(cp: int) -> bool:
    return FULLWIDTH_BLOCK[0] <= cp <= FULLWIDTH_BLOCK[1]


# --------------------------------------------------------------------------
# Confusables: code point -> ASCII look-alike.
# Curated to the characters that most plausibly spoof ASCII identifiers.
# --------------------------------------------------------------------------
CONFUSABLES: Dict[int, str] = {
    # ---- Cyrillic (lowercase) ----
    0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p",
    0x0441: "c", 0x0443: "y", 0x0445: "x", 0x0451: "e",
    0x0456: "i", 0x0457: "i", 0x0455: "s", 0x0458: "j",
    0x0459: "q", 0x045B: "h", 0x045C: "p", 0x045E: "e",
    0x0463: "e", 0x0471: "d", 0x0489: "q", 0x04BB: "h",
    0x04C0: "I", 0x04CF: "O",
    # ---- Cyrillic (uppercase) ----
    0x0410: "A", 0x0412: "B", 0x0415: "E", 0x041A: "K",
    0x041C: "M", 0x041D: "H", 0x041E: "O", 0x0420: "P",
    0x0421: "C", 0x0422: "T", 0x0423: "Y", 0x0425: "X",
    0x0406: "I", 0x0408: "J", 0x0490: "G", 0x04AE: "Y",
    # ---- Greek (lowercase) ----
    0x03B1: "a", 0x03B2: "B", 0x03B5: "e", 0x03B7: "n",
    0x03B9: "i", 0x03BA: "k", 0x03BD: "v", 0x03BF: "o",
    0x03C1: "p", 0x03C4: "t", 0x03C5: "u", 0x03C7: "x",
    0x03C9: "w", 0x03F2: "c", 0x03D0: "B", 0x03D1: "v",
    0x03DD: "G", 0x03F0: "k", 0x03F1: "p", 0x03F4: "O",
    # ---- Greek (uppercase) ----
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0397: "H",
    0x0399: "I", 0x039A: "K", 0x039C: "M", 0x039D: "N",
    0x039F: "O", 0x03A1: "P", 0x03A4: "T", 0x03A5: "Y",
    0x03A7: "X", 0x03A9: "W",
    # ---- Misc ----
    0x212A: "K",  # KELVIN SIGN
    0x212B: "A",  # ANGSTROM SIGN (NFKC -> Å; keep as confusable)
    0x00AA: "a",  # FEMININE ORDINAL
    0x00B5: "u",  # MICRO SIGN
    0x00BA: "o",  # MASCULINE ORDINAL
}

# Fullwidth letters/digits are confusables of ASCII as well.
for _cp in range(0xFF10, 0xFF1A):  # 0-9
    CONFUSABLES.setdefault(_cp, chr(_cp - 0xFF10 + ord("0")))
for _cp in range(0xFF21, 0xFF3B):  # A-Z
    CONFUSABLES.setdefault(_cp, chr(_cp - 0xFF21 + ord("A")))
for _cp in range(0xFF41, 0xFF5B):  # a-z
    CONFUSABLES.setdefault(_cp, chr(_cp - 0xFF41 + ord("a")))


# --------------------------------------------------------------------------
# Script helpers (used for mixed-script detection)
# --------------------------------------------------------------------------
def script_of(cp: int) -> str:
    """Return a coarse script label for a code point."""
    if 0x0410 <= cp <= 0x04FF or 0x0500 <= cp <= 0x052F or 0x2DE0 <= cp <= 0x2DFF \
            or 0xA640 <= cp <= 0xA69F:
        return "cyrillic"
    if 0x0370 <= cp <= 0x03FF:
        return "greek"
    if is_fullwidth(cp):
        return "fullwidth"
    if 0x0400 <= cp <= 0x052F:
        return "cyrillic"
    return "other"


def is_letter(cp: int) -> bool:
    try:
        return unicodedata.category(chr(cp))[0] == "L"
    except Exception:
        return False


def is_nfkc_masquerade(cp: int) -> bool:
    """True if the character's compatibility (NFKC) form collapses to a single
    ASCII alphanumeric — a common spoofing vector (e.g. mathematical bold
    letters, circled letters, roman numerals)."""
    if cp < 0x80:
        return False
    try:
        nf = unicodedata.normalize("NFKC", chr(cp))
    except Exception:
        return False
    return len(nf) == 1 and nf.isascii() and (nf.isalnum())


def classify(cp: int) -> list:
    """Return a list of category ids this code point matches."""
    cats: list = []
    if cp in ZERO_WIDTH:
        # bidi opcodes are tracked separately for balance
        if cp in BIDI_ALL:
            cats.append("bidi")
        else:
            cats.append("zero_width")
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
