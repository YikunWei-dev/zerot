"""zerot — detection engine.

Scans source files for dangerous Unicode code points and produces
:class:`Finding` objects that the reporting layer can render.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from . import catalog

DEFAULT_MAX_SIZE = 5 * 1024 * 1024  # 5 MiB
DEFAULT_EXCLUDE = [
    ".git", ".hg", ".svn", "node_modules", "__pycache__", "venv", ".venv",
    "*.pyc", "*.egg-info", "build", "dist",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico",
    "*.pdf", "*.zip", "*.tar", "*.gz", "*.woff", "*.woff2",
    "*.ttf", "*.eot", "*.mp3", "*.mp4", "*.mov", "*.bin",
    "*.exe", "*.dll", "*.so", "*.dylib", "*.o", "*.a",
]


@dataclass
class Finding:
    path: str
    line: int          # 1-based
    col: int           # 1-based, within the line
    char: str
    cp: int
    categories: List[str]
    looks_like: str = ""
    context: str = ""  # the full source line

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "line": self.line,
            "col": self.col,
            "char": self.char,
            "codepoint": f"U+{self.cp:04X}",
            "categories": self.categories,
            "looks_like": self.looks_like,
            "context": self.context,
        }


@dataclass
class ScanResult:
    targets: List[str] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: List[Dict[str, str]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    @property
    def counts_by_category(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            for c in f.categories:
                out[c] = out.get(c, 0) + 1
        return out

    def max_severity(self) -> str:
        worst = "low"
        for f in self.findings:
            for c in f.categories:
                sev = catalog.CATEGORIES.get(c, ("", "low", ""))[1]
                if catalog.SEVERITY_ORDER[sev] > catalog.SEVERITY_ORDER[worst]:
                    worst = sev
        return worst


# --------------------------------------------------------------------------
# Path handling
# --------------------------------------------------------------------------
def _is_binary(data: bytes) -> bool:
    # Heuristic: NUL byte anywhere in the first chunk => binary.
    if b"\x00" in data:
        return True
    # Overwhelmingly non-text (e.g. > 30% control bytes excluding TAB/LF/CR).
    sample = data[:8192]
    if not sample:
        return False
    bad = sum(
        1 for b in sample
        if b < 0x09 or (0x0E <= b <= 0x1F) or b == 0x7F
    )
    return bad / len(sample) > 0.30


def _match_any(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


# --------------------------------------------------------------------------
# Code-aware masking: drop comments and string literals (which never affect
# program behaviour) so we only scan actual code. Line/column positions are
# preserved by replacing masked spans with spaces of equal length.
# --------------------------------------------------------------------------
_C_LIKE = {
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".cs", ".java",
    ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".swift", ".m", ".mm",
    ".kt", ".kts", ".scala", ".php", ".dart",
}
_HASH_LIKE = {
    ".py", ".pyw", ".rb", ".sh", ".bash", ".zsh", ".yml", ".yaml",
    ".toml", ".cfg", ".ini", ".r", ".pl", ".pm",
}


def _code_mode_for(path: str):
    """Return the comment/string masking mode for a path, or None to scan
    the whole file verbatim."""
    ext = os.path.splitext(path)[1].lower()
    if ext in _C_LIKE:
        return "c"
    if ext in _HASH_LIKE:
        return "hash"
    return None


def mask_non_code(text: str, mode: str, in_block: bool = False):
    """Replace comment and string-literal spans with spaces.

    Comments and string content (e.g. C ``printf(...)``) are data, not code,
    so dangerous Unicode there rarely affects execution and is usually
    intentional. Masking keeps line/column numbers valid.

    ``in_block`` carries ``/* ... */`` block-comment state across calls so a
    comment that spans several lines is masked correctly. The function returns
    ``(masked_text, still_in_block)``.
    """
    if not mode:
        return text, False
    use_hash = (mode == "hash")
    use_c = (mode in ("c", "hash"))
    use_backtick = (mode == "c")
    out: List[str] = []
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
        # line comment: //
        if text[i:i + 2] == "//":
            j = text.find("\n", i)
            end = n if j == -1 else j
            out.append(" " * (end - i))
            i = end
            continue
        # line comment: #  (shell/Python/Ruby/YAML…)
        if use_hash and c == "#":
            j = text.find("\n", i)
            end = n if j == -1 else j
            out.append(" " * (end - i))
            i = end
            continue
        # block comment: /* */  (may remain open past end of this line)
        if use_c and text[i:i + 2] == "/*":
            j = text.find("*/", i + 2)
            end = n if j == -1 else j + 2
            out.append(" " * (end - i))
            i = end
            if j == -1:
                in_block = True
            continue
        # string literals
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
                        break  # unterminated string: stop at newline
                    j += 1
                end = j
            out.append(" " * (end - i))
            i = end
            continue
        out.append(c)
        i += 1
    return "".join(out), in_block


def _iter_files(
    targets: List[str],
    recursive: bool,
    exclude: List[str],
    include: Optional[List[str]],
    max_size: int,
) -> List[str]:
    out: List[str] = []
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


# --------------------------------------------------------------------------
# Core scanning
# --------------------------------------------------------------------------
def _tokenize(line: str):
    """Yield (start, end) spans of identifier-like runs."""
    i = 0
    n = len(line)
    while i < n:
        if line[i].isascii() and (line[i].isalnum() or line[i] == "_") or \
                catalog.is_letter(ord(line[i])):
            j = i
            while j < n and (catalog.is_letter(ord(line[j])) or line[j].isdigit()
                             or line[j] == "_"):
                j += 1
            yield (i, j)
            i = j
        else:
            i += 1


def _check_mixed_script(line: str, path: str, lineno: int,
                        existing: List[Finding]) -> None:
    """Flag mixed-script tokens, merging into any existing finding at the
    same position so a confusable char is not reported twice."""
    for (start, end) in _tokenize(line):
        token = line[start:end]
        has_ascii_letter = any(c.isascii() and c.isalpha() for c in token)
        scripts = {catalog.script_of(ord(c)) for c in token if catalog.is_letter(ord(c))}
        nonascii = scripts - {"other"}
        if has_ascii_letter and nonascii:
            for k, c in enumerate(token):
                if not c.isascii() and catalog.is_letter(ord(c)):
                    col = start + k + 1
                    for f in existing:
                        if f.line == lineno and f.col == col:
                            if "mixed_script" not in f.categories:
                                f.categories.append("mixed_script")
                            break
                    else:
                        existing.append(Finding(
                            path=path, line=lineno, col=col, char=c, cp=ord(c),
                            categories=["mixed_script"], context=line,
                        ))
                    break


def scan_file(path: str, skip_strings: bool = True) -> tuple:
    """Scan a single file. Returns (findings, skip_reason_or_None).

    When ``skip_strings`` is True (default), comments and string literals are
    masked first so that only real code is checked — text inside a string
    (e.g. ``printf(...)``) or a comment cannot produce a finding.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        return [], f"unreadable: {exc}"

    if _is_binary(raw):
        return [], "binary file"

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            # Try a lossy decode so we can still surface odd bytes.
            text = raw.decode("latin-1")

    mask_mode = _code_mode_for(path) if skip_strings else None
    in_block = False

    findings: List[Finding] = []
    bidi_stack: List[Finding] = []

    lines = text.split("\n")
    for lineno, line in enumerate(lines, start=1):
        scan_line = line
        if mask_mode:
            scan_line, in_block = mask_non_code(line, mask_mode, in_block)
        line_findings: List[Finding] = []
        for col, ch in enumerate(scan_line, start=1):
            cp = ord(ch)
            cats = catalog.classify(cp)
            if not cats:
                continue
            looks = catalog.CONFUSABLES.get(cp, "")
            fnd = Finding(
                path=path, line=lineno, col=col, char=ch, cp=cp,
                categories=cats, looks_like=looks, context=line,
            )
            line_findings.append(fnd)
            # track bidi balance
            if cp in catalog.BIDI_OPEN:
                bidi_stack.append(fnd)
            elif cp in catalog.BIDI_POP:
                if bidi_stack:
                    bidi_stack.pop()
                else:
                    line_findings.append(Finding(
                        path=path, line=lineno, col=col, char=ch, cp=cp,
                        categories=["bidi_unbalanced"], context=line,
                    ))
        # mixed-script detection per line (merges into line_findings)
        _check_mixed_script(scan_line, path, lineno, line_findings)
        findings.extend(line_findings)

    # unclosed bidi at EOF: fold the imbalance into the opening's own finding
    # instead of emitting a second finding at the same position.
    for fnd in bidi_stack:
        if "bidi_unbalanced" not in fnd.categories:
            fnd.categories.append("bidi_unbalanced")

    return findings, None


def scan(
    targets: List[str],
    recursive: bool = True,
    exclude: Optional[List[str]] = None,
    include: Optional[List[str]] = None,
    max_size: int = DEFAULT_MAX_SIZE,
    skip_binary: bool = True,
    ignore: Optional[List[str]] = None,
    skip_strings: bool = True,
) -> ScanResult:
    result = ScanResult(targets=list(targets))
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
