"""zerot — command line interface (software mode)."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__, catalog
from .config import load_config
from .engine import scan
from .report import render_json, render_markdown, render_sarif, render_text


def _sev_rank(s: str) -> int:
    return catalog.SEVERITY_ORDER.get(s, 0)


def _should_fail(result, fail_severity: str) -> bool:
    """Fail if any finding has severity >= the given threshold."""
    thr = _sev_rank(fail_severity)
    for f in result.findings:
        for c in f.categories:
            if _sev_rank(catalog.CATEGORIES.get(c, ("", "low", ""))[1]) >= thr:
                return True
    return False


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="zerot",
        description="Detect dangerous Unicode characters in source code "
                    "(zero-width, bidi/Trojan Source, confusables, fullwidth...).",
    )
    p.add_argument("--version", action="version", version=f"zerot {__version__}")
    sub = p.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="scan targets and print a report")
    scan_p.add_argument("targets", nargs="+", help="files or directories")
    scan_p.add_argument("-r", "--recursive", dest="recursive", action="store_true",
                        default=None, help="recurse into directories (default)")
    scan_p.add_argument("--no-recursive", dest="recursive", action="store_false",
                        help="do not recurse into directories")
    scan_p.add_argument("-e", "--exclude", action="append", default=None,
                        help="fnmatch pattern to skip (repeatable)")
    scan_p.add_argument("-i", "--include", action="append", default=None,
                        help="only scan files matching fnmatch pattern (repeatable)")
    scan_p.add_argument("--ignore", action="append", default=None,
                        help="ignore findings whose file path matches this fnmatch "
                             "pattern (repeatable)")
    scan_p.add_argument("--max-size", type=int, default=None,
                        help="skip files larger than N bytes")
    scan_p.add_argument("--no-binary", dest="skip_binary", action="store_false",
                        help="do not skip binary files")
    scan_p.add_argument("--binary-error", dest="binary_error", action="store_true",
                        help="treat binary files as errors")
    scan_p.add_argument("-f", "--format", choices=["md", "json", "text", "sarif"],
                        default=None, help="output format (default md)")
    scan_p.add_argument("-o", "--out", default=None,
                        help="write report to this file instead of stdout")
    scan_p.add_argument("--config", default=None, help="path to JSON config")
    scan_p.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                        default=None, help="fail if any finding's severity is at "
                        "least this (default: high)")
    scan_p.add_argument("--no-color", action="store_true",
                        help="disable colored text output")
    scan_p.add_argument("--scan-strings", action="store_true",
                        help="also scan text inside comments and string literals "
                             "(default: skip them, since they do not affect execution)")
    scan_p.add_argument("-q", "--quiet", action="store_true",
                        help="suppress the report, only set exit code")

    check_p = sub.add_parser(
        "check", help="like scan but exit non-zero when issues are found (CI)")
    check_p.add_argument("targets", nargs="+", help="files or directories")
    check_p.add_argument("-r", "--recursive", dest="recursive", action="store_true",
                         default=None)
    check_p.add_argument("--no-recursive", dest="recursive", action="store_false")
    check_p.add_argument("-e", "--exclude", action="append", default=None)
    check_p.add_argument("-i", "--include", action="append", default=None)
    check_p.add_argument("--max-size", type=int, default=None)
    check_p.add_argument("--ignore", action="append", default=None)
    check_p.add_argument("--no-binary", dest="skip_binary", action="store_false")
    check_p.add_argument("--config", default=None)
    check_p.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                         default=None)
    check_p.add_argument("--scan-strings", action="store_true",
                        help="also scan text inside comments and string literals "
                             "(default: skip them, since they do not affect execution)")
    return p


def _merge(args, cfg: dict) -> dict:
    opts = {}
    for key in ("recursive", "exclude", "include", "max_size", "skip_binary", "ignore"):
        v = getattr(args, key, None)
        if v is None:
            v = cfg.get(key)
        opts[key] = v
    if opts.get("recursive") is None:
        opts["recursive"] = True
    if opts.get("max_size") is None:
        from .engine import DEFAULT_MAX_SIZE
        opts["max_size"] = DEFAULT_MAX_SIZE
    if opts.get("skip_binary") is None:
        opts["skip_binary"] = True
    # format default
    fmt = getattr(args, "format", None) or cfg.get("format", "md")
    opts["format"] = fmt
    # string/comment masking: skip by default; --scan-strings or config overrides
    skip_strings = cfg.get("skip_strings", True)
    if getattr(args, "scan_strings", False):
        skip_strings = False
    opts["skip_strings"] = skip_strings
    # fail settings: severity threshold (default high)
    fail_on = args.fail_on or cfg.get("fail_on") or cfg.get("min_severity") or "high"
    opts["fail_severity"] = fail_on
    return opts


def run(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2

    cfg = load_config(args.config if getattr(args, "config", None) else None)
    opts = _merge(args, cfg)

    result = scan(
        targets=args.targets,
        recursive=opts["recursive"],
        exclude=opts["exclude"],
        include=opts["include"],
        max_size=opts["max_size"],
        skip_binary=opts["skip_binary"],
        ignore=opts["ignore"],
        skip_strings=opts["skip_strings"],
    )

    if getattr(args, "command", None) == "check":
        failed = _should_fail(result, opts["fail_severity"])
        if not getattr(args, "quiet", False):
            print(render_text(result))
        return 1 if failed else 0

    # scan command
    if not getattr(args, "quiet", False):
        if opts["format"] == "json":
            text = render_json(result)
        elif opts["format"] == "text":
            use_color = (not getattr(args, "no_color", False)) and sys.stdout.isatty()
            text = render_text(result, color=use_color)
        elif opts["format"] == "sarif":
            text = render_sarif(result)
        else:
            text = render_markdown(result)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"zerot: wrote report to {args.out}", file=sys.stderr)
        else:
            print(text)

    failed = _should_fail(result, opts["fail_severity"])
    return 1 if failed else 0


def main(argv: Optional[List[str]] = None) -> int:
    try:
        return run(argv)
    except BrokenPipeError:
        return 0
