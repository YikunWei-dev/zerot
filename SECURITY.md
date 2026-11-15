# Security Policy

## Reporting a vulnerability

If you discover a vulnerability in **zerot** (for example, a class of dangerous
Unicode character that the scanner misses, or a way its reports could be
misleading in a security review), please report it privately.

- Open a security advisory on GitHub: **GitHub → Security → Advisories → New draft
  security advisory**, or
- Email the maintainers via the GitHub Security tab.

Please **do not** open a public issue for security-sensitive reports.

We will acknowledge within a few days and aim to ship a fix and a new release
promptly. Credit will be given (with your permission) in the changelog.

## Scope

zerot is a static-analysis linter. It does not execute code. Its purpose is to
surface unicode-based obfuscation such as *Trojan Source* (bidirectional
overrides), zero-width characters, homoglyphs and mixed-script identifiers that
could be used to hide malicious logic in source code.

## Supported versions

Only the latest released `1.x` line receives security fixes.
