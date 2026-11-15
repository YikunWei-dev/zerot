# Intentional dangerous-Unicode sample for testing zerot.
secret = "admin"​  # zero-width space after string
x﻿ = 1  # BOM / ZWNBSP at start of line
note = "hello"‮‬"world"  # RTL override (Trojan Source)
gap = 1 2  # no-break space
indent　with ideographic space
def аррprove():  # mixed-script + confusable (Cyrillic a/p)
    return True
fw = "ａbc"  # fullwidth 'a' confusable
open = ⁦⁧⁨‪‫  # unbalanced bidi isolate open
