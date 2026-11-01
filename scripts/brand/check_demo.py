#!/usr/bin/env python3
"""Demo golden test: site/assets/demo.svg is demo.py's output, plays everywhere, and its strings
stay in step with the code.

- the committed SVG equals `python3 scripts/brand/demo.py` byte for byte;
- it is at most 40 KB, parses as XML, has a <title>, an aria-label and a prefers-reduced-motion
  rule (the final frame, no motion);
- every locklog_* tool it names is a tool the MCP server registers, and every pseudonym it shows
  has the ⟦kind:ID⟧ shape (12 Crockford base32 characters, or ⟦kind:…⟧ as patterns shows it) of a
  detector kind the code knows.

    python3 scripts/brand/check_demo.py
"""

import os
import re
import subprocess
import sys
import xml.dom.minidom

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SVG = os.path.join(ROOT, "site", "assets", "demo.svg")
errors = []

out = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "brand", "demo.py")],
                     check=True, capture_output=True).stdout
with open(SVG, "rb") as f:
    svg = f.read()
if out != svg:
    errors.append("site/assets/demo.svg is not demo.py's output: run "
                  "python3 scripts/brand/demo.py > site/assets/demo.svg")
if len(svg) > 40_000:
    errors.append(f"demo.svg is {len(svg)} bytes, over 40 KB")
xml.dom.minidom.parseString(svg)
text = svg.decode()
for need, what in (("<title>", "a <title>"), ('aria-label="', "an aria-label"),
                   ("prefers-reduced-motion: reduce", "a prefers-reduced-motion rule")):
    if need not in text:
        errors.append(f"demo.svg has no {what}")


def go_sources():
    for base, dirs, files in os.walk(os.path.join(ROOT, "internal")):
        dirs[:] = [d for d in dirs if d != "testdata"]
        for name in files:
            if name.endswith(".go") and not name.endswith("_test.go"):
                with open(os.path.join(base, name), encoding="utf-8") as f:
                    yield f.read()


code = "\n".join(go_sources())
for tool in sorted(set(re.findall(r"locklog_[a-z_]+", text))):
    if f'"{tool}"' not in code:
        errors.append(f"the demo shows {tool}, which no Go source under internal/ names as a tool")
for kind, ident in re.findall(r"⟦([a-z_]+):([^⟧]*)⟧", text):
    if ident != "…" and not re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{12}", ident):
        errors.append(f"pseudonym ⟦{kind}:{ident}⟧ does not have 12 Crockford base32 characters")
    if f'"{kind}"' not in code:
        errors.append(f"pseudonym kind {kind} is not a kind the code names")

for e in errors:
    print("check-demo:", e, file=sys.stderr)
if errors:
    sys.exit(1)
print("check-demo: ok")
