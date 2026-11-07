#!/usr/bin/env python3
"""Syntax-check the SPA's JavaScript with `node --check`.

The SPA is spliced together by crates/webui/build.rs from
crates/webui/src/index.html, crates/webui/src/ui/*.{css,js} and
crates/proto_*/static/*.js, so a JS syntax error would only show up at
runtime in the browser. This catches it in CI instead.

Checks:
  1. every inline <script> left in index.html;
  2. every ui/*.js and proto static *.js file on its own;
  3. all of them concatenated in the order build.rs splices them. The
     files are classic scripts sharing one global scope, so a top-level
     `const`/`let`/`function` declared in two files is a SyntaxError in
     the browser that check 2 cannot see.
"""
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
UI = ROOT / "crates/webui/src/ui"
index = ROOT / "crates/webui/src/index.html"
ui_js = sorted(UI.glob("*.js")) if UI.is_dir() else []
proto_js = sorted(ROOT.glob("crates/proto_*/static/*.js"))

failed = False


def check(label, code, tmp, name):
    global failed
    out = pathlib.Path(tmp) / name
    out.write_text(code, encoding="utf-8")
    r = subprocess.run(["node", "--check", str(out)], capture_output=True, text=True)
    if r.returncode != 0:
        failed = True
        print(f"FAIL {label}\n{r.stderr}")
    else:
        print(f"ok   {label}")


with tempfile.TemporaryDirectory() as tmp:
    text = index.read_text(encoding="utf-8")
    blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", text, re.S)
    for i, block in enumerate(blocks):
        check(f"{index.relative_to(ROOT)} script #{i}", block, tmp, f"index_{i}.js")
    for src in ui_js + proto_js:
        check(str(src.relative_to(ROOT)), src.read_text(encoding="utf-8"), tmp, f"{src.stem}.js")
    if not ui_js:
        failed = True
        print(f"FAIL no JS files found under {UI.relative_to(ROOT)}")
    # Same order as build.rs: app scripts, then protocol scripts. The
    # protocol bundle is one IIFE-wrapped script per file.
    combined = "\n;\n".join(s.read_text(encoding="utf-8") for s in ui_js + proto_js)
    check("all ui/*.js + proto static JS as one global scope", combined, tmp, "combined.js")

sys.exit(1 if failed else 0)
