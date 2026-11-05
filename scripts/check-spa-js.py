#!/usr/bin/env python3
"""Syntax-check every inline <script> in the SPA and every protocol UI module with `node --check`.

The SPA is a single HTML file spliced together by crates/webui/build.rs, so a JS syntax error
only shows up at runtime in the browser. This catches it in CI instead.
"""
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sources = [ROOT / "crates/webui/src/index.html"]
sources += sorted(ROOT.glob("crates/*/static/*.js"))
sources += sorted((ROOT / "crates/webui/src/ui").glob("*.js")) if (ROOT / "crates/webui/src/ui").is_dir() else []

failed = False
with tempfile.TemporaryDirectory() as tmp:
    for src in sources:
        text = src.read_text(encoding="utf-8")
        if src.suffix == ".html":
            blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", text, re.S)
            # build.rs placeholder is replaced at build time; neutralise it for the check.
            blocks = [b.replace("@@PROTO_STATIC_JS@@", "") for b in blocks]
        else:
            blocks = [text]
        for i, block in enumerate(blocks):
            out = pathlib.Path(tmp) / f"{src.stem}_{i}.js"
            out.write_text(block, encoding="utf-8")
            r = subprocess.run(["node", "--check", str(out)], capture_output=True, text=True)
            if r.returncode != 0:
                failed = True
                print(f"FAIL {src.relative_to(ROOT)} script #{i}\n{r.stderr}")
            else:
                print(f"ok   {src.relative_to(ROOT)} script #{i}")
sys.exit(1 if failed else 0)
