//! Build-time template step for the web UI.
//!
//! The SPA source lives in several files so it can be read, reviewed
//! and syntax-checked in pieces, but the binary serves one
//! self-contained HTML page (no extra requests, works air-gapped).
//! This script splices the pieces into `src/index.html`:
//!
//! - `<!-- @@APP_CSS@@ -->` becomes a `<style>` block with
//!   `src/ui/*.css` (sorted by file name).
//! - `<!-- @@APP_JS@@ -->` becomes one `<script>` block per
//!   `src/ui/*.js` file, in file-name order. The files are classic
//!   scripts that share the page's global scope; the numeric prefixes
//!   (`00-core.js`, `10-…`) fix the load order.
//! - `<!-- @@PROTO_STATIC_JS@@ -->` becomes a `<script>` block with
//!   every sibling `crates/proto_*/static/*.js` file, so protocol UI
//!   code (ASDU names, CP56 drift charts, …) stays in the crate that
//!   implements the protocol.
//!
//! The expanded HTML lands at `$OUT_DIR/index.html`, which the
//! router pulls in via `include_str!`. Each spliced file is preceded
//! by a delimiter comment so a browser stack trace maps back to its
//! source. A missing placeholder, or one left over after expansion, is
//! a build error.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const CSS_PLACEHOLDER: &str = "<!-- @@APP_CSS@@ -->";
const APP_JS_PLACEHOLDER: &str = "<!-- @@APP_JS@@ -->";
const PROTO_PLACEHOLDER: &str = "<!-- @@PROTO_STATIC_JS@@ -->";

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_crates = manifest_dir
        .parent()
        .expect("webui crate lives at <workspace>/crates/webui");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let index_src = manifest_dir.join("src").join("index.html");
    println!("cargo:rerun-if-changed={}", index_src.display());
    let raw = fs::read_to_string(&index_src).expect("read src/index.html");

    let ui_dir = manifest_dir.join("src").join("ui");
    println!("cargo:rerun-if-changed={}", ui_dir.display());
    let css_files = files_with_ext(&ui_dir, "css");
    let app_js_files = files_with_ext(&ui_dir, "js");

    // Every sibling proto_* crate's static/*.js. Directory convention
    // keeps the registry and the UI bundle in lockstep without a
    // central list.
    let mut proto_js: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(workspace_crates)
        .expect("read crates/")
        .flatten()
    {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !path.is_dir() || !name.starts_with("proto_") {
            continue;
        }
        let static_dir = path.join("static");
        if static_dir.is_dir() {
            println!("cargo:rerun-if-changed={}", static_dir.display());
            proto_js.extend(files_with_ext(&static_dir, "js"));
        }
    }
    proto_js.sort();

    for ph in [CSS_PLACEHOLDER, APP_JS_PLACEHOLDER, PROTO_PLACEHOLDER] {
        if !raw.contains(ph) {
            panic!(
                "src/index.html is missing the `{ph}` placeholder; the build can't \
                 splice the UI sources into the served page."
            );
        }
    }

    let mut css = String::from("<style>\n");
    for p in &css_files {
        css.push_str(&format!("/* ── {} ── */\n", rel(p)));
        push_file(&mut css, p);
    }
    css.push_str("</style>");

    let mut app_js = String::new();
    for p in &app_js_files {
        app_js.push_str("<script>\n");
        app_js.push_str(&format!("// ── {} ──\n", rel(p)));
        push_file(&mut app_js, p);
        app_js.push_str("</script>\n");
    }

    let mut proto = String::from("<script>\n");
    proto.push_str("// ─── per-protocol static JS bundled by crates/webui/build.rs ───\n");
    proto.push_str("// (sources live at crates/proto_*/static/*.js — edit there, not here)\n\n");
    for p in &proto_js {
        proto.push_str(&format!("// ── {} ──\n", rel(p)));
        push_file(&mut proto, p);
        proto.push('\n');
    }
    proto.push_str("</script>\n");

    // Splice in a fixed order, the HTML shell first, so a placeholder
    // string inside a spliced file is never itself expanded.
    let (a, rest) = raw.split_once(CSS_PLACEHOLDER).unwrap();
    let (b, rest) = rest.split_once(APP_JS_PLACEHOLDER).unwrap();
    let (c, d) = rest.split_once(PROTO_PLACEHOLDER).unwrap();
    if [a, b, c, d].iter().any(|s| s.contains("<!-- @@")) {
        panic!("src/index.html has a duplicate or out-of-order @@ placeholder");
    }
    let expanded = format!("{a}{css}{b}{app_js}{c}{proto}{d}");

    let out_path = out_dir.join("index.html");
    let mut f = fs::File::create(&out_path).expect("create OUT_DIR/index.html");
    f.write_all(expanded.as_bytes())
        .expect("write expanded html");
}

/// Sorted list of `dir/*.<ext>`, each registered for rebuilds.
fn files_with_ext(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {dir:?}: {e}"))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some(ext))
        .collect();
    out.sort();
    for p in &out {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    out
}

/// Last three path components, for the delimiter comments.
fn rel(p: &Path) -> String {
    let parts: Vec<String> = p
        .components()
        .rev()
        .take(3)
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    parts.into_iter().rev().collect::<Vec<_>>().join("/")
}

fn push_file(out: &mut String, p: &Path) {
    let body = fs::read_to_string(p).unwrap_or_else(|e| panic!("read {p:?}: {e}"));
    // A literal `</script>` or `</style>` inside a spliced file would end
    // the block early.
    if body.contains("</script") || body.contains("</style") {
        panic!("{p:?} contains a closing </script> or </style> tag");
    }
    out.push_str(&body);
    if !body.ends_with('\n') {
        out.push('\n');
    }
}
