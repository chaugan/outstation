//! Build-time template step for the web UI.
//!
//! Scans every sibling `crates/proto_*/static/*.js` file, concatenates
//! them into a single `<script>` block, and substitutes the result into
//! a `<!-- @@PROTO_STATIC_JS@@ -->` placeholder in `src/index.html`.
//! The expanded HTML lands at `$OUT_DIR/index.html`, which `lib.rs`
//! pulls in via `include_str!`.
//!
//! This keeps protocol-specific UI code (ASDU type names, CP56 drift
//! charts, …) in the same crate that implements the protocol. Adding a
//! new protocol is a matter of dropping a new `static/<name>_ui.js`
//! file next to the crate's trait impl — no webui edits needed.
//!
//! Files are sorted alphabetically so the bundle order is stable across
//! builds. Each file is wrapped in a small delimiter comment to make
//! any browser-side stack trace easy to map back to its source.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const PLACEHOLDER: &str = "<!-- @@PROTO_STATIC_JS@@ -->";

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_crates = manifest_dir
        .parent()
        .expect("webui crate lives at <workspace>/crates/webui");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let index_src = manifest_dir.join("src").join("index.html");
    println!("cargo:rerun-if-changed={}", index_src.display());

    let raw = fs::read_to_string(&index_src).expect("read src/index.html");

    // Locate every sibling proto_* crate's static/ dir, then every .js
    // file inside. We rely on directory convention (`crates/proto_*`) so
    // the registry and the UI bundle stay in lockstep without a central
    // list to keep in sync.
    let mut js_files: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(workspace_crates).expect("read crates/").flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.starts_with("proto_") {
            continue;
        }
        let static_dir = path.join("static");
        if !static_dir.is_dir() {
            continue;
        }
        // rerun on any addition/removal under this proto's static dir
        println!("cargo:rerun-if-changed={}", static_dir.display());
        for f in fs::read_dir(&static_dir).unwrap_or_else(|_| panic!("read {:?}", static_dir)).flatten() {
            let p = f.path();
            if p.extension().and_then(|s| s.to_str()) == Some("js") {
                println!("cargo:rerun-if-changed={}", p.display());
                js_files.push(p);
            }
        }
    }
    js_files.sort();

    let bundle = build_bundle(&js_files);
    let expanded = raw.replace(PLACEHOLDER, &bundle);
    if !raw.contains(PLACEHOLDER) {
        // Missing placeholder is a hard error in dev — would otherwise
        // silently fall back to the un-expanded HTML and every UI
        // bug would be a mystery until someone grepped for "@@PROTO".
        panic!(
            "src/index.html is missing the `{}` placeholder — the build can't \
             splice per-protocol static JS into the served page.",
            PLACEHOLDER,
        );
    }

    let out_path = out_dir.join("index.html");
    let mut f = fs::File::create(&out_path).expect("create OUT_DIR/index.html");
    f.write_all(expanded.as_bytes()).expect("write expanded html");
}

/// Assemble the substituted `<script>` fragment. Emits one wrapped
/// block per file so browser-side errors point at a named source.
fn build_bundle(js_files: &[PathBuf]) -> String {
    let mut out = String::new();
    out.push_str("<script>\n");
    out.push_str("// ─── per-protocol static JS bundled by crates/webui/build.rs ───\n");
    out.push_str("// (sources live at crates/proto_*/static/*.js — edit there, not here)\n\n");
    for p in js_files {
        let rel = p
            .components()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let body = fs::read_to_string(p).unwrap_or_else(|e| panic!("read {:?}: {}", p, e));
        out.push_str(&format!("// ── {} ──\n", rel));
        out.push_str(&body);
        if !body.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("\n");
    }
    out.push_str("</script>\n");
    out
}

fn _suppress_unused_warn(_: &Path) {}
