//! Self-contained HTML export of a stored analysis (F131):
//! `GET /api/analyses/:id/report.html`.
//!
//! One file with inline CSS and no scripts, fonts, images or other
//! external assets, so it can be archived, mailed or printed as it is.
//! It is built from the stored summary and every stored endpoint
//! detail (read as plain JSON, so older rows render too) plus the run's
//! facts when the run still exists. Every value is HTML-escaped.

use std::fmt::Write as _;

use serde_json::Value;

use crate::db::StoredAnalysis;
use crate::dto::RunState;

/// Escape text for HTML element and attribute content.
pub(crate) fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

fn s(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(x) => x.clone(),
        other => other.to_string(),
    }
}

fn pct(v: &Value) -> String {
    v.as_f64()
        .map(|x| format!("{x:.1}%"))
        .unwrap_or_else(|| "–".into())
}

fn utc(secs: u64) -> String {
    // Civil date from days since the epoch (Howard Hinnant's algorithm).
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// The verdict class used for colour *and* a text badge, so the page
/// reads the same in black and white.
fn tone(outcome_or_verdict: &str) -> &'static str {
    match outcome_or_verdict {
        "pass" | "all_correct" => "ok",
        "fail" | "failed" | "run_failed" | "no_delivery" | "no_session" | "partial" => "bad",
        _ => "warn",
    }
}

const CSS: &str = r#"
:root{--fg:#1d1d1b;--dim:#5c5c58;--rule:#cfcfc8;--ok:#2f6b2f;--warn:#8a5a00;--bad:#9b1c1c;--bg:#fff}
*{box-sizing:border-box}
body{margin:0;padding:24px;font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:var(--bg)}
main{max-width:1100px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px;border-bottom:1px solid var(--rule);padding-bottom:4px}
h3{font-size:15px;margin:18px 0 6px}
.meta{color:var(--dim);margin:0 0 16px}
.verdict{border:2px solid currentColor;border-radius:4px;padding:12px 16px;margin:12px 0}
.verdict strong{font-size:18px}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.badge{display:inline-block;border:1px solid currentColor;border-radius:3px;padding:0 5px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.02em}
table{border-collapse:collapse;width:100%;margin:6px 0 12px;font-size:13px}
th,td{border:1px solid var(--rule);padding:4px 6px;text-align:left;vertical-align:top}
th{background:#f2f2ee}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 16px;margin:0}
dt{color:var(--dim)}dd{margin:0}
ul.notes{margin:4px 0;padding-left:20px}
.warnbox{border-left:4px solid var(--warn);padding:6px 10px;background:#fbf6ea;margin:8px 0}
section.ep{break-inside:avoid;border-top:1px solid var(--rule);padding-top:6px}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace}
footer{margin-top:32px;color:var(--dim);font-size:12px}
@media print{body{padding:0;font-size:11px}h2{break-after:avoid}table{font-size:10px}.verdict{border-width:1px}section.ep{break-inside:avoid-page}a{color:inherit;text-decoration:none}}
"#;

/// Render the report. `details` are `(endpoint, detail JSON)`.
pub(crate) fn render(
    row: &StoredAnalysis,
    summary: &Value,
    details: &[(String, Value)],
    run: Option<&RunState>,
) -> String {
    let mut h = String::with_capacity(32 * 1024 + details.len() * 2048);
    let verdict = s(&summary["verdict"]);
    let _ = write!(
        h,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>Fidelity report: analysis {} of run {}</title><style>{CSS}</style></head><body><main>",
        row.id, row.run_id
    );
    let _ = write!(
        h,
        "<h1>Replay fidelity report</h1><p class=\"meta\">Analysis #{} of run #{} · {} · source {} · protocol {} · role {} · mode {}</p>",
        row.id,
        row.run_id,
        esc(&utc(row.created_at)),
        esc(&row.source),
        esc(&s(&summary["protocol"])),
        esc(&s(&summary["role"])),
        esc(&s(&summary["mode"]))
    );

    // Verdict.
    let t = tone(&verdict);
    let _ = write!(
        h,
        "<div class=\"verdict {t}\"><span class=\"badge\">{}</span> <strong>{}</strong> · score {}<br><span>{}</span></div>",
        match t {
            "ok" => "pass",
            "bad" => "fail",
            _ => "check",
        },
        esc(&verdict),
        esc(&pct(&summary["score_pct"])),
        esc(&s(&summary["verdict_reason"]))
    );
    if let Some(w) = summary["run_warning"].as_str() {
        let _ = write!(
            h,
            "<p class=\"warnbox\"><strong>Warning:</strong> {}</p>",
            esc(w)
        );
    }
    if let Some(notes) = summary["notes"].as_array().filter(|n| !n.is_empty()) {
        h.push_str("<h2>Notes</h2><ul class=\"notes\">");
        for n in notes {
            let _ = write!(h, "<li>{}</li>", esc(&s(n)));
        }
        h.push_str("</ul>");
    }

    // Run.
    h.push_str("<h2>Run</h2><dl>");
    let mut dd = |k: &str, v: String| {
        let _ = write!(h, "<dt>{}</dt><dd>{}</dd>", esc(k), esc(&v));
    };
    dd("Run status", s(&summary["run_status"]));
    dd("Source pcap", s(&summary["original_pcap"]));
    dd(
        "Capture",
        format!(
            "{} packets, {} bytes",
            s(&summary["captured_total_packets"]),
            s(&summary["captured_size_bytes"])
        ),
    );
    if let Some(r) = run {
        dd("Started", utc(r.started_at));
        if let Some(f) = r.finished_at {
            dd("Finished", utc(f));
        }
        dd("Target", format!("{}:{}", r.target_ip, r.target_port));
        if let Some(b) = &r.benchmark {
            dd(
                "Messages",
                format!(
                    "{} sent, {} received",
                    b.total_messages_sent, b.total_messages_received
                ),
            );
            dd(
                "Ack latency",
                format!(
                    "p50 {:.1} ms · p90 {:.1} ms · p99 {:.1} ms · max {:.1} ms",
                    b.aggregate_latency_p50_us as f64 / 1e3,
                    b.aggregate_latency_p90_us as f64 / 1e3,
                    b.aggregate_latency_p99_us as f64 / 1e3,
                    b.aggregate_latency_max_us as f64 / 1e3
                ),
            );
            dd(
                "Sessions",
                format!(
                    "{} ({} failed, {} stopped)",
                    b.per_session.len(),
                    b.sessions_failed(),
                    b.sessions_cancelled()
                ),
            );
        }
        if let Some(e) = &r.error {
            dd("Run error", e.clone());
        }
    }
    h.push_str("</dl>");
    if let Some(ws) = run
        .and_then(|r| r.benchmark.as_ref())
        .map(|b| &b.warnings)
        .filter(|w| !w.is_empty())
    {
        h.push_str("<ul class=\"notes\">");
        for w in ws {
            let _ = write!(h, "<li class=\"warn\">Run warning: {}</li>", esc(w));
        }
        h.push_str("</ul>");
    }

    // Fleet.
    let f = &summary["fleet"];
    h.push_str("<h2>Fleet</h2><table><thead><tr>");
    let cols = [
        ("Endpoints", "slave_count"),
        ("Correct", "fully_correct"),
        ("Partial", "partial"),
        ("Failed", "failed"),
        ("Inconclusive", "inconclusive"),
        ("Never connected", "never_connected"),
        ("Unpaired", "unpaired"),
        ("Reconnects", "reconnects"),
    ];
    for (label, _) in cols {
        let _ = write!(h, "<th scope=\"col\" class=\"n\">{label}</th>");
    }
    h.push_str("<th scope=\"col\" class=\"n\">Mean score</th><th scope=\"col\" class=\"n\">Frame-weighted</th></tr></thead><tbody><tr>");
    for (_, key) in cols {
        let _ = write!(h, "<td class=\"n\">{}</td>", esc(&s(&f[key])));
    }
    let _ = write!(
        h,
        "<td class=\"n\">{}</td><td class=\"n\">{}</td></tr></tbody></table>",
        esc(&pct(&f["aggregate_score_pct"])),
        esc(&pct(&f["frame_weighted_score_pct"]))
    );

    // Endpoints.
    let slaves = summary["slaves"].as_array().cloned().unwrap_or_default();
    let _ = write!(h, "<h2>Endpoints ({})</h2>", slaves.len());
    h.push_str(
        "<table><thead><tr><th scope=\"col\">Endpoint</th><th scope=\"col\">Outcome</th>\
         <th scope=\"col\">Verdict</th><th scope=\"col\" class=\"n\">Score</th>\
         <th scope=\"col\" class=\"n\">Delivered</th><th scope=\"col\" class=\"n\">Sessions</th>\
         <th scope=\"col\">Reason</th></tr></thead><tbody>",
    );
    for e in &slaves {
        let outcome = s(&e["outcome"]);
        let _ = write!(
            h,
            "<tr><td><a href=\"#ep-{id}\"><code>{ip}</code></a></td><td class=\"{t}\"><span class=\"badge\">{o}</span></td>\
             <td>{v}</td><td class=\"n\">{sc}</td><td class=\"n\">{d}/{x}</td><td class=\"n\">{n}</td><td>{r}</td></tr>",
            id = esc(&s(&e["slave_ip"]).replace(['.', ':'], "-")),
            ip = esc(&s(&e["slave_ip"])),
            t = tone(&outcome),
            o = esc(&outcome),
            v = esc(&s(&e["verdict"])),
            sc = esc(&pct(&e["score_pct"])),
            d = esc(&s(&e["delivered_iframes"])),
            x = esc(&s(&e["expected_iframes"])),
            n = esc(&s(&e["sessions"])),
            r = esc(&s(&e["verdict_reason"])),
        );
    }
    h.push_str("</tbody></table>");

    // Endpoint details.
    if !details.is_empty() {
        h.push_str("<h2>Endpoint details</h2>");
    }
    for (ep, d) in details {
        let _ = write!(
            h,
            "<section class=\"ep\" id=\"ep-{}\"><h3><code>{}</code> · {} · {}</h3><p>{}</p>",
            esc(&ep.replace(['.', ':'], "-")),
            esc(ep),
            esc(&s(&d["verdict"])),
            esc(&pct(&d["score_pct"])),
            esc(&s(&d["verdict_reason"]))
        );
        if let Some(notes) = d["notes"].as_array().filter(|n| !n.is_empty()) {
            h.push_str("<ul class=\"notes\">");
            for n in notes {
                let _ = write!(h, "<li>{}</li>", esc(&s(n)));
            }
            h.push_str("</ul>");
        }
        if let Some(ss) = d["sessions"].as_array().filter(|x| x.len() > 1) {
            h.push_str(
                "<table><thead><tr><th scope=\"col\" class=\"n\">#</th><th scope=\"col\">Flow</th>\
                 <th scope=\"col\" class=\"n\">Delivered</th><th scope=\"col\" class=\"n\">Score</th>\
                 <th scope=\"col\">Verdict</th></tr></thead><tbody>",
            );
            for x in ss {
                let _ = write!(
                    h,
                    "<tr><td class=\"n\">{}</td><td><code>{} → {}</code></td><td class=\"n\">{}/{}</td><td class=\"n\">{}</td><td>{}</td></tr>",
                    esc(&s(&x["index"])),
                    esc(&s(&x["flow"]["client"])),
                    esc(&s(&x["flow"]["server"])),
                    esc(&s(&x["delivered"])),
                    esc(&s(&x["expected"])),
                    esc(&pct(&x["score_pct"])),
                    esc(&s(&x["verdict"]))
                );
            }
            h.push_str("</tbody></table>");
        }
        h.push_str("</section>");
    }
    let _ = write!(
        h,
        "<footer>Generated by outstation {} from stored analysis #{}. The JSON of this analysis: <code>GET /api/analyses/{}</code>.</footer></main></body></html>",
        env!("CARGO_PKG_VERSION"),
        row.id,
        row.id
    );
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn report_is_escaped_and_self_contained() {
        let row = StoredAnalysis {
            id: 3,
            run_id: 7,
            created_at: 1_700_000_000,
            verdict: "partial".into(),
            score_pct: 50.0,
            source: "auto".into(),
        };
        let summary = json!({
            "verdict": "partial", "score_pct": 50.0, "protocol": "iec104",
            "verdict_reason": "<script>alert(1)</script>",
            "run_warning": "the run being analysed was STOPPED",
            "fleet": {"slave_count": 2, "fully_correct": 1, "failed": 1},
            "slaves": [
                {"slave_ip": "10.0.0.2", "outcome": "pass", "verdict": "good_delivery", "score_pct": 100.0},
                {"slave_ip": "10.0.0.3", "outcome": "fail", "verdict": "partial_delivery", "score_pct": 0.0,
                 "verdict_reason": "\"quoted\" & <b>"}
            ]
        });
        let details = vec![(
            "10.0.0.3".to_string(),
            json!({"verdict": "partial_delivery", "notes": ["n<1>"], "sessions": []}),
        )];
        let h = render(&row, &summary, &details, None);
        assert!(h.starts_with("<!doctype html>"));
        assert!(!h.contains("<script"), "nothing executable");
        assert!(h.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(h.contains("&quot;quoted&quot; &amp; &lt;b&gt;"));
        assert!(h.contains("n&lt;1&gt;"));
        assert!(h.contains("STOPPED"));
        assert!(h.contains("id=\"ep-10-0-0-3\""));
        assert!(h.contains("2023-11-14 22:13:20 UTC"));
        // No external asset of any kind.
        for needle in ["src=", "http://", "https://", "@import", "url("] {
            assert!(!h.contains(needle), "{needle}");
        }
        assert!(h.contains("@media print"));
    }
}
