//! Run-to-run comparison (T10): per-RTU and fleet deltas between two
//! benchmark runs, from their stored analysis summaries and benchmark
//! reports, plus a list of regressions against configurable
//! thresholds. Pure functions; the route lives in `routes/compare.rs`.
//!
//! RTUs are keyed by source IP: the analysis' `slave_ip` (the RTU in
//! slave role, the master's IP in master role) and the benchmark's
//! per-session `src_ip` (the same address in both roles).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde::Serialize;
use serde_json::Value;

use crate::dto::BenchmarkReportJson;

/// Regression thresholds, all overridable as query parameters.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub(crate) struct Thresholds {
    /// Score drop (percentage points) that counts as a regression.
    pub(crate) score_drop: f64,
    /// Delivered-percentage drop (percentage points).
    pub(crate) delivered_drop: f64,
    /// Relative p50 latency increase, in percent.
    pub(crate) p50_increase_pct: f64,
    /// Relative p99 latency increase, in percent.
    pub(crate) p99_increase_pct: f64,
    /// Latency increases smaller than this (µs) are noise, never flagged.
    pub(crate) latency_min_us: f64,
    /// Relative fleet throughput drop, in percent.
    pub(crate) throughput_drop_pct: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            score_drop: 1.0,
            delivered_drop: 1.0,
            p50_increase_pct: 20.0,
            p99_increase_pct: 20.0,
            latency_min_us: 1000.0,
            throughput_drop_pct: 10.0,
        }
    }
}

impl Thresholds {
    pub(crate) fn validate(&self) -> Result<(), String> {
        for (k, v) in [
            ("score_drop", self.score_drop),
            ("delivered_drop", self.delivered_drop),
            ("p50_increase_pct", self.p50_increase_pct),
            ("p99_increase_pct", self.p99_increase_pct),
            ("latency_min_us", self.latency_min_us),
            ("throughput_drop_pct", self.throughput_drop_pct),
        ] {
            if !(v.is_finite() && v >= 0.0) {
                return Err(format!("{k} must be a finite number >= 0, got {v}"));
            }
        }
        Ok(())
    }
}

/// One run's inputs to a comparison.
pub(crate) struct Side<'a> {
    /// Stored analysis summary (`GET /api/analyses/:id` body).
    pub(crate) summary: &'a Value,
    pub(crate) bench: Option<&'a BenchmarkReportJson>,
}

/// One RTU's figures in one run. `None` = not known for that run.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub(crate) struct RtuSide {
    pub(crate) score: Option<f64>,
    pub(crate) verdict: Option<String>,
    /// `pass`, `fail` or `inconclusive`.
    pub(crate) outcome: Option<String>,
    pub(crate) expected: Option<u64>,
    pub(crate) delivered: Option<u64>,
    pub(crate) delivered_pct: Option<f64>,
    pub(crate) p50_us: Option<u64>,
    pub(crate) p99_us: Option<u64>,
    pub(crate) msgs_sent: Option<u64>,
    /// Sessions of this RTU that ended with an error.
    pub(crate) errors: u64,
    /// First session error, if any.
    pub(crate) error: Option<String>,
}

/// `b - a` for each metric known on both sides.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub(crate) struct RtuDelta {
    pub(crate) score: Option<f64>,
    pub(crate) delivered: Option<i64>,
    pub(crate) delivered_pct: Option<f64>,
    pub(crate) p50_us: Option<i64>,
    pub(crate) p99_us: Option<i64>,
    pub(crate) msgs_sent: Option<i64>,
    pub(crate) errors: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct RtuRow {
    pub(crate) rtu: String,
    pub(crate) a: RtuSide,
    pub(crate) b: RtuSide,
    pub(crate) delta: RtuDelta,
    pub(crate) verdict_changed: bool,
    /// Metrics of this RTU flagged as regressions.
    pub(crate) regressions: Vec<&'static str>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub(crate) struct FleetSide {
    pub(crate) verdict: Option<String>,
    pub(crate) score: Option<f64>,
    pub(crate) frame_weighted_score: Option<f64>,
    pub(crate) rtus: usize,
    pub(crate) fully_correct: Option<u64>,
    pub(crate) partial: Option<u64>,
    pub(crate) failed: Option<u64>,
    pub(crate) never_connected: Option<u64>,
    pub(crate) expected: u64,
    pub(crate) delivered: u64,
    pub(crate) delivered_pct: Option<f64>,
    pub(crate) sessions: Option<u64>,
    pub(crate) sessions_failed: Option<u64>,
    pub(crate) msgs_sent: Option<u64>,
    pub(crate) msgs_received: Option<u64>,
    pub(crate) p50_us: Option<u64>,
    pub(crate) p90_us: Option<u64>,
    pub(crate) p99_us: Option<u64>,
    pub(crate) max_us: Option<u64>,
    pub(crate) throughput: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub(crate) struct FleetDelta {
    pub(crate) score: Option<f64>,
    pub(crate) frame_weighted_score: Option<f64>,
    pub(crate) delivered: i64,
    pub(crate) delivered_pct: Option<f64>,
    pub(crate) sessions_failed: Option<i64>,
    pub(crate) msgs_sent: Option<i64>,
    pub(crate) msgs_received: Option<i64>,
    pub(crate) p50_us: Option<i64>,
    pub(crate) p90_us: Option<i64>,
    pub(crate) p99_us: Option<i64>,
    pub(crate) max_us: Option<i64>,
    pub(crate) throughput: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct FleetCompare {
    pub(crate) a: FleetSide,
    pub(crate) b: FleetSide,
    pub(crate) delta: FleetDelta,
    pub(crate) verdict_changed: bool,
}

/// One regression: `metric` got worse from `a` to `b` by more than
/// `threshold`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Regression {
    /// `fleet` or `rtu`.
    pub(crate) scope: &'static str,
    pub(crate) rtu: Option<String>,
    pub(crate) metric: &'static str,
    pub(crate) a: Value,
    pub(crate) b: Value,
    pub(crate) threshold: Option<f64>,
    pub(crate) message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Comparison {
    pub(crate) fleet: FleetCompare,
    pub(crate) rtus: Vec<RtuRow>,
    pub(crate) only_in_a: Vec<String>,
    pub(crate) only_in_b: Vec<String>,
    pub(crate) regressions: Vec<Regression>,
    pub(crate) regressed: bool,
    pub(crate) thresholds: Thresholds,
}

fn f(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(Value::as_f64)
}
fn u(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(Value::as_u64)
}
fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

fn pct(delivered: u64, expected: u64) -> Option<f64> {
    (expected > 0).then(|| delivered as f64 * 100.0 / expected as f64)
}

/// Sort key that orders IPv4 addresses numerically, anything else after.
fn ip_key(k: &str) -> (u8, u32, String) {
    match k.parse::<Ipv4Addr>() {
        Ok(ip) => (0, u32::from(ip), String::new()),
        Err(_) => (1, 0, k.to_string()),
    }
}

fn rtu_sides(side: &Side<'_>) -> BTreeMap<String, RtuSide> {
    let mut out: BTreeMap<String, RtuSide> = BTreeMap::new();
    if let Some(slaves) = side.summary.get("slaves").and_then(Value::as_array) {
        for sl in slaves {
            let Some(ip) = s(sl, "slave_ip") else {
                continue;
            };
            let e = out.entry(ip).or_default();
            e.score = f(sl, "score_pct");
            e.verdict = s(sl, "verdict");
            e.outcome = s(sl, "outcome");
            e.expected = u(sl, "expected_iframes");
            e.delivered = u(sl, "delivered_iframes");
            e.delivered_pct = match (e.delivered, e.expected) {
                (Some(d), Some(x)) => pct(d, x),
                _ => None,
            };
        }
    }
    if let Some(b) = side.bench {
        for ses in &b.per_session {
            let e = out.entry(ses.src_ip.clone()).or_default();
            // Several sessions per RTU (rare): sum volumes, keep the
            // worst latency.
            e.msgs_sent = Some(e.msgs_sent.unwrap_or(0) + ses.messages_sent);
            if ses.messages_sent > 0 || ses.latency_p99_us > 0 {
                e.p50_us = Some(e.p50_us.unwrap_or(0).max(ses.latency_p50_us));
                e.p99_us = Some(e.p99_us.unwrap_or(0).max(ses.latency_p99_us));
            }
            if let Some(err) = &ses.error {
                e.errors += 1;
                e.error.get_or_insert_with(|| err.clone());
            }
        }
    }
    out
}

fn fleet_side(side: &Side<'_>, rtus: &BTreeMap<String, RtuSide>) -> FleetSide {
    let sm = side.summary;
    let fl = sm.get("fleet").cloned().unwrap_or(Value::Null);
    let expected: u64 = rtus.values().filter_map(|r| r.expected).sum();
    let delivered: u64 = rtus.values().filter_map(|r| r.delivered).sum();
    let b = side.bench;
    FleetSide {
        verdict: s(sm, "verdict"),
        score: f(sm, "score_pct"),
        frame_weighted_score: f(&fl, "frame_weighted_score_pct"),
        rtus: rtus.len(),
        fully_correct: u(&fl, "fully_correct"),
        partial: u(&fl, "partial"),
        failed: u(&fl, "failed"),
        never_connected: u(&fl, "never_connected"),
        expected,
        delivered,
        delivered_pct: pct(delivered, expected),
        sessions: b.map(|b| b.per_session.len() as u64),
        sessions_failed: b.map(|b| b.sessions_failed() as u64),
        msgs_sent: b.map(|b| b.total_messages_sent),
        msgs_received: b.map(|b| b.total_messages_received),
        p50_us: b.map(|b| b.aggregate_latency_p50_us),
        p90_us: b.map(|b| b.aggregate_latency_p90_us),
        p99_us: b.map(|b| b.aggregate_latency_p99_us),
        max_us: b.map(|b| b.aggregate_latency_max_us),
        throughput: b.map(|b| b.aggregate_throughput_msgs_per_sec),
    }
}

fn df(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    Some(b? - a?)
}
fn di(a: Option<u64>, b: Option<u64>) -> Option<i64> {
    Some(b? as i64 - a? as i64)
}

/// Rank of a per-endpoint outcome; higher is better.
fn outcome_rank(o: &str) -> u8 {
    match o {
        "pass" => 2,
        "inconclusive" => 1,
        _ => 0,
    }
}

/// Rank of a fleet verdict; higher is better. Unknown names rank with
/// `inconclusive`.
pub(crate) fn fleet_verdict_rank(v: &str) -> u8 {
    match v {
        "all_correct" => 3,
        "inconclusive" => 2,
        "partial" => 1,
        "failed" | "run_failed" | "no_delivery" | "no_session" => 0,
        _ => 2,
    }
}

struct Flags<'t> {
    th: &'t Thresholds,
    out: Vec<Regression>,
}

impl Flags<'_> {
    fn push(
        &mut self,
        rtu: Option<&str>,
        metric: &'static str,
        a: Value,
        b: Value,
        threshold: Option<f64>,
        message: String,
    ) {
        self.out.push(Regression {
            scope: if rtu.is_some() { "rtu" } else { "fleet" },
            rtu: rtu.map(str::to_string),
            metric,
            a,
            b,
            threshold,
            message,
        });
    }

    /// Percentage-point drop (score, delivered %).
    fn drop_pp(
        &mut self,
        rtu: Option<&str>,
        metric: &'static str,
        a: Option<f64>,
        b: Option<f64>,
        th: f64,
    ) -> bool {
        let (Some(a), Some(b)) = (a, b) else {
            return false;
        };
        if a - b > th {
            let who = rtu.map(|r| format!("RTU {r}: ")).unwrap_or_default();
            self.push(
                rtu,
                metric,
                a.into(),
                b.into(),
                Some(th),
                format!("{who}{metric} fell from {a:.2} to {b:.2} (more than {th} points)"),
            );
            return true;
        }
        false
    }

    /// Relative latency increase above `pct` and above the noise floor.
    fn latency_up(
        &mut self,
        rtu: Option<&str>,
        metric: &'static str,
        a: Option<u64>,
        b: Option<u64>,
        pct: f64,
    ) -> bool {
        let (Some(a), Some(b)) = (a, b) else {
            return false;
        };
        if a == 0 && b == 0 {
            return false;
        }
        let inc = b as f64 - a as f64;
        if inc > self.th.latency_min_us && b as f64 > a as f64 * (1.0 + pct / 100.0) {
            let who = rtu.map(|r| format!("RTU {r}: ")).unwrap_or_default();
            self.push(
                rtu,
                metric,
                a.into(),
                b.into(),
                Some(pct),
                format!("{who}{metric} rose from {a} µs to {b} µs (more than {pct}%)"),
            );
            return true;
        }
        false
    }
}

/// Compare run `a` (the baseline) with run `b`.
pub(crate) fn compare(a: &Side<'_>, b: &Side<'_>, th: &Thresholds) -> Comparison {
    let ra = rtu_sides(a);
    let rb = rtu_sides(b);
    let fa = fleet_side(a, &ra);
    let fb = fleet_side(b, &rb);
    let mut flags = Flags {
        th,
        out: Vec::new(),
    };

    // Fleet.
    flags.drop_pp(None, "score", fa.score, fb.score, th.score_drop);
    flags.drop_pp(
        None,
        "delivered_pct",
        fa.delivered_pct,
        fb.delivered_pct,
        th.delivered_drop,
    );
    flags.latency_up(None, "p50_us", fa.p50_us, fb.p50_us, th.p50_increase_pct);
    flags.latency_up(None, "p99_us", fa.p99_us, fb.p99_us, th.p99_increase_pct);
    if let (Some(x), Some(y)) = (fa.throughput, fb.throughput) {
        if x > 0.0 && y < x * (1.0 - th.throughput_drop_pct / 100.0) {
            flags.push(
                None,
                "throughput",
                x.into(),
                y.into(),
                Some(th.throughput_drop_pct),
                format!(
                    "throughput fell from {x:.1} to {y:.1} msg/s (more than {}%)",
                    th.throughput_drop_pct
                ),
            );
        }
    }
    if let (Some(x), Some(y)) = (fa.sessions_failed, fb.sessions_failed) {
        if y > x {
            flags.push(
                None,
                "sessions_failed",
                x.into(),
                y.into(),
                None,
                format!("failed sessions rose from {x} to {y}"),
            );
        }
    }
    if let (Some(x), Some(y)) = (&fa.verdict, &fb.verdict) {
        if fleet_verdict_rank(y) < fleet_verdict_rank(x) {
            flags.push(
                None,
                "verdict",
                x.as_str().into(),
                y.as_str().into(),
                None,
                format!("fleet verdict went from {x} to {y}"),
            );
        }
    }

    // RTUs.
    let mut keys: Vec<String> = ra.keys().chain(rb.keys()).cloned().collect();
    keys.sort_by_key(|k| ip_key(k));
    keys.dedup();
    let mut rows = Vec::new();
    let mut only_in_a = Vec::new();
    let mut only_in_b = Vec::new();
    for k in keys {
        match (ra.get(&k), rb.get(&k)) {
            (Some(_), None) => {
                flags.push(
                    Some(&k),
                    "missing_in_b",
                    Value::Bool(true),
                    Value::Bool(false),
                    None,
                    format!("RTU {k} is in run a but not in run b"),
                );
                only_in_a.push(k);
            }
            (None, Some(_)) => only_in_b.push(k),
            (Some(x), Some(y)) => {
                let before = flags.out.len();
                flags.drop_pp(Some(&k), "score", x.score, y.score, th.score_drop);
                flags.drop_pp(
                    Some(&k),
                    "delivered_pct",
                    x.delivered_pct,
                    y.delivered_pct,
                    th.delivered_drop,
                );
                flags.latency_up(Some(&k), "p50_us", x.p50_us, y.p50_us, th.p50_increase_pct);
                flags.latency_up(Some(&k), "p99_us", x.p99_us, y.p99_us, th.p99_increase_pct);
                if y.errors > x.errors {
                    flags.push(
                        Some(&k),
                        "errors",
                        x.errors.into(),
                        y.errors.into(),
                        None,
                        format!(
                            "RTU {k}: failed sessions rose from {} to {}{}",
                            x.errors,
                            y.errors,
                            y.error
                                .as_deref()
                                .map(|e| format!(" ({e})"))
                                .unwrap_or_default()
                        ),
                    );
                }
                if let (Some(oa), Some(ob)) = (&x.outcome, &y.outcome) {
                    if outcome_rank(ob) < outcome_rank(oa) {
                        flags.push(
                            Some(&k),
                            "verdict",
                            x.verdict.clone().unwrap_or_default().into(),
                            y.verdict.clone().unwrap_or_default().into(),
                            None,
                            format!(
                                "RTU {k}: verdict went from {} to {}",
                                x.verdict.as_deref().unwrap_or(oa),
                                y.verdict.as_deref().unwrap_or(ob)
                            ),
                        );
                    }
                }
                let regressions = flags.out[before..].iter().map(|r| r.metric).collect();
                rows.push(RtuRow {
                    delta: RtuDelta {
                        score: df(x.score, y.score),
                        delivered: di(x.delivered, y.delivered),
                        delivered_pct: df(x.delivered_pct, y.delivered_pct),
                        p50_us: di(x.p50_us, y.p50_us),
                        p99_us: di(x.p99_us, y.p99_us),
                        msgs_sent: di(x.msgs_sent, y.msgs_sent),
                        errors: y.errors as i64 - x.errors as i64,
                    },
                    verdict_changed: x.verdict != y.verdict,
                    rtu: k,
                    a: x.clone(),
                    b: y.clone(),
                    regressions,
                });
            }
            (None, None) => {}
        }
    }

    let delta = FleetDelta {
        score: df(fa.score, fb.score),
        frame_weighted_score: df(fa.frame_weighted_score, fb.frame_weighted_score),
        delivered: fb.delivered as i64 - fa.delivered as i64,
        delivered_pct: df(fa.delivered_pct, fb.delivered_pct),
        sessions_failed: di(fa.sessions_failed, fb.sessions_failed),
        msgs_sent: di(fa.msgs_sent, fb.msgs_sent),
        msgs_received: di(fa.msgs_received, fb.msgs_received),
        p50_us: di(fa.p50_us, fb.p50_us),
        p90_us: di(fa.p90_us, fb.p90_us),
        p99_us: di(fa.p99_us, fb.p99_us),
        max_us: di(fa.max_us, fb.max_us),
        throughput: df(fa.throughput, fb.throughput),
    };
    let regressed = !flags.out.is_empty();
    Comparison {
        fleet: FleetCompare {
            verdict_changed: fa.verdict != fb.verdict,
            a: fa,
            b: fb,
            delta,
        },
        rtus: rows,
        only_in_a,
        only_in_b,
        regressions: flags.out,
        regressed,
        thresholds: *th,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::SessionReportJson;
    use serde_json::json;

    fn summary(score: f64, verdict: &str, slaves: Value) -> Value {
        json!({"verdict": verdict, "score_pct": score,
               "fleet": {"fully_correct": 1, "partial": 0, "failed": 0,
                         "never_connected": 0, "frame_weighted_score_pct": score},
               "slaves": slaves})
    }

    fn slave(ip: &str, score: f64, outcome: &str, exp: u64, del: u64) -> Value {
        json!({"slave_ip": ip, "score_pct": score, "verdict": outcome,
               "outcome": outcome, "expected_iframes": exp, "delivered_iframes": del})
    }

    fn bench(rows: &[(&str, u64, u64, Option<&str>)], p99: u64, tput: f64) -> BenchmarkReportJson {
        BenchmarkReportJson {
            per_session: rows
                .iter()
                .map(|(ip, sent, p99, err)| SessionReportJson {
                    src_ip: ip.to_string(),
                    messages_sent: *sent,
                    latency_p50_us: p99 / 2,
                    latency_p99_us: *p99,
                    error: err.map(str::to_string),
                    ..Default::default()
                })
                .collect(),
            total_messages_sent: rows.iter().map(|r| r.1).sum(),
            aggregate_latency_p99_us: p99,
            aggregate_throughput_msgs_per_sec: tput,
            ..Default::default()
        }
    }

    #[test]
    fn identical_runs_have_zero_deltas_and_no_regressions() {
        let s = summary(
            100.0,
            "all_correct",
            json!([slave("10.0.0.2", 100.0, "pass", 10, 10)]),
        );
        let b = bench(&[("10.0.0.2", 10, 2000, None)], 2000, 50.0);
        let side = Side {
            summary: &s,
            bench: Some(&b),
        };
        let c = compare(&side, &side, &Thresholds::default());
        assert!(!c.regressed, "{:?}", c.regressions);
        assert_eq!(c.rtus.len(), 1);
        assert_eq!(c.rtus[0].delta.score, Some(0.0));
        assert_eq!(c.rtus[0].delta.p99_us, Some(0));
        assert!(c.only_in_a.is_empty() && c.only_in_b.is_empty());
        assert_eq!(c.fleet.delta.delivered_pct, Some(0.0));
    }

    #[test]
    fn regressions_are_flagged_per_rtu_and_fleet() {
        let sa = summary(
            100.0,
            "all_correct",
            json!([
                slave("10.0.0.2", 100.0, "pass", 10, 10),
                slave("10.0.0.10", 100.0, "pass", 10, 10),
                slave("10.0.0.3", 100.0, "pass", 10, 10)
            ]),
        );
        let ba = bench(
            &[
                ("10.0.0.2", 10, 2000, None),
                ("10.0.0.10", 10, 2000, None),
                ("10.0.0.3", 10, 2000, None),
            ],
            2000,
            100.0,
        );
        let sb = summary(
            60.0,
            "partial",
            json!([
                slave("10.0.0.2", 50.0, "fail", 10, 5),
                slave("10.0.0.10", 100.0, "pass", 10, 10),
                slave("10.0.0.4", 100.0, "pass", 10, 10)
            ]),
        );
        let bb = bench(
            &[
                ("10.0.0.2", 5, 9000, Some("reset by peer")),
                ("10.0.0.10", 10, 2100, None),
                ("10.0.0.4", 10, 2000, None),
            ],
            9000,
            40.0,
        );
        let c = compare(
            &Side {
                summary: &sa,
                bench: Some(&ba),
            },
            &Side {
                summary: &sb,
                bench: Some(&bb),
            },
            &Thresholds::default(),
        );
        assert!(c.regressed);
        assert_eq!(c.only_in_a, ["10.0.0.3"]);
        assert_eq!(c.only_in_b, ["10.0.0.4"]);
        // Numeric IP order: .2 before .10.
        let order: Vec<&str> = c.rtus.iter().map(|r| r.rtu.as_str()).collect();
        assert_eq!(order, ["10.0.0.2", "10.0.0.10"]);
        let r2 = &c.rtus[0];
        assert_eq!(r2.delta.score, Some(-50.0));
        assert_eq!(r2.delta.delivered, Some(-5));
        assert_eq!(r2.delta.errors, 1);
        assert!(r2.verdict_changed);
        for m in [
            "score",
            "delivered_pct",
            "p50_us",
            "p99_us",
            "errors",
            "verdict",
        ] {
            assert!(r2.regressions.contains(&m), "{m}: {:?}", r2.regressions);
        }
        // +100 µs on .10 is under the noise floor.
        assert!(c.rtus[1].regressions.is_empty());
        let fleet: Vec<&str> = c
            .regressions
            .iter()
            .filter(|r| r.scope == "fleet")
            .map(|r| r.metric)
            .collect();
        for m in [
            "score",
            "p99_us",
            "throughput",
            "sessions_failed",
            "verdict",
        ] {
            assert!(fleet.contains(&m), "{m}: {fleet:?}");
        }
        assert!(c
            .regressions
            .iter()
            .any(|r| r.metric == "missing_in_b" && r.rtu.as_deref() == Some("10.0.0.3")));
    }

    #[test]
    fn thresholds_are_configurable() {
        let sa = summary(
            100.0,
            "all_correct",
            json!([slave("10.0.0.2", 100.0, "pass", 100, 100)]),
        );
        let sb = summary(
            98.0,
            "all_correct",
            json!([slave("10.0.0.2", 98.0, "pass", 100, 98)]),
        );
        let a = Side {
            summary: &sa,
            bench: None,
        };
        let b = Side {
            summary: &sb,
            bench: None,
        };
        assert!(compare(&a, &b, &Thresholds::default()).regressed);
        let loose = Thresholds {
            score_drop: 5.0,
            delivered_drop: 5.0,
            ..Default::default()
        };
        let c = compare(&a, &b, &loose);
        assert!(!c.regressed, "{:?}", c.regressions);
        assert_eq!(c.rtus[0].a.p99_us, None, "no benchmark report, no latency");
        assert!(Thresholds {
            score_drop: -1.0,
            ..Default::default()
        }
        .validate()
        .is_err());
    }
}
