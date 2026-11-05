//! Fault injection (`proto_config.faults`): a per-session plan of
//! deliberate protocol misbehaviour, used to test how the peer (a real
//! master or RTU) reacts.
//!
//! ```json
//! {
//!   "fault_seed": 42,
//!   "faults": [
//!     { "at": {"ms": 5000},  "kind": "withhold_acks",     "duration_ms": 20000 },
//!     { "at": {"frame": 120}, "kind": "drop_iframes",     "pct": 10, "duration_ms": 2000 },
//!     { "at": {"ms": 9000},  "kind": "duplicate_iframes", "pct": 50, "duration_ms": 1000 },
//!     { "at": {"frame": 10}, "kind": "corrupt_ns",        "count": 1 },
//!     { "at": {"ms": 0},     "kind": "testfr_silence",    "duration_ms": 60000 },
//!     { "at": {"ms": 1000},  "kind": "delay",             "ms": 300, "duration_ms": 5000 },
//!     { "at": {"ms": 30000}, "kind": "rst" },
//!     { "at": {"frame": 50}, "kind": "stopdt" },
//!     { "at": {"ms": 2000},  "kind": "malformed_apdu",    "count": 1 },
//!     { "at": {"ms": 0},     "kind": "slow_ack",          "extra_ms": 500, "duration_ms": 10000 }
//!   ]
//! }
//! ```
//!
//! `at.ms` counts from the moment the TCP connection is established;
//! `at.frame` fires just before the link sends its N-th I-frame
//! (0-based, every I-frame counted: replayed, synthesized and dropped
//! ones). Parsing is strict: unknown kinds, unknown or missing keys and
//! out-of-range values are errors. `fault_seed` (default
//! [`DEFAULT_FAULT_SEED`]) seeds the generator behind the percentage
//! faults, so a plan is reproducible frame for frame.
//!
//! What each kind does (both roles unless noted):
//!
//! * `withhold_acks {duration_ms}`: no S-frames, and our I-frames
//!   repeat the last N(R) already sent, so the peer's t1 runs out.
//! * `drop_iframes {pct, duration_ms}`: each outgoing I-frame is
//!   dropped with probability `pct`; its N(S) is consumed, so the next
//!   frame is out of sequence at the peer.
//! * `duplicate_iframes {pct, duration_ms}`: each outgoing I-frame is
//!   sent twice with the same N(S) with probability `pct`.
//! * `corrupt_ns {count}`: the next `count` I-frames carry a wrong
//!   N(S) (V(S) + 16384); V(S) itself advances normally.
//! * `testfr_silence {duration_ms}`: TESTFR act is neither answered
//!   nor sent (t3).
//! * `delay {ms, duration_ms}`: every outgoing I-frame is held `ms`
//!   longer than it would have been.
//! * `rst {}`: abortive close (SO_LINGER 0, RST); the session ends.
//! * `stopdt {}`: master: STOPDT act, and STARTDT act once confirmed;
//!   slave: an unsolicited STOPDT act (a controlled station must not
//!   send one) to see how the master copes.
//! * `malformed_apdu {count}`: `count` APDUs with an invalid length
//!   octet (2).
//! * `slow_ack {extra_ms[, duration_ms]}`: every acknowledgement
//!   (S-frame, and the N(R) in our I-frames) goes out `extra_ms` late;
//!   without `duration_ms` until the session ends.
//!
//! The runtime half ([`FaultInjector`]) lives inside the link engine's
//! service loop, so it is serviced, timed and cancelled like everything
//! else there.

use anyhow::{anyhow, bail, Result};
use protoplay::{FaultRecord, FAULT_RECORDS_CAP};
use serde_json::{Map, Value};

pub const FAULTS_KEY: &str = "faults";
pub const FAULT_SEED_KEY: &str = "fault_seed";
/// Seed used when `fault_seed` is absent.
pub const DEFAULT_FAULT_SEED: u64 = 0x1EC1_0400;
/// Most faults in one plan.
pub const MAX_FAULTS: usize = 256;
const MAX_DURATION_MS: u64 = 86_400_000;
const MAX_DELAY_MS: u64 = 600_000;
const MAX_COUNT: u64 = 1_000;
/// Offset added to V(S) by `corrupt_ns`.
pub const CORRUPT_NS_OFFSET: u16 = 0x4000;
/// Sequence numbers listed per fault record.
const NS_LIST_CAP: usize = 16;

/// When a fault fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// Milliseconds after the connection was established.
    Ms(u64),
    /// Just before the N-th I-frame (0-based) is sent.
    Frame(u64),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FaultKind {
    WithholdAcks {
        duration_ms: u64,
    },
    DropIframes {
        pct: f64,
        duration_ms: u64,
    },
    DuplicateIframes {
        pct: f64,
        duration_ms: u64,
    },
    CorruptNs {
        count: u64,
    },
    TestfrSilence {
        duration_ms: u64,
    },
    Delay {
        ms: u64,
        duration_ms: u64,
    },
    Rst,
    Stopdt,
    MalformedApdu {
        count: u64,
    },
    SlowAck {
        extra_ms: u64,
        duration_ms: Option<u64>,
    },
}

/// Every kind name, as configured.
pub const FAULT_KINDS: &[&str] = &[
    "withhold_acks",
    "drop_iframes",
    "duplicate_iframes",
    "corrupt_ns",
    "testfr_silence",
    "delay",
    "rst",
    "stopdt",
    "malformed_apdu",
    "slow_ack",
];

impl FaultKind {
    pub fn name(&self) -> &'static str {
        match self {
            FaultKind::WithholdAcks { .. } => "withhold_acks",
            FaultKind::DropIframes { .. } => "drop_iframes",
            FaultKind::DuplicateIframes { .. } => "duplicate_iframes",
            FaultKind::CorruptNs { .. } => "corrupt_ns",
            FaultKind::TestfrSilence { .. } => "testfr_silence",
            FaultKind::Delay { .. } => "delay",
            FaultKind::Rst => "rst",
            FaultKind::Stopdt => "stopdt",
            FaultKind::MalformedApdu { .. } => "malformed_apdu",
            FaultKind::SlowAck { .. } => "slow_ack",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fault {
    pub at: Trigger,
    pub kind: FaultKind,
}

/// A validated fault plan.
#[derive(Debug, Clone, PartialEq)]
pub struct FaultPlan {
    pub faults: Vec<Fault>,
    pub seed: u64,
}

impl Default for FaultPlan {
    fn default() -> Self {
        Self {
            faults: Vec::new(),
            seed: DEFAULT_FAULT_SEED,
        }
    }
}

fn uint(obj: &Map<String, Value>, key: &str, ctx: &str, min: u64, max: u64) -> Result<u64> {
    let v = obj
        .get(key)
        .ok_or_else(|| anyhow!("{ctx}: missing \"{key}\""))?;
    let n = v
        .as_u64()
        .ok_or_else(|| anyhow!("{ctx}: \"{key}\" must be a non-negative integer, got {v}"))?;
    if !(min..=max).contains(&n) {
        bail!("{ctx}: \"{key}\" must be {min}..={max}, got {n}");
    }
    Ok(n)
}

fn pct(obj: &Map<String, Value>, ctx: &str) -> Result<f64> {
    let v = obj
        .get("pct")
        .ok_or_else(|| anyhow!("{ctx}: missing \"pct\""))?;
    let p = v
        .as_f64()
        .ok_or_else(|| anyhow!("{ctx}: \"pct\" must be a number, got {v}"))?;
    if !(p > 0.0 && p <= 100.0) {
        bail!("{ctx}: \"pct\" must be > 0 and <= 100, got {p}");
    }
    Ok(p)
}

fn parse_trigger(v: Option<&Value>, ctx: &str) -> Result<Trigger> {
    let at = v
        .ok_or_else(|| anyhow!("{ctx}: missing \"at\""))?
        .as_object()
        .ok_or_else(|| anyhow!("{ctx}: \"at\" must be {{\"ms\": N}} or {{\"frame\": N}}"))?;
    let c = format!("{ctx}.at");
    match (at.len(), at.contains_key("ms"), at.contains_key("frame")) {
        (1, true, _) => Ok(Trigger::Ms(uint(at, "ms", &c, 0, MAX_DURATION_MS)?)),
        (1, _, true) => Ok(Trigger::Frame(uint(at, "frame", &c, 0, u64::MAX)?)),
        _ => bail!("{c} must have exactly one key, \"ms\" or \"frame\""),
    }
}

fn parse_fault(i: usize, v: &Value) -> Result<Fault> {
    let ctx = format!("faults[{i}]");
    let obj = v
        .as_object()
        .ok_or_else(|| anyhow!("{ctx} must be an object"))?;
    let kind = obj
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{ctx}: missing string \"kind\""))?;
    let ctx = format!("{ctx} ({kind})");
    let params: &[&str] = match kind {
        "withhold_acks" | "testfr_silence" => &["duration_ms"],
        "drop_iframes" | "duplicate_iframes" => &["pct", "duration_ms"],
        "corrupt_ns" | "malformed_apdu" => &["count"],
        "delay" => &["ms", "duration_ms"],
        "rst" | "stopdt" => &[],
        "slow_ack" => &["extra_ms", "duration_ms"],
        _ => bail!(
            "{ctx}: unknown fault kind (expected one of {})",
            FAULT_KINDS.join(", ")
        ),
    };
    for k in obj.keys() {
        if k != "at" && k != "kind" && !params.contains(&k.as_str()) {
            bail!("{ctx}: unknown key \"{k}\"");
        }
    }
    let dur = |o| uint(o, "duration_ms", &ctx, 1, MAX_DURATION_MS);
    let kind = match kind {
        "withhold_acks" => FaultKind::WithholdAcks {
            duration_ms: dur(obj)?,
        },
        "drop_iframes" => FaultKind::DropIframes {
            pct: pct(obj, &ctx)?,
            duration_ms: dur(obj)?,
        },
        "duplicate_iframes" => FaultKind::DuplicateIframes {
            pct: pct(obj, &ctx)?,
            duration_ms: dur(obj)?,
        },
        "corrupt_ns" => FaultKind::CorruptNs {
            count: uint(obj, "count", &ctx, 1, MAX_COUNT)?,
        },
        "testfr_silence" => FaultKind::TestfrSilence {
            duration_ms: dur(obj)?,
        },
        "delay" => FaultKind::Delay {
            ms: uint(obj, "ms", &ctx, 1, MAX_DELAY_MS)?,
            duration_ms: dur(obj)?,
        },
        "rst" => FaultKind::Rst,
        "stopdt" => FaultKind::Stopdt,
        "malformed_apdu" => FaultKind::MalformedApdu {
            count: uint(obj, "count", &ctx, 1, MAX_COUNT)?,
        },
        _ => FaultKind::SlowAck {
            extra_ms: uint(obj, "extra_ms", &ctx, 1, MAX_DELAY_MS)?,
            duration_ms: obj
                .contains_key("duration_ms")
                .then(|| dur(obj))
                .transpose()?,
        },
    };
    Ok(Fault {
        at: parse_trigger(obj.get("at"), &ctx)?,
        kind,
    })
}

impl FaultPlan {
    pub fn is_empty(&self) -> bool {
        self.faults.is_empty()
    }

    /// Validate the `faults` / `fault_seed` values of a parsed
    /// `proto_config`.
    pub fn from_values(faults: Option<&Value>, seed: Option<&Value>) -> Result<Self> {
        let seed = match seed {
            None | Some(Value::Null) => DEFAULT_FAULT_SEED,
            Some(v) => v
                .as_u64()
                .ok_or_else(|| anyhow!("fault_seed must be a non-negative integer, got {v}"))?,
        };
        let faults = match faults {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) => {
                if a.len() > MAX_FAULTS {
                    bail!("faults: at most {MAX_FAULTS} entries, got {}", a.len());
                }
                a.iter()
                    .enumerate()
                    .map(|(i, v)| parse_fault(i, v))
                    .collect::<Result<Vec<_>>>()?
            }
            Some(v) => bail!("faults must be an array, got {v}"),
        };
        Ok(Self { faults, seed })
    }

    /// Plan from a whole `proto_config` string. An absent or empty
    /// config is an empty plan.
    pub fn parse(proto_config: Option<&str>) -> Result<Self> {
        let Some(s) = proto_config.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(Self::default());
        };
        let v: Value = serde_json::from_str(s).map_err(|e| anyhow!("proto_config: {e}"))?;
        Self::from_values(v.get(FAULTS_KEY), v.get(FAULT_SEED_KEY))
    }

    /// Does the plan contain a fault of this kind name?
    pub fn has(&self, name: &str) -> bool {
        self.faults.iter().any(|f| f.kind.name() == name)
    }
}

// ---------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------

/// SplitMix64: tiny, seedable, good enough for fault dice.
#[derive(Debug, Clone)]
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in [0, 100).
    fn pct(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64 * 100.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum WindowKind {
    Withhold,
    Drop(f64),
    Duplicate(f64),
    TestfrSilence,
    Delay(u64),
    SlowAck(u64),
}

#[derive(Debug, Clone, Copy)]
struct Window {
    kind: WindowKind,
    until_ns: u64,
    rec: usize,
}

/// One-shot action the link performs when a fault fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Rst,
    Stopdt,
    Malformed(u64),
}

pub(crate) struct FaultInjector {
    plan: Vec<Fault>,
    fired: Vec<bool>,
    rng: Rng,
    epoch_ns: u64,
    windows: Vec<Window>,
    corrupt_left: u64,
    corrupt_rec: usize,
    records: Vec<FaultRecord>,
    seqs: Vec<Vec<u16>>,
    first_fire_ns: Option<u64>,
}

impl FaultInjector {
    /// `None` for an empty plan.
    pub fn new(plan: &FaultPlan, epoch_ns: u64) -> Option<Self> {
        if plan.is_empty() {
            return None;
        }
        Some(Self {
            plan: plan.faults.clone(),
            fired: vec![false; plan.faults.len()],
            rng: Rng(plan.seed),
            epoch_ns,
            windows: Vec::new(),
            corrupt_left: 0,
            corrupt_rec: 0,
            records: Vec::new(),
            seqs: Vec::new(),
            first_fire_ns: None,
        })
    }

    pub fn first_fire_ns(&self) -> Option<u64> {
        self.first_fire_ns
    }

    pub fn fired_count(&self) -> usize {
        self.records.len()
    }

    fn record(&mut self, now: u64, kind: &str, detail: String) -> usize {
        self.first_fire_ns.get_or_insert(now);
        self.records.push(FaultRecord {
            at_ms: now.saturating_sub(self.epoch_ns) / 1_000_000,
            kind: kind.into(),
            detail,
            frames_affected: 0,
        });
        self.seqs.push(Vec::new());
        self.records.len() - 1
    }

    /// Fire every fault whose trigger is met (`frames` = I-frames
    /// attempted so far). Window faults become active; one-shot faults
    /// are returned for the link to carry out, with their record index.
    pub fn poll(&mut self, now: u64, frames: u64, master: bool) -> Vec<(Action, usize)> {
        let mut out = Vec::new();
        let rel_ms = now.saturating_sub(self.epoch_ns) / 1_000_000;
        for i in 0..self.plan.len() {
            if self.fired[i] {
                continue;
            }
            let f = self.plan[i];
            let due = match f.at {
                Trigger::Ms(ms) => rel_ms >= ms,
                Trigger::Frame(n) => frames >= n,
            };
            if !due {
                continue;
            }
            self.fired[i] = true;
            let until = |d: u64| now.saturating_add(d.saturating_mul(1_000_000));
            let (window, detail) = match f.kind {
                FaultKind::WithholdAcks { duration_ms } => (
                    Some((WindowKind::Withhold, until(duration_ms))),
                    format!("acknowledgements withheld for {duration_ms} ms"),
                ),
                FaultKind::DropIframes { pct, duration_ms } => (
                    Some((WindowKind::Drop(pct), until(duration_ms))),
                    format!(
                        "dropping {pct}% of outgoing I-frames for {duration_ms} ms (N(S) consumed)"
                    ),
                ),
                FaultKind::DuplicateIframes { pct, duration_ms } => (
                    Some((WindowKind::Duplicate(pct), until(duration_ms))),
                    format!("duplicating {pct}% of outgoing I-frames for {duration_ms} ms"),
                ),
                FaultKind::CorruptNs { count } => (
                    None,
                    format!("next {count} I-frame(s) sent with N(S) = V(S) + {CORRUPT_NS_OFFSET}"),
                ),
                FaultKind::TestfrSilence { duration_ms } => (
                    Some((WindowKind::TestfrSilence, until(duration_ms))),
                    format!("TESTFR neither answered nor sent for {duration_ms} ms"),
                ),
                FaultKind::Delay { ms, duration_ms } => (
                    Some((WindowKind::Delay(ms * 1_000_000), until(duration_ms))),
                    format!("outgoing I-frames held {ms} ms for {duration_ms} ms"),
                ),
                FaultKind::Rst => (None, "connection aborted with RST (SO_LINGER 0)".into()),
                FaultKind::Stopdt => (
                    None,
                    if master {
                        "STOPDT act sent; STARTDT act follows the con".into()
                    } else {
                        "unsolicited STOPDT act sent by the controlled station".into()
                    },
                ),
                FaultKind::MalformedApdu { count } => (
                    None,
                    format!("{count} APDU(s) with an invalid length octet sent"),
                ),
                FaultKind::SlowAck {
                    extra_ms,
                    duration_ms,
                } => (
                    Some((
                        WindowKind::SlowAck(extra_ms * 1_000_000),
                        duration_ms.map_or(u64::MAX, until),
                    )),
                    match duration_ms {
                        Some(d) => format!("acknowledgements delayed {extra_ms} ms for {d} ms"),
                        None => format!("acknowledgements delayed {extra_ms} ms"),
                    },
                ),
            };
            let rec = self.record(now, f.kind.name(), detail);
            if let Some((kind, until_ns)) = window {
                self.windows.push(Window {
                    kind,
                    until_ns,
                    rec,
                });
            }
            match f.kind {
                FaultKind::CorruptNs { count } => {
                    self.corrupt_left += count;
                    self.corrupt_rec = rec;
                }
                FaultKind::Rst => out.push((Action::Rst, rec)),
                FaultKind::Stopdt => out.push((Action::Stopdt, rec)),
                FaultKind::MalformedApdu { count } => out.push((Action::Malformed(count), rec)),
                _ => {}
            }
        }
        out
    }

    fn active(&self, now: u64, pred: impl Fn(WindowKind) -> bool) -> Option<Window> {
        self.windows
            .iter()
            .find(|w| now < w.until_ns && pred(w.kind))
            .copied()
    }

    /// Count one affected frame on record `rec`, optionally with its
    /// sequence number.
    pub fn note(&mut self, rec: usize, seq: Option<u16>) {
        if let Some(r) = self.records.get_mut(rec) {
            r.frames_affected += 1;
        }
        if let (Some(s), Some(list)) = (seq, self.seqs.get_mut(rec)) {
            if list.len() < NS_LIST_CAP {
                list.push(s);
            }
        }
    }

    /// Record index of an active `withhold_acks` window.
    pub fn withholding(&self, now: u64) -> Option<usize> {
        self.active(now, |k| k == WindowKind::Withhold)
            .map(|w| w.rec)
    }

    /// Extra ack delay (ns) and record of an active `slow_ack` window.
    pub fn slow_ack(&self, now: u64) -> Option<(u64, usize)> {
        self.active(now, |k| matches!(k, WindowKind::SlowAck(_)))
            .map(|w| match w.kind {
                WindowKind::SlowAck(d) => (d, w.rec),
                _ => unreachable!(),
            })
    }

    pub fn testfr_silenced(&self, now: u64) -> Option<usize> {
        self.active(now, |k| k == WindowKind::TestfrSilence)
            .map(|w| w.rec)
    }

    /// Hold time (ns) and record of an active `delay` window.
    pub fn delay(&self, now: u64) -> Option<(u64, usize)> {
        self.active(now, |k| matches!(k, WindowKind::Delay(_)))
            .map(|w| match w.kind {
                WindowKind::Delay(d) => (d, w.rec),
                _ => unreachable!(),
            })
    }

    /// Roll the drop dice for the I-frame with N(S) `ns`.
    pub fn roll_drop(&mut self, now: u64, ns: u16) -> bool {
        let Some(w) = self.active(now, |k| matches!(k, WindowKind::Drop(_))) else {
            return false;
        };
        let WindowKind::Drop(p) = w.kind else {
            return false;
        };
        let hit = self.rng.pct() < p;
        if hit {
            self.note(w.rec, Some(ns));
        }
        hit
    }

    /// Roll the duplicate dice for the I-frame with N(S) `ns`.
    pub fn roll_duplicate(&mut self, now: u64, ns: u16) -> bool {
        let Some(w) = self.active(now, |k| matches!(k, WindowKind::Duplicate(_))) else {
            return false;
        };
        let WindowKind::Duplicate(p) = w.kind else {
            return false;
        };
        let hit = self.rng.pct() < p;
        if hit {
            self.note(w.rec, Some(ns));
        }
        hit
    }

    /// Should the I-frame with N(S) `ns` go out with a corrupted N(S)?
    pub fn take_corrupt(&mut self, ns: u16) -> bool {
        if self.corrupt_left == 0 {
            return false;
        }
        self.corrupt_left -= 1;
        self.note(self.corrupt_rec, Some(ns));
        true
    }

    /// Next time something changes on its own: an unfired `ms` trigger
    /// or the end of an active window.
    pub fn next_deadline_ns(&self, now: u64) -> Option<u64> {
        let triggers = self
            .plan
            .iter()
            .zip(&self.fired)
            .filter(|(_, &fired)| !fired)
            .filter_map(|(f, _)| match f.at {
                Trigger::Ms(ms) => Some(self.epoch_ns + ms * 1_000_000),
                Trigger::Frame(_) => None,
            });
        let ends = self
            .windows
            .iter()
            .map(|w| w.until_ns)
            .filter(|&t| t > now && t != u64::MAX);
        triggers.chain(ends).min()
    }

    /// The records, with the affected sequence numbers appended to
    /// each detail.
    pub fn into_records(self) -> Vec<FaultRecord> {
        self.records
            .into_iter()
            .zip(self.seqs)
            .take(FAULT_RECORDS_CAP)
            .map(|(mut r, seqs)| {
                if !seqs.is_empty() {
                    let list: Vec<String> = seqs.iter().map(u16::to_string).collect();
                    let more = r.frames_affected.saturating_sub(seqs.len() as u64);
                    r.detail.push_str(&format!("; N(S) {}", list.join(", ")));
                    if more > 0 {
                        r.detail.push_str(&format!(" (+{more} more)"));
                    }
                }
                r
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(json: &str) -> Result<FaultPlan> {
        FaultPlan::parse(Some(json))
    }

    #[test]
    fn parses_every_kind() {
        let p = plan(
            r#"{"fault_seed":7,"faults":[
            {"at":{"ms":5000},"kind":"withhold_acks","duration_ms":100},
            {"at":{"frame":120},"kind":"drop_iframes","pct":10,"duration_ms":2000},
            {"at":{"ms":1},"kind":"duplicate_iframes","pct":50.5,"duration_ms":1},
            {"at":{"frame":0},"kind":"corrupt_ns","count":2},
            {"at":{"ms":0},"kind":"testfr_silence","duration_ms":60000},
            {"at":{"ms":0},"kind":"delay","ms":300,"duration_ms":5000},
            {"at":{"ms":30000},"kind":"rst"},
            {"at":{"frame":50},"kind":"stopdt"},
            {"at":{"ms":2},"kind":"malformed_apdu","count":1},
            {"at":{"ms":0},"kind":"slow_ack","extra_ms":500},
            {"at":{"ms":0},"kind":"slow_ack","extra_ms":5,"duration_ms":9}
        ]}"#,
        )
        .unwrap();
        assert_eq!(p.seed, 7);
        assert_eq!(p.faults.len(), 11);
        assert_eq!(p.faults[1].at, Trigger::Frame(120));
        assert_eq!(
            p.faults[1].kind,
            FaultKind::DropIframes {
                pct: 10.0,
                duration_ms: 2000
            }
        );
        assert_eq!(
            p.faults[9].kind,
            FaultKind::SlowAck {
                extra_ms: 500,
                duration_ms: None
            }
        );
        let names: Vec<&str> = p.faults.iter().map(|f| f.kind.name()).collect();
        for k in FAULT_KINDS {
            assert!(names.contains(k), "{k}");
        }
        assert_eq!(plan("{}").unwrap(), FaultPlan::default());
        assert!(FaultPlan::parse(None).unwrap().is_empty());
    }

    #[test]
    fn rejects_bad_plans() {
        for bad in [
            r#"{"faults":{}}"#,
            r#"{"faults":[5]}"#,
            r#"{"faults":[{"at":{"ms":1},"kind":"explode"}]}"#,
            r#"{"faults":[{"at":{"ms":1}}]}"#,
            r#"{"faults":[{"kind":"rst"}]}"#,
            r#"{"faults":[{"at":{"ms":1,"frame":2},"kind":"rst"}]}"#,
            r#"{"faults":[{"at":{"sec":1},"kind":"rst"}]}"#,
            r#"{"faults":[{"at":{"ms":-1},"kind":"rst"}]}"#,
            r#"{"faults":[{"at":{"ms":1},"kind":"rst","count":1}]}"#,
            r#"{"faults":[{"at":{"ms":1},"kind":"drop_iframes","duration_ms":10}]}"#,
            r#"{"faults":[{"at":{"ms":1},"kind":"drop_iframes","pct":0,"duration_ms":10}]}"#,
            r#"{"faults":[{"at":{"ms":1},"kind":"drop_iframes","pct":101,"duration_ms":10}]}"#,
            r#"{"faults":[{"at":{"ms":1},"kind":"drop_iframes","pct":"5","duration_ms":10}]}"#,
            r#"{"faults":[{"at":{"ms":1},"kind":"withhold_acks","duration_ms":0}]}"#,
            r#"{"faults":[{"at":{"ms":1},"kind":"corrupt_ns","count":0}]}"#,
            r#"{"faults":[{"at":{"ms":1},"kind":"delay","ms":1}]}"#,
            r#"{"faults":[{"at":{"ms":1},"kind":"slow_ack"}]}"#,
            r#"{"faults":[{"at":{"ms":1},"kind":"slow_ack","extra_ms":1,"durationms":1}]}"#,
            r#"{"faults":[],"fault_seed":-3}"#,
            r#"{"faults":[],"fault_seed":"x"}"#,
        ] {
            assert!(plan(bad).is_err(), "{bad}");
        }
    }

    fn injector(json: &str) -> FaultInjector {
        FaultInjector::new(&plan(json).unwrap(), 1_000_000_000).unwrap()
    }

    #[test]
    fn triggers_windows_and_records() {
        let mut f = injector(
            r#"{"faults":[
            {"at":{"ms":100},"kind":"withhold_acks","duration_ms":50},
            {"at":{"frame":3},"kind":"corrupt_ns","count":1},
            {"at":{"ms":0},"kind":"rst"}
        ]}"#,
        );
        let t0 = 1_000_000_000;
        let acts = f.poll(t0, 0, true);
        assert_eq!(acts, vec![(Action::Rst, 0)]);
        assert_eq!(f.first_fire_ns(), Some(t0));
        assert_eq!(f.next_deadline_ns(t0), Some(t0 + 100_000_000));
        assert!(f.withholding(t0 + 120_000_000).is_none(), "not fired yet");
        assert!(f.poll(t0 + 100_000_000, 2, true).is_empty());
        assert_eq!(f.withholding(t0 + 120_000_000), Some(1));
        assert!(f.withholding(t0 + 150_000_000).is_none(), "window over");
        assert_eq!(f.next_deadline_ns(t0 + 120_000_000), Some(t0 + 150_000_000));
        assert!(!f.take_corrupt(2));
        f.poll(t0 + 130_000_000, 3, true);
        assert!(f.take_corrupt(3));
        assert!(!f.take_corrupt(4));
        let recs = f.into_records();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[1].at_ms, 100);
        assert_eq!(recs[2].kind, "corrupt_ns");
        assert_eq!(recs[2].frames_affected, 1);
        assert!(recs[2].detail.ends_with("; N(S) 3"), "{}", recs[2].detail);
    }

    #[test]
    fn dice_are_seeded_and_roughly_fair() {
        let json = r#"{"fault_seed":99,"faults":[{"at":{"ms":0},"kind":"drop_iframes","pct":25,"duration_ms":1000}]}"#;
        let run = || {
            let mut f = injector(json);
            f.poll(1_000_000_000, 0, false);
            (0..2000u16)
                .map(|i| f.roll_drop(1_000_000_001, i))
                .collect::<Vec<bool>>()
        };
        let a = run();
        assert_eq!(a, run(), "same seed, same drops");
        let hits = a.iter().filter(|&&h| h).count();
        assert!((400..600).contains(&hits), "{hits}");
    }
}
