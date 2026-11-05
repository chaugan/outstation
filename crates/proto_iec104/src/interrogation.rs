//! Captured GI/CI interrogation exchanges: one shared rule for the
//! slave replayer and the post-run analyzer.
//!
//! When the slave synthesizes GI/CI responses for a live master
//! (`responder`), replaying the *captured* interrogation exchanges as
//! well would send unsolicited ActCon/ActTerm and stale Inrogen /
//! Reqcogen data. The replayer therefore strips them from its script
//! (F018), and the analyzer removes the same frames from its expected
//! side, so both must use exactly the rule below.
//!
//! A frame belongs to a captured interrogation exchange when it is
//!
//! * a `C_IC_NA_1` / `C_CI_NA_1` (type 100 / 101) confirmation,
//!   termination or negative reply: COT 7 (ActCon, positive or
//!   negative), 10 (ActTerm), or 44..=47 (unknown type / COT / CA /
//!   IOA); or
//! * any ASDU with COT 20..=41 (Inrogen station/group 1..16 and
//!   Reqcogen general/group 1..4), which by definition is only ever
//!   sent in answer to an interrogation.
//!
//! The rule is per frame, so it also catches the tail of an exchange
//! whose ActCon fell before the start of a mid-flow capture.

use std::ops::Range;

use crate::asdu::{cot_value, DUI_LEN};

/// `proto_config` key that turns GI/CI response synthesis off
/// (`{"gi_ci_synthesis": false}`). Absent = on.
pub const SYNTHESIS_KEY: &str = "gi_ci_synthesis";

/// Whether the slave synthesizes GI/CI responses for this run, from
/// the IEC 104 `proto_config`. Default on; only an explicit
/// `"gi_ci_synthesis": false` turns it off. Malformed JSON counts as
/// the default (the run itself validates the config).
pub fn synthesis_enabled(proto_config: Option<&str>) -> bool {
    let Some(s) = proto_config.map(str::trim).filter(|s| !s.is_empty()) else {
        return true;
    };
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(v) => v
            .get(SYNTHESIS_KEY)
            .and_then(|x| x.as_bool())
            .unwrap_or(true),
        Err(_) => true,
    }
}

/// Is this ASDU part of a captured interrogation exchange? See the
/// module docs for the rule.
pub fn is_captured_interrogation_frame(asdu: &[u8]) -> bool {
    if asdu.len() < DUI_LEN {
        return false;
    }
    let cot = cot_value(asdu);
    if matches!(asdu[0], 100 | 101) && matches!(cot, 7 | 10 | 44..=47) {
        return true;
    }
    (20..=41).contains(&cot)
}

/// Index ranges (into `asdus`) of the captured interrogation exchanges,
/// merged into maximal runs of consecutive frames.
pub fn captured_interrogation_bursts<A: AsRef<[u8]>>(asdus: &[A]) -> Vec<Range<usize>> {
    let mut out: Vec<Range<usize>> = Vec::new();
    for (i, a) in asdus.iter().enumerate() {
        if !is_captured_interrogation_frame(a.as_ref()) {
            continue;
        }
        match out.last_mut() {
            Some(r) if r.end == i => r.end = i + 1,
            _ => out.push(i..i + 1),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(type_id: u8, cot: u8) -> Vec<u8> {
        vec![type_id, 1, cot, 0, 1, 0, 0, 0, 0, 20]
    }

    #[test]
    fn bursts_cover_actcon_data_and_actterm() {
        let s = vec![
            a(13, 3),
            a(100, 7),
            a(1, 20),
            a(13, 20),
            a(100, 10),
            a(13, 3),
            a(15, 37),
            a(101, 10),
            a(100, 46),
            a(13, 1),
        ];
        assert_eq!(captured_interrogation_bursts(&s), vec![1..5, 6..9]);
    }

    #[test]
    fn commands_and_spontaneous_frames_are_kept() {
        assert!(!is_captured_interrogation_frame(&a(100, 6)));
        assert!(!is_captured_interrogation_frame(&a(13, 3)));
        assert!(!is_captured_interrogation_frame(&a(45, 7)));
        assert!(is_captured_interrogation_frame(&a(100, 7 | 0x40)));
        assert!(!is_captured_interrogation_frame(&[100, 1]));
    }

    #[test]
    fn synthesis_flag() {
        assert!(synthesis_enabled(None));
        assert!(synthesis_enabled(Some("")));
        assert!(synthesis_enabled(Some(r#"{"cp56":{}}"#)));
        assert!(synthesis_enabled(Some(r#"{"gi_ci_synthesis":true}"#)));
        assert!(!synthesis_enabled(Some(r#"{"gi_ci_synthesis":false}"#)));
        assert!(synthesis_enabled(Some("not json")));
    }
}
