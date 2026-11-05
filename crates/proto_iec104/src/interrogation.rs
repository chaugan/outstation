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
//!
//! # Every stripped capture frame
//!
//! [`CaptureStrip`] is the one definition of *all* captured frames the
//! slave leaves out of its script because it answers the live master
//! itself; the replayer (`session`) and the analyzer both classify
//! through it, so `stripped_capture_frames` and the analyzer's
//! expected side always agree:
//!
//! * captured interrogation exchanges (above), with GI/CI synthesis on;
//! * captured command confirmations
//!   ([`crate::commands::is_captured_command_frame`]), with command
//!   echo on;
//! * captured return information caused by a **remote** command
//!   (monitor-direction data with COT 11,
//!   [`is_captured_remote_return_info`]), with command echo on *and*
//!   `commands.return_info` other than `"none"`. The slave then sends
//!   its own return information for each live command it executes, so
//!   replaying the capture's COT 11 frames as well would report remote
//!   commands the live master never sent, next to the live ones.
//!
//! Return information caused by a **local** command (COT 12) is kept:
//! it reports an operator action at the RTU itself (a local switch, a
//! bay controller), not an answer to the controlling station, so it is
//! ordinary process data that the live master has no part in and the
//! command echo never synthesizes.

use std::ops::Range;

use crate::asdu::{cot_value, DUI_LEN};
use crate::commands::{self, CommandsConfig, ReturnInfo, COT_RETREM};

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

/// Is this ASDU captured return information caused by a remote command:
/// monitor-direction data (type < 45) with COT 11? Stripped from the
/// script when the slave synthesizes its own return information (see
/// the module docs). COT 12 (local command) is not.
pub fn is_captured_remote_return_info(asdu: &[u8]) -> bool {
    asdu.len() >= DUI_LEN && asdu[0] < 45 && cot_value(asdu) == COT_RETREM
}

/// Why a captured frame is left out of the slave's script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stripped {
    /// Part of a captured GI/CI exchange.
    Interrogation,
    /// A captured command confirmation or read reply.
    Command,
    /// Captured return information caused by a remote command (COT 11).
    ReturnInfo,
}

/// Which captured frames the slave strips from its script because it
/// answers the live master itself. One definition for the replayer and
/// the analyzer; see the module docs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureStrip {
    /// GI/CI synthesis is on.
    pub interrogations: bool,
    /// Command echo is on.
    pub commands: bool,
    /// Command echo synthesizes return information.
    pub return_info: bool,
}

impl CaptureStrip {
    /// The rule for a slave run with GI/CI synthesis `gi_ci` and the
    /// command-echo settings `commands`.
    pub fn new(gi_ci: bool, commands: &CommandsConfig) -> Self {
        Self {
            interrogations: gi_ci,
            commands: commands.enabled,
            return_info: commands.enabled && commands.return_info != ReturnInfo::None,
        }
    }

    /// Why `asdu` is stripped, or `None` if it is replayed.
    pub fn classify(&self, asdu: &[u8]) -> Option<Stripped> {
        if self.interrogations && is_captured_interrogation_frame(asdu) {
            Some(Stripped::Interrogation)
        } else if self.commands && commands::is_captured_command_frame(asdu) {
            Some(Stripped::Command)
        } else if self.return_info && is_captured_remote_return_info(asdu) {
            Some(Stripped::ReturnInfo)
        } else {
            None
        }
    }
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
    fn return_info_is_stripped_only_with_echo_and_return_info_on() {
        let cfg = |enabled: bool, ri: ReturnInfo| CommandsConfig {
            enabled,
            return_info: ri,
            ..CommandsConfig::default()
        };
        let retrem = a(1, 11);
        let local = a(1, 12);
        let spont = a(1, 3);
        for ri in [ReturnInfo::Spontaneous, ReturnInfo::Retrem] {
            let s = CaptureStrip::new(true, &cfg(true, ri));
            assert_eq!(s.classify(&retrem), Some(Stripped::ReturnInfo));
            assert_eq!(s.classify(&a(31, 11 | 0x80)), Some(Stripped::ReturnInfo));
            // COT 12: a local operator action, ordinary data.
            assert_eq!(s.classify(&local), None);
            assert_eq!(s.classify(&spont), None);
        }
        for s in [
            CaptureStrip::new(true, &cfg(true, ReturnInfo::None)),
            CaptureStrip::new(true, &cfg(false, ReturnInfo::Retrem)),
        ] {
            assert_eq!(s.classify(&retrem), None);
        }
        // A command type never counts as return information.
        assert!(!is_captured_remote_return_info(&a(45, 11)));
        assert!(!is_captured_remote_return_info(&[1, 1, 11]));
    }

    #[test]
    fn capture_strip_classifies_every_kind() {
        let s = CaptureStrip::new(
            true,
            &CommandsConfig {
                return_info: ReturnInfo::Spontaneous,
                ..CommandsConfig::default()
            },
        );
        assert_eq!(s.classify(&a(100, 7)), Some(Stripped::Interrogation));
        assert_eq!(s.classify(&a(1, 20)), Some(Stripped::Interrogation));
        assert_eq!(s.classify(&a(45, 7)), Some(Stripped::Command));
        assert_eq!(s.classify(&a(1, 5)), Some(Stripped::Command));
        assert_eq!(s.classify(&a(1, 11)), Some(Stripped::ReturnInfo));
        assert_eq!(s.classify(&a(13, 3)), None);
        let off = CaptureStrip::new(
            false,
            &CommandsConfig {
                enabled: false,
                ..CommandsConfig::default()
            },
        );
        assert_eq!(off, CaptureStrip::default());
        for x in [a(100, 7), a(1, 20), a(45, 7), a(1, 11)] {
            assert_eq!(off.classify(&x), None);
        }
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
