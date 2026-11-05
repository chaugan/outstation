//! Identification of captured GI/CI response bursts in a server-side
//! (controlled-station) I-frame stream.
//!
//! A burst answers one interrogation command for one station: the
//! ActCon (`C_IC_NA_1` / `C_CI_NA_1`, COT 7), the interrogated data
//! (COT 20..=36 for a GI, 37..=41 for a CI) and the ActTerm (COT 10),
//! all carrying the station's Common Address. Spontaneous or periodic
//! frames may be interleaved with a burst; they are not members.
//!
//! The slave replayer strips burst members from the replayed script
//! when it synthesizes live GI/CI answers (otherwise the live master
//! gets an unsolicited ActCon/ActTerm), and the analyzer can use the
//! same function so both sides drop exactly the same frames.
//!
//! Matching rules, per (kind, CA):
//! * a positive ActCon opens a burst;
//! * data frames of the matching COT range join the open burst; with
//!   none open (a capture that starts mid-burst) they open an
//!   *orphan* burst;
//! * the ActTerm closes the open burst (or forms an orphan burst of
//!   its own);
//! * a negative ActCon (P/N = 1) or a mirror with COT 44..=47 (unknown
//!   type, cause, CA or IOA) is a one-frame burst;
//! * a burst still open at the end of the stream (capture cut) ends at
//!   its last member.

use std::collections::HashMap;
use std::ops::Range;

use crate::apci::Frame;
use crate::asdu::{common_address, DUI_LEN};

/// GI or CI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterrogationKind {
    /// General interrogation, `C_IC_NA_1` (type 100), data COT 20..=36.
    General,
    /// Counter interrogation, `C_CI_NA_1` (type 101), data COT 37..=41.
    Counter,
}

impl InterrogationKind {
    pub fn type_id(self) -> u8 {
        match self {
            InterrogationKind::General => 100,
            InterrogationKind::Counter => 101,
        }
    }

    fn from_type(type_id: u8) -> Option<Self> {
        match type_id {
            100 => Some(Self::General),
            101 => Some(Self::Counter),
            _ => None,
        }
    }

    fn from_data_cot(cot: u8) -> Option<Self> {
        match cot {
            20..=36 => Some(Self::General),
            37..=41 => Some(Self::Counter),
            _ => None,
        }
    }
}

/// One response burst. Indices refer to the slice passed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterrogationBurst {
    pub kind: InterrogationKind,
    /// Station Common Address of every member.
    pub ca: u16,
    /// From the first to one past the last member. May contain
    /// interleaved non-member frames.
    pub span: Range<usize>,
    /// Every member index, ascending.
    pub members: Vec<usize>,
    /// Burst opened by a positive ActCon.
    pub has_act_con: bool,
    /// Burst closed by an ActTerm.
    pub has_act_term: bool,
    /// Rejected (negative ActCon or COT 44..=47 mirror).
    pub negative: bool,
}

impl InterrogationBurst {
    fn new(kind: InterrogationKind, ca: u16, idx: usize) -> Self {
        Self {
            kind,
            ca,
            span: idx..idx + 1,
            members: vec![idx],
            has_act_con: false,
            has_act_term: false,
            negative: false,
        }
    }

    fn push(&mut self, idx: usize) {
        self.members.push(idx);
        self.span.end = idx + 1;
    }

    /// Opened by data or ActTerm rather than an ActCon (the capture
    /// started inside the burst).
    pub fn orphan(&self) -> bool {
        !self.has_act_con && !self.negative
    }
}

/// What role an ASDU plays in an interrogation response.
enum Role {
    ActCon,
    ActTerm,
    Negative,
    Data,
}

fn classify(asdu: &[u8]) -> Option<(InterrogationKind, u16, Role)> {
    if asdu.len() < DUI_LEN {
        return None;
    }
    let cot = asdu[2] & 0x3f;
    let negative = asdu[2] & 0x40 != 0;
    let ca = common_address(asdu);
    if let Some(kind) = InterrogationKind::from_type(asdu[0]) {
        let role = match cot {
            44..=47 => Role::Negative,
            7 if negative => Role::Negative,
            7 => Role::ActCon,
            10 => Role::ActTerm,
            _ => return None,
        };
        return Some((kind, ca, role));
    }
    InterrogationKind::from_data_cot(cot).map(|k| (k, ca, Role::Data))
}

/// Find the interrogation response bursts in a sequence of server
/// I-frame ASDUs. Indices in the result refer to `asdus`. Bursts are
/// ordered by their first member.
pub fn interrogation_bursts<A: AsRef<[u8]>>(asdus: &[A]) -> Vec<InterrogationBurst> {
    let mut done: Vec<InterrogationBurst> = Vec::new();
    let mut open: HashMap<(InterrogationKind, u16), InterrogationBurst> = HashMap::new();
    for (idx, asdu) in asdus.iter().enumerate() {
        let Some((kind, ca, role)) = classify(asdu.as_ref()) else {
            continue;
        };
        let key = (kind, ca);
        match role {
            Role::Negative => {
                let mut b = InterrogationBurst::new(kind, ca, idx);
                b.negative = true;
                done.push(b);
            }
            Role::ActCon => {
                // A new ActCon while one is open: the old one lost its
                // ActTerm (or it was never sent); close it as it is.
                if let Some(prev) = open.remove(&key) {
                    done.push(prev);
                }
                let mut b = InterrogationBurst::new(kind, ca, idx);
                b.has_act_con = true;
                open.insert(key, b);
            }
            Role::Data => match open.get_mut(&key) {
                Some(b) => b.push(idx),
                None => {
                    open.insert(key, InterrogationBurst::new(kind, ca, idx));
                }
            },
            Role::ActTerm => {
                let mut b = match open.remove(&key) {
                    Some(mut b) => {
                        b.push(idx);
                        b
                    }
                    None => InterrogationBurst::new(kind, ca, idx),
                };
                b.has_act_term = true;
                done.push(b);
            }
        }
    }
    done.extend(open.into_values());
    done.sort_by_key(|b| b.span.start);
    done
}

/// Indices of every burst member in `asdus`, ascending.
pub fn interrogation_member_indices<A: AsRef<[u8]>>(asdus: &[A]) -> Vec<usize> {
    let mut v: Vec<usize> = interrogation_bursts(asdus)
        .into_iter()
        .flat_map(|b| b.members)
        .collect();
    v.sort_unstable();
    v
}

/// Spans of the captured interrogation bursts among `frames` (indices
/// into `frames`; S- and U-frames are never members but may fall
/// inside a span). See [`interrogation_bursts`] for the members.
pub fn captured_interrogation_bursts(frames: &[Frame<'_>]) -> Vec<Range<usize>> {
    let (pos, asdus): (Vec<usize>, Vec<&[u8]>) = frames
        .iter()
        .enumerate()
        .filter_map(|(i, f)| f.asdu().map(|a| (i, a)))
        .unzip();
    interrogation_bursts(&asdus)
        .into_iter()
        .map(|b| pos[b.span.start]..pos[b.span.end - 1] + 1)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::Apdu;

    fn act(type_id: u8, cot: u8, ca: u16) -> Vec<u8> {
        let q = if type_id == 100 { 20 } else { 5 };
        vec![type_id, 1, cot, 0, ca as u8, (ca >> 8) as u8, 0, 0, 0, q]
    }
    fn data(cot: u8, ca: u16, ioa: u8) -> Vec<u8> {
        vec![1, 1, cot, 0, ca as u8, (ca >> 8) as u8, ioa, 0, 0, 1]
    }
    fn spont(ca: u16, ioa: u8) -> Vec<u8> {
        data(3, ca, ioa)
    }

    #[test]
    fn complete_gi_burst_with_interleaved_spontaneous() {
        let s = vec![
            spont(1, 9),
            act(100, 7, 1),
            data(20, 1, 1),
            spont(1, 9),
            data(20, 1, 2),
            act(100, 10, 1),
            spont(1, 9),
        ];
        let b = interrogation_bursts(&s);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].kind, InterrogationKind::General);
        assert_eq!(b[0].ca, 1);
        assert_eq!(b[0].span, 1..6);
        assert_eq!(b[0].members, vec![1, 2, 4, 5]);
        assert!(b[0].has_act_con && b[0].has_act_term && !b[0].orphan());
        assert_eq!(interrogation_member_indices(&s), vec![1, 2, 4, 5]);
    }

    #[test]
    fn bursts_are_matched_per_ca_and_kind() {
        let s = vec![
            act(100, 7, 1),
            act(100, 7, 2),
            act(101, 7, 1),
            data(20, 2, 1),
            data(37, 1, 5),
            data(21, 1, 1),
            act(100, 10, 2),
            act(101, 10, 1),
            act(100, 10, 1),
        ];
        let b = interrogation_bursts(&s);
        assert_eq!(b.len(), 3);
        assert_eq!(
            (b[0].kind, b[0].ca, b[0].members.clone()),
            (InterrogationKind::General, 1, vec![0, 5, 8])
        );
        assert_eq!(
            (b[1].kind, b[1].ca, b[1].members.clone()),
            (InterrogationKind::General, 2, vec![1, 3, 6])
        );
        assert_eq!(
            (b[2].kind, b[2].ca, b[2].members.clone()),
            (InterrogationKind::Counter, 1, vec![2, 4, 7])
        );
    }

    #[test]
    fn orphans_negatives_and_cut_bursts() {
        let s = vec![
            data(20, 1, 1),        // capture started mid-burst
            act(100, 10, 1),       // ...and its ActTerm
            act(100, 7 | 0x40, 1), // negative ActCon
            act(100, 46, 7),       // unknown-CA mirror
            act(101, 7, 1),        // CI cut by capture end
            data(38, 1, 3),
            spont(1, 2),
        ];
        let b = interrogation_bursts(&s);
        assert_eq!(b.len(), 4);
        assert!(b[0].orphan() && b[0].has_act_term);
        assert_eq!(b[0].members, vec![0, 1]);
        assert!(b[1].negative && b[1].members == vec![2]);
        assert!(b[2].negative && b[2].ca == 7);
        assert!(b[3].has_act_con && !b[3].has_act_term);
        assert_eq!(b[3].span, 4..6);
        assert_eq!(interrogation_member_indices(&s), vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn ordinary_traffic_has_no_bursts() {
        let s = vec![spont(1, 1), data(5, 1, 2), data(42, 1, 3), vec![100, 1]];
        assert!(interrogation_bursts(&s).is_empty());
    }

    #[test]
    fn frame_spans_skip_s_and_u_frames() {
        let mut stream = Vec::new();
        stream.extend(Apdu::U { code: 0x0b }.serialize());
        for (i, a) in [act(100, 7, 1), data(20, 1, 1)].into_iter().enumerate() {
            stream.extend(
                Apdu::I {
                    ns: i as u16,
                    nr: 0,
                    asdu: a,
                }
                .serialize(),
            );
        }
        stream.extend(Apdu::S { nr: 1 }.serialize());
        stream.extend(
            Apdu::I {
                ns: 2,
                nr: 0,
                asdu: act(100, 10, 1),
            }
            .serialize(),
        );
        let frames: Vec<Frame> = crate::apci::frames(&stream).collect();
        assert_eq!(frames.len(), 5);
        assert_eq!(captured_interrogation_bursts(&frames), vec![1..5]);
    }
}
