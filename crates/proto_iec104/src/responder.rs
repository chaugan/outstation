//! Pure spec-correct ASDU generator for IEC 60870-5-104 General
//! Interrogation (`C_IC_NA_1`, type 100) and Counter Interrogation
//! (`C_CI_NA_1`, type 101) responses.
//!
//! Both the live slave-replayer and the post-run analyzer call into
//! here. The slave wraps the returned ASDUs in APCI frames with live
//! N(S)/N(R); the analyzer compares the returned ASDUs byte-for-byte
//! against what the slave actually emitted in the captured pcap. By
//! sharing one implementation we guarantee they agree on what
//! "spec-correct" means.
//!
//! The functions in this module take the parsed [`Inventory`] and a
//! few request-derived inputs (CA, OA, QOI/QCC, T, P/N) and return a
//! `Vec<Vec<u8>>` — the ordered list of ASDU byte buffers the slave
//! must emit on the wire to satisfy the request:
//!
//! 1. **ActCon** — `C_IC_NA_1` / `C_CI_NA_1` with COT=7, echoing
//!    QOI/QCC, signalling "command accepted, response coming".
//! 2. Zero or more **Inrogen** (or **Reqcogen**) data frames carrying
//!    the actual point values, COT = 20+G or 37/38+G, T/P/N copied
//!    from the request, OA echoed.
//! 3. **ActTerm** — same shape as ActCon but COT=10, signalling
//!    "response complete".
//!
//! Per IEC 60870-5-101 §7.4.4.4 a zero-point group is still a legal
//! interrogation: the response is just ActCon → ActTerm with no data
//! frames in between. This builder handles that case.
//!
//! Addressing and rejection rules:
//!
//! * The inventory is filtered by the request's Common Address; every
//!   data ASDU carries the CA of the station it describes.
//! * CA 0xFFFF (broadcast) is answered once per station CA the
//!   inventory knows, each with its own ActCon → data → ActTerm.
//! * A CA the inventory does not know gets a negative mirror (P/N=1)
//!   with COT 46 "unknown common address of ASDU", and nothing else.
//! * An unsupported qualifier (QOI outside 20..=36; QCC request
//!   qualifier outside 1..=5) gets a negative ActCon (COT 7, P/N=1) and
//!   nothing else.
//! * QCC freeze/reset (FRZ = 1, 2 or 3) is acknowledged with ActCon →
//!   ActTerm and no data; only FRZ = 0 (read) returns counter values.

use crate::apdu::{APCI_LEN, MAX_APDU_LEN};
use crate::asdu::{element_len, write_ioa, DUI_LEN, IOA_LEN};
use crate::inventory::{Inventory, InventoryEntry};

pub use crate::inventory::CA_BROADCAST;

/// COT 7 = Activation Confirmation, COT 10 = Activation Termination.
pub const COT_ACT_CON: u8 = 7;
pub const COT_ACT_TERM: u8 = 10;
/// COT 46 = unknown common address of ASDU.
pub const COT_UNKNOWN_CA: u8 = 46;

/// COT 20 = Inrogen station, 21..36 = Inrogen group 1..16.
pub const COT_INROGEN_STATION: u8 = 20;
/// COT 37 = Reqcogen, 38..41 = Reqco group 1..4.
pub const COT_REQCOGEN: u8 = 37;
pub const COT_REQCO_GROUP_BASE: u8 = 38;

/// Hard upper bound on Information Object count per ASDU from the
/// 7-bit N field in the VSQ (IEC 60870-5-101 §7.2.2). The actual cap
/// is per-type, computed from `MAX_APDU_LEN` so the resulting APCI
/// fits the 1-byte APDU length field — see [`max_elements_for`].
pub const MAX_ELEMENTS_PER_ASDU: usize = 127;

/// Largest element count of `type_id` that fits in a single APCI
/// (after the 6-byte DUI). Returns 0 if `type_id` has no known
/// element layout. The IEC 104 APDU length octet caps the body at
/// `MAX_APDU_LEN` (253) bytes including the 4 control-field bytes,
/// so the ASDU itself can use at most `MAX_APDU_LEN - APCI_LEN = 249`
/// bytes. After the 6-byte DUI we have `249 - 6 = 243` bytes for
/// `n × (IOA_LEN + element_len)` (SQ=0 case).
pub fn max_elements_for(type_id: u8) -> usize {
    let Some(elem) = element_len(type_id) else {
        return 0;
    };
    let body_budget = MAX_APDU_LEN - APCI_LEN - DUI_LEN; // 243
    let stride = IOA_LEN + elem;
    let by_bytes = body_budget / stride;
    by_bytes.min(MAX_ELEMENTS_PER_ASDU)
}

/// Request fields the responder echoes on every reply ASDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestEcho {
    /// Common Address from the request DUI. A station CA selects that
    /// station; [`CA_BROADCAST`] fans out to every known station.
    pub ca: u16,
    /// Originator Address (high byte of the 2-byte COT field). Per
    /// spec the slave echoes the master's OA so the master can
    /// correlate the response with the originating request.
    pub oa: u8,
    /// Test bit (0x80 of the COT byte). Echo from the request so a
    /// test interrogation gets a test response.
    pub test: bool,
}

impl RequestEcho {
    /// Pack T + P/N into the high two bits of the COT byte.
    #[inline]
    fn cot_byte(&self, cot: u8, negative: bool) -> u8 {
        let mut b = cot & 0x3f;
        if self.test {
            b |= 0x80;
        }
        if negative {
            b |= 0x40;
        }
        b
    }
}

/// The reply of one station (one Common Address) to an interrogation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaResponse {
    /// Station CA every ASDU in this reply carries. For an unknown-CA
    /// rejection this is the CA from the request.
    pub ca: u16,
    /// True when the request was rejected (P/N=1 on `act_con`).
    pub negative: bool,
    /// Mirrored command: COT 7 (positive or negative) or COT 46.
    pub act_con: Vec<u8>,
    /// Inrogen / Reqcogen data ASDUs (empty for a rejection, an empty
    /// group, or a counter freeze/reset).
    pub data: Vec<Vec<u8>>,
    /// Activation termination; `None` for a rejection.
    pub act_term: Option<Vec<u8>>,
}

/// Full reply to one interrogation command, in wire order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InterrogationResponse {
    /// One entry per answering station (several only for a broadcast).
    pub per_ca: Vec<CaResponse>,
}

impl InterrogationResponse {
    /// True if any station rejected the request. For a single-CA
    /// request this is the P/N bit of the (only) ActCon.
    pub fn negative(&self) -> bool {
        self.per_ca.iter().any(|r| r.negative)
    }

    /// Every ASDU to emit, in wire order.
    pub fn asdus(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.per_ca.iter().flat_map(|r| {
            std::iter::once(&r.act_con)
                .chain(r.data.iter())
                .chain(r.act_term.iter())
        })
    }

    /// Owned ASDUs in wire order.
    pub fn into_asdus(self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for r in self.per_ca {
            out.push(r.act_con);
            out.extend(r.data);
            out.extend(r.act_term);
        }
        out
    }
}

/// What a valid qualifier asks for.
enum Plan {
    /// Reply with data frames carrying this COT.
    Data(u8),
    /// ActCon + ActTerm, no data (counter freeze / reset).
    NoData,
    /// Negative ActCon.
    Reject,
}

#[derive(Clone, Copy)]
enum Kind {
    General,
    Counter,
}

impl Kind {
    fn type_id(self) -> u8 {
        match self {
            Kind::General => 100, // C_IC_NA_1
            Kind::Counter => 101, // C_CI_NA_1
        }
    }
}

fn gi_plan(qoi: u8) -> Plan {
    match qoi {
        20..=36 => Plan::Data(qoi), // station: COT 20; group N: COT 20+N
        _ => Plan::Reject,
    }
}

fn ci_plan(qcc: u8) -> Plan {
    let rqt = qcc & 0x3f;
    let frz = qcc >> 6;
    let cot = match rqt {
        5 => COT_REQCOGEN,
        g @ 1..=4 => COT_REQCO_GROUP_BASE + (g - 1), // 38..41
        _ => return Plan::Reject,
    };
    if frz == 0 {
        Plan::Data(cot)
    } else {
        // 1 = freeze without reset, 2 = freeze with reset, 3 = reset.
        Plan::NoData
    }
}

/// Answer a General Interrogation (`C_IC_NA_1`, COT 6) with qualifier
/// `qoi`. See the module docs for the addressing and rejection rules.
pub fn respond_gi(inv: &Inventory, echo: RequestEcho, qoi: u8) -> InterrogationResponse {
    respond(inv, echo, Kind::General, qoi)
}

/// Answer a Counter Interrogation (`C_CI_NA_1`, COT 6) with qualifier
/// `qcc`. See the module docs for the addressing and rejection rules.
pub fn respond_ci(inv: &Inventory, echo: RequestEcho, qcc: u8) -> InterrogationResponse {
    respond(inv, echo, Kind::Counter, qcc)
}

/// [`respond_gi`] flattened to the ASDUs in wire order.
pub fn build_gi_response(inv: &Inventory, echo: RequestEcho, qoi: u8) -> Vec<Vec<u8>> {
    respond_gi(inv, echo, qoi).into_asdus()
}

/// [`respond_ci`] flattened to the ASDUs in wire order.
pub fn build_ci_response(inv: &Inventory, echo: RequestEcho, qcc: u8) -> Vec<Vec<u8>> {
    respond_ci(inv, echo, qcc).into_asdus()
}

fn respond(inv: &Inventory, echo: RequestEcho, kind: Kind, qualifier: u8) -> InterrogationResponse {
    let stations: Vec<u16> = if echo.ca == CA_BROADCAST {
        inv.cas.iter().copied().collect()
    } else if inv.knows_ca(echo.ca) {
        vec![echo.ca]
    } else {
        Vec::new()
    };
    if stations.is_empty() {
        return InterrogationResponse {
            per_ca: vec![CaResponse {
                ca: echo.ca,
                negative: true,
                act_con: build_control(kind, echo, echo.ca, COT_UNKNOWN_CA, true, qualifier),
                data: Vec::new(),
                act_term: None,
            }],
        };
    }
    let plan = match kind {
        Kind::General => gi_plan(qualifier),
        Kind::Counter => ci_plan(qualifier),
    };
    let per_ca = stations
        .into_iter()
        .map(|ca| {
            let control =
                |cot: u8, negative: bool| build_control(kind, echo, ca, cot, negative, qualifier);
            match plan {
                Plan::Reject => CaResponse {
                    ca,
                    negative: true,
                    act_con: control(COT_ACT_CON, true),
                    data: Vec::new(),
                    act_term: None,
                },
                Plan::NoData => CaResponse {
                    ca,
                    negative: false,
                    act_con: control(COT_ACT_CON, false),
                    data: Vec::new(),
                    act_term: Some(control(COT_ACT_TERM, false)),
                },
                Plan::Data(cot) => {
                    let entries = match kind {
                        Kind::General => inv.entries_for_gi(ca, qualifier),
                        Kind::Counter => inv.entries_for_ci(ca, qualifier),
                    };
                    CaResponse {
                        ca,
                        negative: false,
                        act_con: control(COT_ACT_CON, false),
                        data: build_data_frames(echo, ca, cot, &entries),
                        act_term: Some(control(COT_ACT_TERM, false)),
                    }
                }
            }
        })
        .collect();
    InterrogationResponse { per_ca }
}

/// Build a `C_IC_NA_1` (type 100) or `C_CI_NA_1` (type 101) mirror
/// with one IOA=0 element carrying the QOI / QCC byte. Used for
/// ActCon, ActTerm and the negative replies.
fn build_control(
    kind: Kind,
    echo: RequestEcho,
    ca: u16,
    cot: u8,
    negative: bool,
    qualifier: u8,
) -> Vec<u8> {
    let mut a = vec![0u8; DUI_LEN + IOA_LEN + 1];
    a[0] = kind.type_id();
    a[1] = 0x01; // VSQ: SQ=0, N=1
    a[2] = echo.cot_byte(cot, negative);
    a[3] = echo.oa;
    a[4] = (ca & 0xff) as u8;
    a[5] = (ca >> 8) as u8;
    write_ioa(&mut a, DUI_LEN, 0); // IOA = 0 for system commands
    a[DUI_LEN + IOA_LEN] = qualifier;
    a
}

/// Build the data frames for one station's interrogation response.
/// Each entry is sent in its interrogation form (untimed type, time
/// tag stripped). Consecutive entries with the same type share an
/// ASDU (`SQ=0`, `N=k`) sized to fit a single APCI
/// (≤ `MAX_APDU_LEN`); a type change starts a new ASDU.
///
/// Per-type element cap matters: a type-13 (M_ME_NC_1, 5 B/elem)
/// fits at most 30 IOAs per ASDU, while a type-1 (M_SP_NA_1, 1 B/elem)
/// fits 60. Without per-type capping the responder emits frames whose
/// declared APCI length wraps the 1-byte length field and the receiver
/// sees garbage.
fn build_data_frames(
    echo: RequestEcho,
    ca: u16,
    cot: u8,
    entries: &[((u16, u32), &InventoryEntry)],
) -> Vec<Vec<u8>> {
    let forms: Vec<(u32, u8, &[u8])> = entries
        .iter()
        .filter_map(|&((_, ioa), e)| e.interrogation_form().map(|(t, b)| (ioa, t, b)))
        .collect();
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut i = 0;
    while i < forms.len() {
        let type_id = forms[i].1;
        let cap = max_elements_for(type_id);
        let elem = element_len(type_id).unwrap_or(0);
        // Run of consecutive same-type entries, capped to the per-type
        // byte budget (cap >= 1 for every interrogation type).
        let mut j = i + 1;
        while j < forms.len() && forms[j].1 == type_id && (j - i) < cap {
            j += 1;
        }
        let n = j - i;
        let mut a = Vec::with_capacity(DUI_LEN + n * (IOA_LEN + elem));
        a.push(type_id);
        a.push(n as u8 & 0x7f); // SQ=0, N=n
        a.push(echo.cot_byte(cot, false));
        a.push(echo.oa);
        a.push((ca & 0xff) as u8);
        a.push((ca >> 8) as u8);
        for &(ioa, _, body) in &forms[i..j] {
            let mut ioa_buf = [0u8; IOA_LEN];
            write_ioa(&mut ioa_buf, 0, ioa);
            a.extend_from_slice(&ioa_buf);
            a.extend_from_slice(body);
        }
        out.push(a);
        i = j;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;

    fn echo_for(ca: u16) -> RequestEcho {
        RequestEcho {
            ca,
            oa: 0,
            test: false,
        }
    }

    /// Build a synthetic ASDU containing one M_ME_NC_1 (type 13)
    /// floating-point point at the given (CA, IOA) with COT=20 so the
    /// inventory tags it as Station GI eligible.
    fn synth_point(ca: u16, ioa: u32, value_byte0: u8) -> Vec<u8> {
        let elem = element_len(13).unwrap(); // 5 bytes (4 float + 1 QDS)
        let mut a = vec![0u8; DUI_LEN + IOA_LEN + elem];
        a[0] = 13;
        a[1] = 0x01; // SQ=0, N=1
        a[2] = 20; // COT = Inrogen station
        a[3] = 0;
        a[4] = (ca & 0xff) as u8;
        a[5] = ((ca >> 8) & 0xff) as u8;
        write_ioa(&mut a, DUI_LEN, ioa);
        a[DUI_LEN + IOA_LEN] = value_byte0;
        a
    }

    /// One M_EI_NA_1 (end of initialisation) from `ca`: the station
    /// is known but has no points.
    fn known_empty_station(ca: u16) -> Inventory {
        let mut inv = Inventory::default();
        inv.ingest_asdu(&[70, 1, 4, 0, ca as u8, (ca >> 8) as u8, 0, 0, 0, 0]);
        inv
    }

    #[test]
    fn known_station_without_points_yields_actcon_actterm_only() {
        let inv = known_empty_station(1);
        let resp = build_gi_response(&inv, echo_for(1), 20);
        assert_eq!(resp.len(), 2);
        assert_eq!(resp[0][0], 100); // C_IC_NA_1
        assert_eq!(resp[0][2], COT_ACT_CON);
        assert_eq!(resp[1][2], COT_ACT_TERM);
        assert_eq!(resp[0][DUI_LEN + IOA_LEN], 20); // QOI echoed
        assert!(!respond_gi(&inv, echo_for(1), 20).negative());
    }

    #[test]
    fn unknown_ca_gets_negative_cot46_only() {
        let mut inv = Inventory::default();
        inv.ingest_asdu(&synth_point(1, 100, 0xaa));
        for kind in [100u8, 101] {
            let r = if kind == 100 {
                respond_gi(&inv, echo_for(7), 20)
            } else {
                respond_ci(&inv, echo_for(7), 5)
            };
            assert!(r.negative());
            let asdus = r.into_asdus();
            assert_eq!(asdus.len(), 1);
            assert_eq!(asdus[0][0], kind);
            assert_eq!(asdus[0][2], 0x40 | COT_UNKNOWN_CA);
            assert_eq!(&asdus[0][4..6], &[7, 0]);
        }
        // An entirely empty inventory knows no station at all.
        let r = respond_gi(&Inventory::default(), echo_for(1), 20);
        assert!(r.negative());
        assert_eq!(r.into_asdus()[0][2], 0x40 | COT_UNKNOWN_CA);
    }

    #[test]
    fn station_gi_returns_all_points_in_one_frame() {
        let mut inv = Inventory::default();
        inv.ingest_asdu(&synth_point(1, 100, 0xaa));
        inv.ingest_asdu(&synth_point(1, 101, 0xbb));
        inv.ingest_asdu(&synth_point(1, 102, 0xcc));
        let resp = build_gi_response(&inv, echo_for(1), 20);
        assert_eq!(resp.len(), 3); // ActCon, 1 data frame, ActTerm
        assert_eq!(resp[1][0], 13);
        assert_eq!(resp[1][1] & 0x7f, 3); // N=3
        assert_eq!(resp[1][2] & 0x3f, COT_INROGEN_STATION);
    }

    #[test]
    fn group_gi_only_returns_matching_group() {
        // Group 2 IOA (COT=22) and a station-only IOA (COT=20).
        let mut inv = Inventory::default();
        let mut grp2 = synth_point(1, 200, 0x11);
        grp2[2] = 22;
        inv.ingest_asdu(&grp2);
        inv.ingest_asdu(&synth_point(1, 201, 0x22)); // COT=20, no group
        let r20 = build_gi_response(&inv, echo_for(1), 20);
        // Station GI returns both.
        assert_eq!(r20[1][1] & 0x7f, 2);
        let r22 = build_gi_response(&inv, echo_for(1), 22);
        // Group 2 returns only the group-2 IOA.
        assert_eq!(r22[1][1] & 0x7f, 1);
        assert_eq!(r22[1][2] & 0x3f, 22);
    }

    #[test]
    fn chunks_by_per_type_byte_budget() {
        // type 13 = M_ME_NC_1 (4 B float + 1 B QDS = 5 B/elem).
        // Stride per IOA = 3 + 5 = 8 B, so max-per-ASDU = floor(243/8) = 30.
        let mut inv = Inventory::default();
        for i in 0..200u32 {
            inv.ingest_asdu(&synth_point(1, 1000 + i, i as u8));
        }
        let resp = build_gi_response(&inv, echo_for(1), 20);
        // 200 / 30 = 6 frames of 30 + 1 frame of 20  → ActCon + 7 + ActTerm.
        assert_eq!(resp.len(), 9);
        for f in &resp[1..resp.len() - 1] {
            // No ASDU exceeds the APCI byte budget.
            assert!(
                f.len() <= MAX_APDU_LEN - APCI_LEN,
                "frame too big: {}",
                f.len()
            );
        }
        assert_eq!(resp[1][1] & 0x7f, 30);
        assert_eq!(resp[7][1] & 0x7f, 20);
    }

    /// Regression for a real bug: type 36 (M_ME_TF_1, 12 B/elem) was
    /// being packed at 127 IOAs/ASDU, producing a 1911-byte ASDU whose
    /// declared APCI length wrapped the 1-byte length field. The
    /// receiver then saw the next valid APCI offset by ~1.9 KB and
    /// reported "ERR prefix N bytes" for everything in between.
    #[test]
    fn type36_response_fits_apdu_length_field() {
        let mut inv = Inventory::default();
        // Synthesize 200 type-36 entries (4 B float + 1 B QDS + 7 B
        // CP56Time2a = 12 B/elem). Stride per IOA = 3 + 12 = 15 B.
        // max-per-ASDU = floor(243/15) = 16.
        for i in 0..200u32 {
            let elem = element_len(36).unwrap();
            let mut a = vec![0u8; DUI_LEN + IOA_LEN + elem];
            a[0] = 36;
            a[1] = 0x01; // SQ=0, N=1
            a[2] = 20; // station Inrogen → eligible
            a[3] = 0;
            a[4] = 1;
            a[5] = 0;
            write_ioa(&mut a, DUI_LEN, 1000 + i);
            inv.ingest_asdu(&a);
        }
        let resp = build_gi_response(&inv, echo_for(1), 20);
        for f in &resp[1..resp.len() - 1] {
            assert!(
                f.len() <= MAX_APDU_LEN - APCI_LEN,
                "type-36 frame would overflow APCI length field: {} bytes",
                f.len()
            );
            // Interrogated data goes out untimed: M_ME_TF_1 answers as
            // M_ME_NC_1 (5 B/elem), capped at floor(243/8) = 30.
            assert_eq!(f[0], 13);
            assert!((f[1] & 0x7f) as usize <= max_elements_for(13));
        }
        // The type-36 byte budget itself: floor(243 / 15) = 16.
        assert_eq!(max_elements_for(36), 16);
        // Total elements add up across frames.
        let total: usize = resp[1..resp.len() - 1]
            .iter()
            .map(|f| (f[1] & 0x7f) as usize)
            .sum();
        assert_eq!(total, 200);
    }

    #[test]
    fn ci_response_only_includes_counters() {
        let mut inv = Inventory::default();
        // M_IT_NA_1 (type 15) — counter
        let mut counter_asdu = vec![0u8; DUI_LEN + IOA_LEN + 5];
        counter_asdu[0] = 15;
        counter_asdu[1] = 0x01;
        counter_asdu[2] = 37; // COT = Reqcogen
        counter_asdu[4] = 1;
        write_ioa(&mut counter_asdu, DUI_LEN, 500);
        inv.ingest_asdu(&counter_asdu);
        // A non-counter (type 13) point — should NOT show up in CI.
        inv.ingest_asdu(&synth_point(1, 600, 0xff));
        let resp = build_ci_response(&inv, echo_for(1), 0x05); // QCQ=5 general
        assert_eq!(resp.len(), 3);
        assert_eq!(resp[1][0], 15); // type 15 only
        assert_eq!(resp[1][1] & 0x7f, 1);
    }

    #[test]
    fn echoes_ca_oa_and_test_bit() {
        let inv = known_empty_station(0xbeef);
        let echo = RequestEcho {
            ca: 0xbeef,
            oa: 0x42,
            test: true,
        };
        let resp = build_gi_response(&inv, echo, 20);
        let act_con = &resp[0];
        assert_eq!(act_con[3], 0x42); // OA echoed
        assert_eq!(act_con[4], 0xef); // CA low
        assert_eq!(act_con[5], 0xbe); // CA high
        assert!(act_con[2] & 0x80 != 0, "test bit should be set");
        assert_eq!(act_con[2] & 0x3f, COT_ACT_CON);
    }

    /// Audit probe (F014): two stations share IOA 100 with different
    /// values. A GI to CA 1 must only return CA 1's point, labelled CA 1.
    #[test]
    fn gi_filters_by_request_ca() {
        let mut inv = Inventory::default();
        let mut p1 = vec![1u8, 1, 20, 0, 1, 0, 100, 0, 0, 1];
        inv.ingest_asdu(&p1);
        p1[4] = 2;
        p1[9] = 0;
        inv.ingest_asdu(&p1);
        let resp = build_gi_response(&inv, echo_for(1), 20);
        assert_eq!(resp.len(), 3);
        assert_eq!(resp[1], vec![1, 1, 20, 0, 1, 0, 100, 0, 0, 1]);
        let resp = build_gi_response(&inv, echo_for(2), 20);
        assert_eq!(resp[1], vec![1, 1, 20, 0, 2, 0, 100, 0, 0, 0]);
    }

    #[test]
    fn broadcast_gi_fans_out_per_station_with_real_cas() {
        let mut inv = Inventory::default();
        inv.ingest_asdu(&synth_point(1, 100, 0xaa));
        inv.ingest_asdu(&synth_point(2, 100, 0xbb));
        inv.ingest_asdu(&synth_point(2, 101, 0xcc));
        let r = respond_gi(&inv, echo_for(CA_BROADCAST), 20);
        assert!(!r.negative());
        assert_eq!(r.per_ca.len(), 2);
        assert_eq!(r.per_ca[0].ca, 1);
        assert_eq!(r.per_ca[1].ca, 2);
        let asdus = r.into_asdus();
        // ActCon(1), data(1), ActTerm(1), ActCon(2), data(2), ActTerm(2)
        assert_eq!(asdus.len(), 6);
        let cot_ca: Vec<(u8, u16)> = asdus
            .iter()
            .map(|a| (a[2] & 0x3f, u16::from_le_bytes([a[4], a[5]])))
            .collect();
        assert_eq!(
            cot_ca,
            vec![
                (COT_ACT_CON, 1),
                (COT_INROGEN_STATION, 1),
                (COT_ACT_TERM, 1),
                (COT_ACT_CON, 2),
                (COT_INROGEN_STATION, 2),
                (COT_ACT_TERM, 2),
            ]
        );
        assert!(asdus.iter().all(|a| a[4] != 0xff || a[5] != 0xff));
        assert_eq!(asdus[4][1] & 0x7f, 2);
    }

    #[test]
    fn unsupported_qoi_is_rejected() {
        let mut inv = Inventory::default();
        inv.ingest_asdu(&synth_point(1, 100, 0xaa));
        for qoi in [0u8, 1, 19, 37, 255] {
            let r = respond_gi(&inv, echo_for(1), qoi);
            assert!(r.negative(), "qoi {qoi}");
            let asdus = r.into_asdus();
            assert_eq!(asdus.len(), 1, "qoi {qoi}: negative ActCon only");
            assert_eq!(asdus[0][2], 0x40 | COT_ACT_CON);
            assert_eq!(asdus[0][DUI_LEN + IOA_LEN], qoi);
        }
        // Broadcast with a bad QOI: one negative ActCon per station.
        inv.ingest_asdu(&synth_point(2, 100, 0xaa));
        let r = respond_gi(&inv, echo_for(CA_BROADCAST), 0);
        assert_eq!(r.per_ca.len(), 2);
        assert!(r.per_ca.iter().all(|c| c.negative && c.act_term.is_none()));
    }

    fn counter_inventory() -> Inventory {
        let mut inv = Inventory::default();
        // M_IT_NA_1 at IOA 500 in counter group 2 (COT 39).
        inv.ingest_asdu(&[15, 1, 39, 0, 1, 0, 0xf4, 0x01, 0, 1, 2, 3, 4, 5]);
        inv
    }

    #[test]
    fn qcc_request_qualifiers() {
        let inv = counter_inventory();
        // General read: COT 37.
        let r = build_ci_response(&inv, echo_for(1), 5);
        assert_eq!(r.len(), 3);
        assert_eq!(r[1][2], COT_REQCOGEN);
        // Group 2 read: COT 39; group 1: no data.
        let r = build_ci_response(&inv, echo_for(1), 2);
        assert_eq!(r.len(), 3);
        assert_eq!(r[1][2], COT_REQCO_GROUP_BASE + 1);
        assert_eq!(build_ci_response(&inv, echo_for(1), 1).len(), 2);
        // RQT 0 and 6..=63 are rejected.
        for qcc in [0u8, 6, 31, 63, 0x40, 0x46] {
            let r = respond_ci(&inv, echo_for(1), qcc);
            assert!(r.negative(), "qcc {qcc:#x}");
            let a = r.into_asdus();
            assert_eq!(a.len(), 1);
            assert_eq!(a[0][2], 0x40 | COT_ACT_CON);
        }
    }

    #[test]
    fn qcc_freeze_and_reset_return_no_data() {
        let inv = counter_inventory();
        // FRZ 1 (freeze), 2 (freeze + reset), 3 (reset) with RQT 5.
        for frz in 1u8..=3 {
            let qcc = (frz << 6) | 5;
            let r = respond_ci(&inv, echo_for(1), qcc);
            assert!(!r.negative());
            let a = r.into_asdus();
            assert_eq!(a.len(), 2, "FRZ {frz}: ActCon + ActTerm only");
            assert_eq!(a[0][2], COT_ACT_CON);
            assert_eq!(a[1][2], COT_ACT_TERM);
            assert_eq!(a[0][DUI_LEN + IOA_LEN], qcc, "full QCC echoed");
        }
    }

    #[test]
    fn gi_excludes_counters_events_and_command_mirrors() {
        let mut inv = Inventory::default();
        inv.ingest_asdu(&[70, 1, 4, 0, 1, 0, 0, 0, 0, 0]); // M_EI_NA_1
        inv.ingest_asdu(&[45, 1, 7, 0, 1, 0, 0x88, 0x13, 0, 0x81]); // C_SC_NA_1 ActCon
        inv.ingest_asdu(&[15, 1, 37, 0, 1, 0, 0x58, 0x1b, 0, 1, 0, 0, 0, 0]); // M_IT_NA_1
        inv.ingest_asdu(&synth_point(1, 100, 0xaa));
        let r = build_gi_response(&inv, echo_for(1), 20);
        assert_eq!(r.len(), 3);
        assert_eq!(r[1][0], 13);
        assert_eq!(r[1][1] & 0x7f, 1);
    }

    #[test]
    fn timed_point_answers_gi_untimed() {
        let mut inv = Inventory::default();
        // M_ME_TF_1 (36) spontaneous: float + QDS + CP56.
        let mut a = vec![36, 1, 3, 0, 1, 0, 100, 0, 0, 1, 2, 3, 4, 0];
        a.extend_from_slice(&[9u8; 7]);
        inv.ingest_asdu(&a);
        let r = build_gi_response(&inv, echo_for(1), 20);
        assert_eq!(r.len(), 3);
        assert_eq!(r[1], vec![13, 1, 20, 0, 1, 0, 100, 0, 0, 1, 2, 3, 4, 0]);
    }
}
