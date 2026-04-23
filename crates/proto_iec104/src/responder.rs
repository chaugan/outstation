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

use crate::apdu::{APCI_LEN, MAX_APDU_LEN};
use crate::asdu::{element_len, write_ioa, DUI_LEN, IOA_LEN};
use crate::inventory::Inventory;

/// COT 7 = Activation Confirmation, COT 10 = Activation Termination.
pub const COT_ACT_CON: u8 = 7;
pub const COT_ACT_TERM: u8 = 10;

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

/// Per-request bits the responder needs to echo on every reply ASDU.
#[derive(Debug, Clone, Copy)]
pub struct RequestEcho {
    /// 16-bit Common Address from the request DUI. The response uses
    /// this same CA on every ASDU. Wildcard handling (CA=65535) is
    /// the caller's job — pass the per-RTU CA the slave should reply
    /// with.
    pub ca: u16,
    /// Originator Address (high byte of the 2-byte COT field). Per
    /// spec the slave echoes the master's OA so the master can
    /// correlate the response with the originating request.
    pub oa: u8,
    /// Test bit (0x80 of the COT byte). Echo from the request so a
    /// test interrogation gets a test response.
    pub test: bool,
    /// Positive/Negative bit (0x40). Always 0 for a normal positive
    /// confirmation; non-zero only when reporting a failure (not used
    /// here because we always have a deterministic response).
    pub negative: bool,
}

impl RequestEcho {
    /// Pack T + P/N into the high two bits of the COT byte.
    #[inline]
    fn cot_high_bits(&self) -> u8 {
        let mut b = 0u8;
        if self.test {
            b |= 0x80;
        }
        if self.negative {
            b |= 0x40;
        }
        b
    }
}

/// Build the full response burst (ActCon → data frames → ActTerm) for
/// a General Interrogation. Returns the ASDUs in the exact order the
/// slave must put them on the wire. Each ASDU is a `Vec<u8>` ready to
/// hand to `Apdu::I { asdu, .. }`.
pub fn build_gi_response(
    inv: &Inventory,
    echo: RequestEcho,
    qoi: u8,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    out.push(build_ic_control(echo, COT_ACT_CON, qoi));
    let cot_data = inrogen_cot_for_qoi(qoi);
    let entries = inv.entries_for_gi(qoi);
    out.extend(build_data_frames(echo, cot_data, &entries));
    out.push(build_ic_control(echo, COT_ACT_TERM, qoi));
    out
}

/// Build the full response burst for a Counter Interrogation.
pub fn build_ci_response(
    inv: &Inventory,
    echo: RequestEcho,
    qcc: u8,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    out.push(build_ci_control(echo, COT_ACT_CON, qcc));
    let cot_data = reqcogen_cot_for_qcc(qcc);
    let entries = inv.entries_for_ci(qcc);
    out.extend(build_data_frames(echo, cot_data, &entries));
    out.push(build_ci_control(echo, COT_ACT_TERM, qcc));
    out
}

/// Map a QOI (in C_IC_NA_1) to the COT a corresponding data frame
/// should carry per IEC 60870-5-101 §7.2.6.22 / §7.2.3 table 14.
fn inrogen_cot_for_qoi(qoi: u8) -> u8 {
    match qoi {
        20 => COT_INROGEN_STATION,
        g @ 21..=36 => g, // Group N → COT 20+N (which equals the QOI).
        _ => COT_INROGEN_STATION,
    }
}

/// Map a QCC (in C_CI_NA_1) to the COT a corresponding data frame
/// should carry. QCC.QCQ = 5 → general; 1..4 → group 1..4.
fn reqcogen_cot_for_qcc(qcc: u8) -> u8 {
    let qcq = qcc & 0x3f;
    match qcq {
        5 => COT_REQCOGEN,
        g @ 1..=4 => COT_REQCO_GROUP_BASE + (g - 1), // → 38..41
        _ => COT_REQCOGEN,
    }
}

/// Build a `C_IC_NA_1` (type 100) ASDU with one IOA=0 element
/// carrying the QOI byte. Used for both ActCon and ActTerm.
fn build_ic_control(echo: RequestEcho, cot: u8, qoi: u8) -> Vec<u8> {
    let mut a = vec![0u8; DUI_LEN + IOA_LEN + 1];
    a[0] = 100; // C_IC_NA_1
    a[1] = 0x01; // VSQ: SQ=0, N=1
    a[2] = (cot & 0x3f) | echo.cot_high_bits();
    a[3] = echo.oa;
    a[4] = (echo.ca & 0xff) as u8;
    a[5] = ((echo.ca >> 8) & 0xff) as u8;
    write_ioa(&mut a, DUI_LEN, 0); // IOA = 0 for system commands
    a[DUI_LEN + IOA_LEN] = qoi;
    a
}

/// Build a `C_CI_NA_1` (type 101) ASDU. Same shape as `C_IC_NA_1` but
/// the element body is the QCC byte rather than QOI.
fn build_ci_control(echo: RequestEcho, cot: u8, qcc: u8) -> Vec<u8> {
    let mut a = vec![0u8; DUI_LEN + IOA_LEN + 1];
    a[0] = 101; // C_CI_NA_1
    a[1] = 0x01;
    a[2] = (cot & 0x3f) | echo.cot_high_bits();
    a[3] = echo.oa;
    a[4] = (echo.ca & 0xff) as u8;
    a[5] = ((echo.ca >> 8) & 0xff) as u8;
    write_ioa(&mut a, DUI_LEN, 0);
    a[DUI_LEN + IOA_LEN] = qcc;
    a
}

/// Build the data frames for an interrogation response. Groups
/// consecutive entries with the same `type_id` into a single ASDU
/// (`SQ=0`, `N=k`) sized to fit a single APCI (≤ `MAX_APDU_LEN`).
/// Mixed types start new ASDUs. Returns one `Vec<u8>` per ASDU in
/// the order they should hit the wire.
///
/// Per-type element cap matters: a type-36 (M_ME_TF_1, 12 B/elem)
/// fits at most 16 IOAs per ASDU, while a type-1 (M_SP_NA_1, 1 B/elem)
/// fits 60. Without per-type capping the responder emits frames whose
/// declared APCI length wraps the 1-byte length field and the receiver
/// sees garbage.
fn build_data_frames(
    echo: RequestEcho,
    cot: u8,
    entries: &[((u16, u32), &crate::inventory::InventoryEntry)],
) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut i = 0;
    while i < entries.len() {
        let ((_, _), e0) = entries[i];
        let type_id = e0.type_id;
        let elem = match element_len(type_id) {
            Some(n) => n,
            None => {
                // Type we don't know how to walk — skip silently.
                i += 1;
                continue;
            }
        };
        let cap = max_elements_for(type_id);
        if cap == 0 {
            i += 1;
            continue;
        }
        // Find the run of consecutive same-type entries (capped to
        // the per-type byte budget).
        let mut j = i + 1;
        while j < entries.len()
            && entries[j].1.type_id == type_id
            && (j - i) < cap
        {
            j += 1;
        }
        let n = j - i;
        let mut a = Vec::with_capacity(DUI_LEN + n * (IOA_LEN + elem));
        a.push(type_id);
        a.push(n as u8 & 0x7f); // SQ=0, N=n
        a.push((cot & 0x3f) | echo.cot_high_bits());
        a.push(echo.oa);
        a.push((echo.ca & 0xff) as u8);
        a.push(((echo.ca >> 8) & 0xff) as u8);
        for k in i..j {
            let ((_, ioa), entry) = entries[k];
            let mut ioa_buf = [0u8; IOA_LEN];
            write_ioa(&mut ioa_buf, 0, ioa);
            a.extend_from_slice(&ioa_buf);
            a.extend_from_slice(&entry.element_body);
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
        RequestEcho { ca, oa: 0, test: false, negative: false }
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

    #[test]
    fn empty_inventory_yields_actcon_actterm_only() {
        let inv = Inventory::default();
        let resp = build_gi_response(&inv, echo_for(1), 20);
        assert_eq!(resp.len(), 2);
        assert_eq!(resp[0][0], 100); // C_IC_NA_1
        assert_eq!(resp[0][2] & 0x3f, COT_ACT_CON);
        assert_eq!(resp[1][2] & 0x3f, COT_ACT_TERM);
        assert_eq!(resp[0][DUI_LEN + IOA_LEN], 20); // QOI echoed
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
            assert!(f.len() <= MAX_APDU_LEN - APCI_LEN, "frame too big: {}", f.len());
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
            assert!((f[1] & 0x7f) as usize <= 16, "type-36 N capped at 16");
        }
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
        let inv = Inventory::default();
        let echo = RequestEcho { ca: 0xbeef, oa: 0x42, test: true, negative: false };
        let resp = build_gi_response(&inv, echo, 20);
        let act_con = &resp[0];
        assert_eq!(act_con[3], 0x42); // OA echoed
        assert_eq!(act_con[4], 0xef); // CA low
        assert_eq!(act_con[5], 0xbe); // CA high
        assert!(act_con[2] & 0x80 != 0, "test bit should be set");
        assert_eq!(act_con[2] & 0x3f, COT_ACT_CON);
    }
}
