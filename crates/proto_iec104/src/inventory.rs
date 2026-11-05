//! Per-RTU IEC 104 point database, built from a captured server-side
//! payload, used by the slave-mode replayer to synthesise spec-correct
//! responses to General Interrogation (`C_IC_NA_1`) and Counter
//! Interrogation (`C_CI_NA_1`) commands from the live master.
//!
//! The database is **observational** — it learns from what the captured
//! pcap actually carried, not from any external configuration:
//!
//! * Each (CA, IOA) seen on the wire becomes an entry, tagged with the
//!   most recently observed type ID and element body bytes.
//! * Group membership (for QOI 21..36 / QCC 1..4) is inferred from the
//!   COTs the IOA was observed with: a frame with COT=20+G (Inrogen
//!   group G) marks the IOA as belonging to group G; COT=20 (station
//!   Inrogen) is treated as "all groups".
//! * IOAs only ever seen with spontaneous COTs (1..3, 11..13, etc.) are
//!   still eligible for QOI=20 (station GI) but not for any specific
//!   group GI — matching how a real RTU would treat an unconfigured
//!   point.
//!
//! Ingested values become the slave's "current state" for the GI
//! response; the most recent value per (CA, IOA) wins.
//!
//! Only **monitor-direction process information** (type IDs 1..=21 and
//! 30..=40) becomes a point. Command mirrors (45..=64, 100+), end of
//! initialisation (70) and confirmations/negative replies (COT 6..=10,
//! 44..=47, or P/N=1) are never points. Every Common Address seen in a
//! server-side ASDU is still recorded in [`Inventory::cas`] so the
//! responder can tell a known-but-empty station from an unknown one.
//!
//! When answering an interrogation the stored point is converted to its
//! *interrogation form* ([`interrogation_type`]): time-tagged variants
//! map to their untimed equivalents and the time tag is stripped, since
//! interrogated data is sent without time tags. Protection-equipment
//! events (17..=19, 38..=40) have no untimed form and are never
//! interrogated. Integrated totals (15, 16, 37) answer Counter
//! Interrogation only.

use std::collections::{BTreeMap, BTreeSet};

use crate::apci;
use crate::asdu::{
    common_address, cot_value, element_len, read_ioa, rewrite_asdu, vsq, RewriteMap, DUI_LEN,
    IOA_LEN,
};

/// One point in the per-slave database.
#[derive(Debug, Clone)]
pub struct InventoryEntry {
    /// Type ID as last observed on the wire.
    pub type_id: u8,
    /// Element body bytes as last observed — everything after the IOA,
    /// up to but not including the next IOA (or end of ASDU).
    pub element_body: Vec<u8>,
    /// Monitor groups (1..16) this IOA belongs to, inferred from any
    /// COT in 21..36 the IOA was seen with. Empty means "only Station
    /// GI eligible" (QOI=20 still returns it).
    pub gi_groups: BTreeSet<u8>,
    /// Counter groups (1..4) this IOA belongs to, inferred from any
    /// COT in 38..41 the IOA was seen with.
    pub ci_groups: BTreeSet<u8>,
}

impl InventoryEntry {
    /// Type ID and element body to use in an interrogation response:
    /// the untimed equivalent of the observed type, with the time tag
    /// stripped. `None` for types that are never interrogated.
    pub fn interrogation_form(&self) -> Option<(u8, &[u8])> {
        let t = interrogation_type(self.type_id)?;
        let len = element_len(t)?;
        self.element_body.get(..len).map(|body| (t, body))
    }

    /// Answers General Interrogation (station or group).
    pub fn is_gi_point(&self) -> bool {
        matches!(interrogation_type(self.type_id), Some(t) if !is_counter_type(t))
    }

    /// Answers Counter Interrogation (integrated totals).
    pub fn is_counter(&self) -> bool {
        is_counter_type(self.type_id)
    }
}

/// Monitor-direction process-information type IDs that the inventory
/// stores: 1..=21 and 30..=40.
pub fn is_monitor_process_type(type_id: u8) -> bool {
    matches!(type_id, 1..=21 | 30..=40)
}

/// Integrated totals: M_IT_NA_1 (15), M_IT_TA_1 (16), M_IT_TB_1 (37).
pub fn is_counter_type(type_id: u8) -> bool {
    matches!(type_id, 15 | 16 | 37)
}

/// Untimed type used to report a point in an interrogation response.
///
/// CP24 (2..=16 even) and CP56 (30..=37) time-tagged types map to their
/// untimed counterparts; untimed types (1..=15 odd, 20, 21) map to
/// themselves. Protection events (17..=19, 38..=40) and everything else
/// return `None`.
pub fn interrogation_type(type_id: u8) -> Option<u8> {
    Some(match type_id {
        1 | 3 | 5 | 7 | 9 | 11 | 13 | 15 | 20 | 21 => type_id,
        2 | 4 | 6 | 8 | 10 | 12 | 14 | 16 => type_id - 1,
        30 => 1,  // M_SP_TB_1 -> M_SP_NA_1
        31 => 3,  // M_DP_TB_1 -> M_DP_NA_1
        32 => 5,  // M_ST_TB_1 -> M_ST_NA_1
        33 => 7,  // M_BO_TB_1 -> M_BO_NA_1
        34 => 9,  // M_ME_TD_1 -> M_ME_NA_1
        35 => 11, // M_ME_TE_1 -> M_ME_NB_1
        36 => 13, // M_ME_TF_1 -> M_ME_NC_1
        37 => 15, // M_IT_TB_1 -> M_IT_NA_1
        _ => return None,
    })
}

/// Common Address 0xFFFF is the broadcast address; it never names a
/// station.
pub const CA_BROADCAST: u16 = 0xFFFF;

/// Per-slave point database. Keyed by (Common Address, IOA).
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub entries: BTreeMap<(u16, u32), InventoryEntry>,
    /// Every station Common Address seen in an ingested ASDU (any type,
    /// including stations that reported no points). Excludes the
    /// broadcast address.
    pub cas: BTreeSet<u16>,
}

// Cause-of-transmission ranges per IEC 60870-5-101 §7.2.3.
const COT_INROGEN_STATION: u8 = 20;
const COT_INROGEN_GROUP_FIRST: u8 = 21; // group 1
const COT_INROGEN_GROUP_LAST: u8 = 36; // group 16
const COT_REQCOGEN: u8 = 37; // counters, all
const COT_REQCO_GROUP_FIRST: u8 = 38; // counter group 1
const COT_REQCO_GROUP_LAST: u8 = 41; // counter group 4

impl Inventory {
    /// Walk a captured server-side byte stream and update the database
    /// in place. Framing goes through [`apci::frames`], so a leading
    /// partial frame (mid-flow capture), junk after a gap, or a
    /// truncated tail is skipped and ingestion continues at the next
    /// valid frame boundary.
    pub fn ingest_payload(&mut self, payload: &[u8]) {
        for asdu in apci::frames(payload).filter_map(|f| f.asdu()) {
            self.ingest_asdu(asdu);
        }
    }

    /// Like [`Inventory::ingest_payload`], but applies `map` to each
    /// ASDU first, so the inventory is keyed by the Common Addresses
    /// and IOAs the live peer will actually see.
    pub fn ingest_payload_rewritten(&mut self, payload: &[u8], map: &RewriteMap) {
        if map.is_empty() {
            return self.ingest_payload(payload);
        }
        for asdu in apci::frames(payload).filter_map(|f| f.asdu()) {
            let mut owned = asdu.to_vec();
            rewrite_asdu(&mut owned, map);
            self.ingest_asdu(&owned);
        }
    }

    /// Ingest one ASDU. Public for callers that already hold framed
    /// ASDUs (e.g. the replayer's extracted, rewritten I-frames).
    pub fn ingest_asdu(&mut self, asdu: &[u8]) {
        if asdu.len() < DUI_LEN {
            return;
        }
        let type_id = asdu[0];
        let ca = common_address(asdu);
        if ca == CA_BROADCAST {
            return;
        }
        self.cas.insert(ca);

        if !is_monitor_process_type(type_id) {
            return;
        }
        let cot = cot_value(asdu);
        let negative = asdu[2] & 0x40 != 0;
        if negative || matches!(cot, 0 | 6..=10 | 44..=47) {
            return;
        }
        let Some(elem) = element_len(type_id) else {
            return;
        };
        let (sq, n) = vsq(asdu);
        let n = n as usize;

        if sq {
            // One IOA at offset DUI_LEN; subsequent elements have
            // implicit IOA = base_ioa + i.
            if asdu.len() < DUI_LEN + IOA_LEN {
                return;
            }
            let base_ioa = read_ioa(asdu, DUI_LEN);
            let body_start = DUI_LEN + IOA_LEN;
            for i in 0..n {
                let off = body_start + i * elem;
                if off + elem > asdu.len() {
                    break;
                }
                let ioa = base_ioa.wrapping_add(i as u32) & 0x00ff_ffff;
                self.upsert(ca, ioa, type_id, &asdu[off..off + elem], cot);
            }
        } else {
            // N full (IOA, body) pairs.
            let stride = IOA_LEN + elem;
            for i in 0..n {
                let off = DUI_LEN + i * stride;
                if off + stride > asdu.len() {
                    break;
                }
                let ioa = read_ioa(asdu, off);
                self.upsert(ca, ioa, type_id, &asdu[off + IOA_LEN..off + stride], cot);
            }
        }
    }

    fn upsert(&mut self, ca: u16, ioa: u32, type_id: u8, body: &[u8], cot: u8) {
        let entry = self
            .entries
            .entry((ca, ioa))
            .or_insert_with(|| InventoryEntry {
                type_id,
                element_body: Vec::new(),
                gi_groups: BTreeSet::new(),
                ci_groups: BTreeSet::new(),
            });
        // Latest wins for type + body (a real RTU's current value).
        entry.type_id = type_id;
        entry.element_body.clear();
        entry.element_body.extend_from_slice(body);
        // Group inference.
        match cot {
            COT_INROGEN_STATION => { /* station GI; no specific group */ }
            c if (COT_INROGEN_GROUP_FIRST..=COT_INROGEN_GROUP_LAST).contains(&c) => {
                entry.gi_groups.insert(c - COT_INROGEN_STATION); // 1..16
            }
            COT_REQCOGEN => { /* general counter; no specific group */ }
            c if (COT_REQCO_GROUP_FIRST..=COT_REQCO_GROUP_LAST).contains(&c) => {
                entry.ci_groups.insert(c - (COT_REQCO_GROUP_FIRST - 1)); // 1..4
            }
            _ => {}
        }
    }

    /// Total points across all CAs.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Was `ca` seen as a station address in the capture?
    pub fn knows_ca(&self, ca: u16) -> bool {
        self.cas.contains(&ca)
    }

    fn entries_for_ca(&self, ca: u16) -> impl Iterator<Item = ((u16, u32), &InventoryEntry)> {
        self.entries
            .range((ca, 0)..=(ca, u32::MAX))
            .map(|(k, v)| (*k, v))
    }

    /// Points of station `ca` that answer a General Interrogation with
    /// the given QOI: 20 = station (every GI point), 21..=36 = group
    /// 1..=16 (points whose `gi_groups` contains the group). Counters
    /// and protection events are never included. Any other QOI returns
    /// an empty list; the responder rejects it before asking.
    pub fn entries_for_gi(&self, ca: u16, qoi: u8) -> Vec<((u16, u32), &InventoryEntry)> {
        let group = match qoi {
            20 => None,
            21..=36 => Some(qoi - 20),
            _ => return Vec::new(),
        };
        self.entries_for_ca(ca)
            .filter(|(_, e)| e.is_gi_point())
            .filter(|(_, e)| group.is_none_or(|g| e.gi_groups.contains(&g)))
            .collect()
    }

    /// Counters of station `ca` that answer a Counter Interrogation.
    /// Only the request qualifier (RQT, low 6 bits of QCC) matters
    /// here: 5 = general (every counter), 1..=4 = counter group 1..=4.
    /// Any other RQT returns an empty list.
    pub fn entries_for_ci(&self, ca: u16, qcc: u8) -> Vec<((u16, u32), &InventoryEntry)> {
        let group = match qcc & 0x3f {
            5 => None,
            g @ 1..=4 => Some(g),
            _ => return Vec::new(),
        };
        self.entries_for_ca(ca)
            .filter(|(_, e)| e.is_counter())
            .filter(|(_, e)| group.is_none_or(|g| e.ci_groups.contains(&g)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::Apdu;
    use crate::asdu::write_ioa;

    /// One-object SQ=0 ASDU.
    fn asdu(type_id: u8, cot: u8, ca: u16, ioa: u32, body: &[u8]) -> Vec<u8> {
        let mut a = vec![type_id, 1, cot, 0, ca as u8, (ca >> 8) as u8, 0, 0, 0];
        write_ioa(&mut a, DUI_LEN, ioa);
        a.extend_from_slice(body);
        a
    }

    fn wrap(ns: u16, a: &[u8]) -> Vec<u8> {
        Apdu::I {
            ns,
            nr: 0,
            asdu: a.to_vec(),
        }
        .serialize()
    }

    fn sp_stream(n: u32) -> Vec<u8> {
        let mut s = Vec::new();
        for i in 0..n {
            s.extend(wrap(i as u16, &asdu(1, 20, 1, 100 + i, &[1])));
        }
        s
    }

    #[test]
    fn mid_flow_prefix_does_not_empty_the_inventory() {
        // Audit repro: 4 tail bytes with a stray 0x68 / length 1.
        let mut s = vec![0x12, 0x68, 0x01, 0x00];
        s.extend(sp_stream(10));
        let mut inv = Inventory::default();
        inv.ingest_payload(&s);
        assert_eq!(inv.len(), 10);
    }

    /// Port of the audit's resync simulation: M_ME_NC_1 / M_SP_NA_1 /
    /// M_IT_NA_1 frames whose values are full of 0x68 bytes, cut at
    /// every offset inside the first frame. Every point after the cut
    /// frame must be recovered with its exact value.
    #[test]
    fn cut_anywhere_in_first_frame_recovers_the_rest() {
        let mut seed = 0x6868_1234u32;
        let mut rnd = || {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let b = (seed >> 16) as u8;
            // One value byte in eight is 0x68: far denser than real
            // data (about 1 in 256), so stray start bytes are common.
            if b & 7 == 0 {
                0x68
            } else {
                b
            }
        };
        let mut s = Vec::new();
        let mut first_len = 0;
        for i in 0..40u32 {
            let a = match i % 3 {
                0 => asdu(13, 3, 1, 0x68 + i, &[rnd(), rnd(), rnd(), rnd(), 0]),
                1 => asdu(1, 20, 1, 0x68 + i, &[rnd() & 1]),
                _ => asdu(15, 37, 1, 0x68 + i, &[rnd(), rnd(), rnd(), rnd(), 0x68]),
            };
            let f = wrap(i as u16, &a);
            if i == 0 {
                first_len = f.len();
            }
            s.extend(f);
        }
        let mut clean = Inventory::default();
        clean.ingest_payload(&s);
        assert_eq!(clean.len(), 40);
        for cut in 1..first_len {
            let mut inv = Inventory::default();
            inv.ingest_payload(&s[cut..]);
            let mut want = clean.entries.clone();
            want.remove(&(1, 0x68));
            assert_eq!(inv.len(), 39, "cut at {cut}");
            for (k, e) in &want {
                assert_eq!(inv.entries[k].element_body, e.element_body, "cut {cut}");
            }
        }
    }

    #[test]
    fn junk_mid_stream_and_truncated_tail_are_skipped() {
        let mut s = sp_stream(5);
        s.extend([0x68, 0xff, 0x00, 0x68]);
        for i in 5..10u32 {
            s.extend(wrap(i as u16, &asdu(1, 20, 1, 100 + i, &[1])));
        }
        let tail = wrap(10, &asdu(1, 20, 1, 999, &[1]));
        s.extend(&tail[..tail.len() - 2]);
        let mut inv = Inventory::default();
        inv.ingest_payload(&s);
        assert_eq!(inv.len(), 10);
        assert!(!inv.entries.contains_key(&(1, 999)));
    }

    #[test]
    fn non_monitor_types_are_not_points() {
        let mut inv = Inventory::default();
        inv.ingest_asdu(&asdu(70, 4, 1, 0, &[0])); // M_EI_NA_1
        inv.ingest_asdu(&asdu(45, 7, 1, 5000, &[0x81])); // C_SC_NA_1 ActCon
        inv.ingest_asdu(&asdu(100, 7, 1, 0, &[20])); // C_IC_NA_1 ActCon
        inv.ingest_asdu(&asdu(103, 7, 1, 0, &[0; 7])); // C_CS_NA_1
        inv.ingest_asdu(&asdu(110, 7, 1, 1, &[0, 0, 1])); // P_ME_NA_1
        assert!(inv.is_empty());
        assert!(inv.knows_ca(1), "CA is known even with no points");
    }

    #[test]
    fn confirmation_and_negative_cots_are_not_points() {
        let mut inv = Inventory::default();
        for cot in [6u8, 7, 10, 44, 45, 46, 47] {
            inv.ingest_asdu(&asdu(1, cot, 1, cot as u32, &[1]));
        }
        inv.ingest_asdu(&asdu(1, 3 | 0x40, 1, 77, &[1])); // P/N=1
        assert!(inv.is_empty());
        inv.ingest_asdu(&asdu(1, 3, 1, 78, &[1]));
        assert_eq!(inv.len(), 1);
    }

    #[test]
    fn broadcast_ca_is_never_a_station() {
        let mut inv = Inventory::default();
        inv.ingest_asdu(&asdu(1, 20, CA_BROADCAST, 1, &[1]));
        assert!(inv.is_empty());
        assert!(inv.cas.is_empty());
    }

    #[test]
    fn counters_only_in_ci_and_events_never_interrogated() {
        let mut inv = Inventory::default();
        inv.ingest_asdu(&asdu(15, 37, 1, 7000, &[1, 0, 0, 0, 0])); // M_IT_NA_1
        inv.ingest_asdu(&asdu(37, 3, 1, 7001, &[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        inv.ingest_asdu(&asdu(16, 3, 1, 7002, &[3, 0, 0, 0, 0, 0, 0, 0]));
        inv.ingest_asdu(&asdu(38, 3, 1, 8000, &[0; 10])); // M_EP_TD_1
        inv.ingest_asdu(&asdu(17, 3, 1, 8001, &[0; 6])); // M_EP_TA_1
        inv.ingest_asdu(&asdu(13, 20, 1, 9000, &[0, 0, 0, 0, 0]));
        assert_eq!(inv.len(), 6);
        let gi: Vec<u32> = inv.entries_for_gi(1, 20).iter().map(|e| e.0 .1).collect();
        assert_eq!(gi, vec![9000]);
        let ci: Vec<u32> = inv.entries_for_ci(1, 5).iter().map(|e| e.0 .1).collect();
        assert_eq!(ci, vec![7000, 7001, 7002]);
        for (_, e) in inv.entries_for_ci(1, 5) {
            let (t, body) = e.interrogation_form().unwrap();
            assert_eq!(t, 15);
            assert_eq!(body.len(), 5);
        }
    }

    #[test]
    fn timed_types_map_to_untimed_and_latest_value_wins() {
        let mut inv = Inventory::default();
        // Seen in the initial GI as M_SP_NA_1 (off), then spontaneously
        // as M_SP_TB_1 (on, with a CP56 stamp).
        inv.ingest_asdu(&asdu(1, 20, 1, 10, &[0]));
        inv.ingest_asdu(&asdu(30, 3, 1, 10, &[1, 9, 9, 9, 9, 9, 9, 9]));
        let e = &inv.entries[&(1, 10)];
        assert_eq!(e.type_id, 30, "observed type is kept");
        assert_eq!(e.interrogation_form(), Some((1, &[1u8][..])));
        // Every CP56 and CP24 variant.
        #[rustfmt::skip]
        let pairs = [
            (2, 1), (4, 3), (6, 5), (8, 7), (10, 9), (12, 11), (14, 13), (16, 15),
            (30, 1), (31, 3), (32, 5), (33, 7), (34, 9), (35, 11), (36, 13), (37, 15),
            (20, 20), (21, 21),
        ];
        for (timed, untimed) in pairs {
            assert_eq!(interrogation_type(timed), Some(untimed), "type {timed}");
        }
        for t in [17u8, 18, 19, 38, 39, 40, 45, 70, 100] {
            assert_eq!(interrogation_type(t), None, "type {t}");
        }
    }

    #[test]
    fn gi_filters_by_ca_and_group() {
        let mut inv = Inventory::default();
        inv.ingest_asdu(&asdu(1, 20, 1, 100, &[1]));
        inv.ingest_asdu(&asdu(1, 20, 2, 100, &[0]));
        inv.ingest_asdu(&asdu(1, 22, 2, 101, &[0]));
        assert_eq!(inv.entries_for_gi(1, 20).len(), 1);
        assert_eq!(inv.entries_for_gi(2, 20).len(), 2);
        assert_eq!(inv.entries_for_gi(2, 22).len(), 1);
        assert_eq!(inv.entries_for_gi(2, 21).len(), 0);
        assert_eq!(inv.entries_for_gi(3, 20).len(), 0);
        assert_eq!(inv.entries_for_gi(1, 0).len(), 0);
        assert_eq!(inv.cas.iter().copied().collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn m_me_nd_1_and_sq1_sequences_are_ingested() {
        let mut inv = Inventory::default();
        // M_ME_ND_1 (21), SQ=1, N=3, base IOA 500: 3 × 2-octet NVA.
        let mut a = vec![21, 0x83, 20, 0, 1, 0];
        a.extend_from_slice(&[0xf4, 0x01, 0x00]);
        a.extend_from_slice(&[1, 0, 2, 0, 3, 0]);
        inv.ingest_asdu(&a);
        assert_eq!(inv.len(), 3);
        assert_eq!(inv.entries[&(1, 502)].element_body, vec![3, 0]);
        assert_eq!(inv.entries_for_gi(1, 20).len(), 3);
    }

    #[test]
    fn rewritten_ingest_uses_target_addresses() {
        let mut map = RewriteMap::default();
        map.common_address.insert(1, 42);
        map.ioa.insert(100, 200);
        let mut inv = Inventory::default();
        inv.ingest_payload_rewritten(&sp_stream(1), &map);
        assert!(inv.knows_ca(42));
        assert!(!inv.knows_ca(1));
        assert!(inv.entries.contains_key(&(42, 200)));
    }
}
