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

use std::collections::{BTreeMap, BTreeSet};

use crate::apdu::{Apdu, ApduReader};
use crate::asdu::{
    common_address, cot_value, element_len, read_ioa, vsq, DUI_LEN, IOA_LEN,
};

/// One point in the per-slave database.
#[derive(Debug, Clone)]
pub struct InventoryEntry {
    /// Type ID (as last observed) used to format the response element.
    pub type_id: u8,
    /// Element body bytes — everything after the IOA, up to but not
    /// including the next IOA (or end of ASDU). For a single-element
    /// response this is appended verbatim after a freshly-built
    /// 3-byte IOA.
    pub element_body: Vec<u8>,
    /// Monitor groups (1..16) this IOA belongs to, inferred from any
    /// COT in 21..36 the IOA was seen with. Empty means "only Station
    /// GI eligible" (QOI=20 still returns it).
    pub gi_groups: BTreeSet<u8>,
    /// Counter groups (1..4) this IOA belongs to, inferred from any
    /// COT in 38..41 the IOA was seen with.
    pub ci_groups: BTreeSet<u8>,
}

/// Per-slave point database. Keyed by (Common Address, IOA).
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub entries: BTreeMap<(u16, u32), InventoryEntry>,
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
    /// in place. Tolerates mid-frame leading bytes — the underlying
    /// `ApduReader` skips them. Unknown ASDU type IDs are silently
    /// skipped (we have no element layout to walk them with).
    pub fn ingest_payload(&mut self, payload: &[u8]) {
        let mut reader = ApduReader::new(payload);
        loop {
            match reader.next_apdu() {
                Ok(Some(Apdu::I { asdu, .. })) => self.ingest_asdu(&asdu),
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }

    /// Ingest one ASDU. Public for testing; `ingest_payload` is the
    /// usual entry point.
    pub fn ingest_asdu(&mut self, asdu: &[u8]) {
        if asdu.len() < DUI_LEN {
            return;
        }
        let type_id = asdu[0];
        let Some(elem) = element_len(type_id) else {
            return;
        };
        let (sq, n) = vsq(asdu);
        let n = n as usize;
        if n == 0 {
            return;
        }
        let cot = cot_value(asdu);
        let ca = common_address(asdu);

        // Skip command/system request frames — those are master
        // commands, not point data.
        if (100..=107).contains(&type_id) {
            return;
        }

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
                let body = asdu[off..off + elem].to_vec();
                self.upsert(ca, base_ioa + i as u32, type_id, body, cot);
            }
        } else {
            // N full (IOA, body) pairs.
            let stride = IOA_LEN + elem;
            for i in 0..n {
                let off = DUI_LEN + i * stride;
                if off + IOA_LEN + elem > asdu.len() {
                    break;
                }
                let ioa = read_ioa(asdu, off);
                let body = asdu[off + IOA_LEN..off + IOA_LEN + elem].to_vec();
                self.upsert(ca, ioa, type_id, body, cot);
            }
        }
    }

    fn upsert(&mut self, ca: u16, ioa: u32, type_id: u8, body: Vec<u8>, cot: u8) {
        let entry = self
            .entries
            .entry((ca, ioa))
            .or_insert_with(|| InventoryEntry {
                type_id,
                element_body: body.clone(),
                gi_groups: BTreeSet::new(),
                ci_groups: BTreeSet::new(),
            });
        // Latest wins for type + body (a real RTU's current value).
        entry.type_id = type_id;
        entry.element_body = body;
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

    /// Total IOAs across all CAs.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// IOAs eligible to respond to a General Interrogation with the
    /// given QOI. QOI=20 returns every entry (Station GI). QOI=21..36
    /// filters to entries whose `gi_groups` contains the matching
    /// group number.
    pub fn entries_for_gi(&self, qoi: u8) -> Vec<((u16, u32), &InventoryEntry)> {
        match qoi {
            20 => self.entries.iter().map(|(k, v)| (*k, v)).collect(),
            g @ 21..=36 => {
                let group = g - 20;
                self.entries
                    .iter()
                    .filter(|(_, e)| e.gi_groups.contains(&group))
                    .map(|(k, v)| (*k, v))
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    /// IOAs eligible to respond to a Counter Interrogation with the
    /// given QCC. The 6-bit QCQ field selects: 5 = general (returns
    /// every counter type), 1..4 = counter group 1..4. Counter types
    /// are M_IT_NA_1 (15) and M_IT_TB_1 (37).
    pub fn entries_for_ci(&self, qcc: u8) -> Vec<((u16, u32), &InventoryEntry)> {
        let qcq = qcc & 0x3f;
        let only_counters = |e: &InventoryEntry| matches!(e.type_id, 15 | 37);
        match qcq {
            5 => self
                .entries
                .iter()
                .filter(|(_, e)| only_counters(e))
                .map(|(k, v)| (*k, v))
                .collect(),
            g @ 1..=4 => self
                .entries
                .iter()
                .filter(|(_, e)| only_counters(e) && e.ci_groups.contains(&g))
                .map(|(k, v)| (*k, v))
                .collect(),
            _ => Vec::new(),
        }
    }
}
