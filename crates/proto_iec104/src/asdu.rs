//! IEC 60870-5-101/104 ASDU parsing and in-place rewriting.
//!
//! Scope of v1: walk the Data Unit Identifier and information object
//! list well enough to remap COT, Common Address, and IOA values
//! against a user-supplied `RewriteMap`. Rewrites are done in place —
//! all target values are the same wire width as the originals (2-byte
//! COT, 2-byte CA, 3-byte IOA), so rewriting never changes ASDU size.
//!
//! Structure, IEC 104 profile:
//!
//! ```text
//!  0           1       2       3       4       5     6 ...
//!  ┌────────┬────────┬───────┬───────┬───────┬───────┐
//!  │Type ID │  VSQ   │ COT_L │ COT_H │  CA_L │  CA_H │  <-- DUI (6 bytes)
//!  └────────┴────────┴───────┴───────┴───────┴───────┘
//!   ┌─────────────┬─────────────────────────────────┐
//!   │ IOA (3 B)   │   information element set       │
//!   └─────────────┴─────────────────────────────────┘
//! ```
//!
//! When `VSQ.SQ = 1`, there is one IOA followed by `N` consecutive
//! information elements whose effective IOAs are `base, base+1, ...`.
//! When `VSQ.SQ = 0`, there are `N` full objects, each with its own IOA.
//!
//! Element sizes are type-specific. We ship a small table for the most
//! common IEC 104 types used in SCADA traffic. For unknown type IDs,
//! we fall back to rewriting the first IOA only and leave the rest of
//! the ASDU alone — conservative is fine; any type not in the table is
//! an exotic one that a production deployment can add in a follow-up.

use std::collections::HashMap;

use anyhow::{bail, Result};
use serde::Deserialize;

pub const DUI_LEN: usize = 6;
pub const IOA_LEN: usize = 3;

/// User-supplied rewrite map, parsed from [`ProtoRunCfg::proto_config`].
///
/// Keys in the JSON payload are always strings (JSON object key
/// constraint). We parse them as integers here so the matching code
/// never touches strings.
#[derive(Debug, Clone, Default)]
pub struct RewriteMap {
    pub common_address: HashMap<u16, u16>,
    pub cot: HashMap<u8, u8>,
    pub ioa: HashMap<u32, u32>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RawRewriteMap {
    #[serde(default)]
    common_address: HashMap<String, u16>,
    #[serde(default)]
    cot: HashMap<String, u8>,
    #[serde(default)]
    ioa: HashMap<String, u32>,
}

impl RewriteMap {
    pub fn is_empty(&self) -> bool {
        self.common_address.is_empty() && self.cot.is_empty() && self.ioa.is_empty()
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let raw: RawRewriteMap = serde_json::from_str(json)?;
        let mut out = Self::default();
        for (k, v) in raw.common_address {
            let k: u16 = k.parse().map_err(|e| anyhow::anyhow!("bad common_address key {k}: {e}"))?;
            out.common_address.insert(k, v);
        }
        for (k, v) in raw.cot {
            let k: u8 = k.parse().map_err(|e| anyhow::anyhow!("bad cot key {k}: {e}"))?;
            out.cot.insert(k, v);
        }
        for (k, v) in raw.ioa {
            let k: u32 = k.parse().map_err(|e| anyhow::anyhow!("bad ioa key {k}: {e}"))?;
            out.ioa.insert(k, v);
        }
        Ok(out)
    }
}

/// Read the low 6 bits of the COT byte (the cause value).
#[inline]
pub fn cot_value(dui: &[u8]) -> u8 {
    dui[2] & 0x3f
}

/// Read the Common Address from the DUI (little-endian 2 bytes).
#[inline]
pub fn common_address(dui: &[u8]) -> u16 {
    u16::from_le_bytes([dui[4], dui[5]])
}

/// Variable Structure Qualifier: (sq, n).
#[inline]
pub fn vsq(dui: &[u8]) -> (bool, u8) {
    let vsq = dui[1];
    (vsq & 0x80 != 0, vsq & 0x7f)
}

/// Read a 3-byte little-endian IOA at `offset` in the ASDU buffer.
#[inline]
pub fn read_ioa(asdu: &[u8], offset: usize) -> u32 {
    (asdu[offset] as u32) | ((asdu[offset + 1] as u32) << 8) | ((asdu[offset + 2] as u32) << 16)
}

/// Write a 3-byte little-endian IOA at `offset`.
#[inline]
pub fn write_ioa(asdu: &mut [u8], offset: usize, ioa: u32) {
    asdu[offset] = (ioa & 0xff) as u8;
    asdu[offset + 1] = ((ioa >> 8) & 0xff) as u8;
    asdu[offset + 2] = ((ioa >> 16) & 0xff) as u8;
}

/// Information element size (bytes) for a Type ID, **excluding** the
/// 3-byte IOA. Returns `None` for types we don't know how to step
/// through.
pub fn element_len(type_id: u8) -> Option<usize> {
    // Only the types we can walk safely. Names are from IEC 60870-5-101.
    Some(match type_id {
        1   => 1,        // M_SP_NA_1 — SIQ
        2   => 1 + 3,    // M_SP_TA_1 — SIQ + CP24Time2a
        3   => 1,        // M_DP_NA_1 — DIQ
        4   => 1 + 3,    // M_DP_TA_1 — DIQ + CP24
        5   => 1 + 1,    // M_ST_NA_1 — VTI + QDS
        6   => 1 + 1 + 3,// M_ST_TA_1 — VTI + QDS + CP24
        7   => 4 + 1,    // M_BO_NA_1 — BSI + QDS
        8   => 4 + 1 + 3,// M_BO_TA_1 — BSI + QDS + CP24
        9   => 2 + 1,    // M_ME_NA_1 — NVA + QDS
        10  => 2 + 1 + 3,// M_ME_TA_1 — NVA + QDS + CP24
        11  => 2 + 1,    // M_ME_NB_1 — SVA + QDS
        12  => 2 + 1 + 3,// M_ME_TB_1 — SVA + QDS + CP24
        13  => 4 + 1,    // M_ME_NC_1 — float + QDS
        14  => 4 + 1 + 3,// M_ME_TC_1 — float + QDS + CP24
        15  => 4 + 1,    // M_IT_NA_1 — BCR
        16  => 4 + 1 + 3,// M_IT_TA_1 — BCR + CP24
        30  => 1 + 7,    // M_SP_TB_1 — SIQ + CP56Time2a
        31  => 1 + 7,    // M_DP_TB_1 — DIQ + CP56
        32  => 1 + 1 + 7,// M_ST_TB_1 — VTI + QDS + CP56
        33  => 4 + 1 + 7,// M_BO_TB_1 — BSI + QDS + CP56
        34  => 2 + 1 + 7,// M_ME_TD_1 — NVA + QDS + CP56
        35  => 2 + 1 + 7,// M_ME_TE_1 — SVA + QDS + CP56
        36  => 4 + 1 + 7,// M_ME_TF_1 — float + QDS + CP56
        37  => 4 + 1 + 7,// M_IT_TB_1 — BCR + CP56
        45  => 1,        // C_SC_NA_1 — SCO
        46  => 1,        // C_DC_NA_1 — DCO
        47  => 1,        // C_RC_NA_1 — RCO
        48  => 2 + 1,    // C_SE_NA_1 — NVA + QOS
        49  => 2 + 1,    // C_SE_NB_1 — SVA + QOS
        50  => 4 + 1,    // C_SE_NC_1 — float + QOS
        51  => 4,        // C_BO_NA_1 — BSI
        58  => 1 + 7,    // C_SC_TA_1 — SCO + CP56
        59  => 1 + 7,    // C_DC_TA_1 — DCO + CP56
        60  => 1 + 7,    // C_RC_TA_1 — RCO + CP56
        61  => 2 + 1 + 7,// C_SE_TA_1 — NVA + QOS + CP56
        62  => 2 + 1 + 7,// C_SE_TB_1 — SVA + QOS + CP56
        63  => 4 + 1 + 7,// C_SE_TC_1 — float + QOS + CP56
        64  => 4 + 7,    // C_BO_TA_1 — BSI + CP56
        70  => 1,        // M_EI_NA_1 — COI
        100 => 1,        // C_IC_NA_1 — QOI
        101 => 1,        // C_CI_NA_1 — QCC
        102 => 0,        // C_RD_NA_1 — no element
        103 => 7,        // C_CS_NA_1 — CP56Time2a
        104 => 1,        // C_TS_NA_1 — FBP (obsolete)
        105 => 1,        // C_RP_NA_1 — QRP
        106 => 3,        // C_CD_NA_1 — CP16Time2a
        107 => 1 + 7,    // C_TS_TA_1 — TSC + CP56
        _ => return None,
    })
}

/// Apply `map` to `asdu` in place. No-op if `map.is_empty()`.
///
/// Returns the number of fields rewritten (for logging/metrics).
pub fn rewrite_asdu(asdu: &mut [u8], map: &RewriteMap) -> usize {
    if map.is_empty() || asdu.len() < DUI_LEN {
        return 0;
    }
    let mut rewrites = 0usize;

    // --- DUI ---
    let type_id = asdu[0];
    let (sq, n) = vsq(asdu);
    let n = n as usize;

    // COT low 6 bits
    let cot = cot_value(asdu);
    if let Some(new_cot) = map.cot.get(&cot) {
        let flags = asdu[2] & 0xc0;
        asdu[2] = flags | (new_cot & 0x3f);
        rewrites += 1;
    }
    // Common Address
    let ca = common_address(asdu);
    if let Some(new_ca) = map.common_address.get(&ca) {
        asdu[4] = (*new_ca & 0xff) as u8;
        asdu[5] = (*new_ca >> 8) as u8;
        rewrites += 1;
    }

    // --- Info object IOAs ---
    if map.ioa.is_empty() || n == 0 {
        return rewrites;
    }

    if sq {
        // One IOA at offset 6; effective IOAs are ioa, ioa+1, ... ioa+n-1.
        // We remap only the starting IOA: remapping a sequence element by
        // element would change the sequence semantics anyway.
        if asdu.len() >= DUI_LEN + IOA_LEN {
            let base = read_ioa(asdu, DUI_LEN);
            if let Some(new_base) = map.ioa.get(&base) {
                write_ioa(asdu, DUI_LEN, *new_base);
                rewrites += 1;
            }
        }
    } else {
        // N full objects at offset 6, each `IOA_LEN + element_len(type)`.
        let Some(elem) = element_len(type_id) else {
            // Unknown type — rewrite the first IOA only.
            if asdu.len() >= DUI_LEN + IOA_LEN {
                let ioa = read_ioa(asdu, DUI_LEN);
                if let Some(new_ioa) = map.ioa.get(&ioa) {
                    write_ioa(asdu, DUI_LEN, *new_ioa);
                    rewrites += 1;
                }
            }
            return rewrites;
        };
        let stride = IOA_LEN + elem;
        let mut off = DUI_LEN;
        for _ in 0..n {
            if off + IOA_LEN > asdu.len() {
                break;
            }
            let ioa = read_ioa(asdu, off);
            if let Some(new_ioa) = map.ioa.get(&ioa) {
                write_ioa(asdu, off, *new_ioa);
                rewrites += 1;
            }
            off += stride;
            if off > asdu.len() {
                break;
            }
        }
    }

    rewrites
}

/// Parse the JSON proto_config into a [`RewriteMap`]. Returns an empty
/// map if the JSON is `null` or an empty object. Used by
/// [`crate::session`].
pub fn load_rewrite_map(proto_config: Option<&str>) -> Result<RewriteMap> {
    let Some(s) = proto_config else {
        return Ok(RewriteMap::default());
    };
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed == "null" || trimmed == "{}" {
        return Ok(RewriteMap::default());
    }
    RewriteMap::from_json(trimmed)
}

/// Convenience for tests and callers that already hold a map in memory.
pub fn rewrite_or_skip(asdu: &mut Vec<u8>, map: &RewriteMap) -> Result<usize> {
    if asdu.len() < DUI_LEN {
        bail!("asdu too short: {} bytes", asdu.len());
    }
    Ok(rewrite_asdu(asdu, map))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_empty_map_is_noop() {
        let mut asdu = vec![0x0d, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let orig = asdu.clone();
        let map = RewriteMap::default();
        assert_eq!(rewrite_asdu(&mut asdu, &map), 0);
        assert_eq!(asdu, orig);
    }

    #[test]
    fn rewrite_common_address() {
        // Type 13, VSQ=1 (one object, SQ=0), COT=3, CA=1, IOA=1
        let mut asdu = vec![
            13,   // type
            0x01, // VSQ: SQ=0, N=1
            0x03, 0x00, // COT=3
            0x01, 0x00, // CA=1
            0x01, 0x00, 0x00, // IOA=1
            0x00, 0x00, 0x00, 0x00, 0x00, // M_ME_NC_1 body: 4 bytes float + 1 byte QDS
        ];
        let mut map = RewriteMap::default();
        map.common_address.insert(1, 42);
        assert_eq!(rewrite_asdu(&mut asdu, &map), 1);
        assert_eq!(common_address(&asdu), 42);
    }

    #[test]
    fn rewrite_cot_preserves_flags() {
        let mut asdu = vec![
            1, 0x01,
            0xC0 | 6, 0x00, // COT=6 with both P/N and T flags set
            0x01, 0x00,
            0x02, 0x00, 0x00,
            0x00,
        ];
        let mut map = RewriteMap::default();
        map.cot.insert(6, 20);
        assert_eq!(rewrite_asdu(&mut asdu, &map), 1);
        assert_eq!(cot_value(&asdu), 20);
        // flags preserved
        assert_eq!(asdu[2] & 0xC0, 0xC0);
    }

    #[test]
    fn rewrite_multiple_ioas_type1_sq0() {
        // Type 1 (M_SP_NA_1, 1-byte element), SQ=0, N=3.
        // Three objects at offsets 6, 10, 14.
        let mut asdu = vec![
            1,    // type
            0x03, // SQ=0, N=3
            0x03, 0x00, 0x01, 0x00, // COT=3, CA=1
            0x01, 0x00, 0x00, 0x01, // IOA=1 + SIQ=0x01
            0x02, 0x00, 0x00, 0x02, // IOA=2 + SIQ=0x02
            0x03, 0x00, 0x00, 0x03, // IOA=3 + SIQ=0x03
        ];
        let mut map = RewriteMap::default();
        map.ioa.insert(1, 100);
        map.ioa.insert(3, 300);
        assert_eq!(rewrite_asdu(&mut asdu, &map), 2);
        assert_eq!(read_ioa(&asdu, 6), 100);
        assert_eq!(read_ioa(&asdu, 10), 2);
        assert_eq!(read_ioa(&asdu, 14), 300);
    }

    #[test]
    fn rewrite_ioa_sq1_rewrites_base_only() {
        // Type 13 (float+QDS = 5 bytes), SQ=1, N=4. Single base IOA.
        let mut asdu = vec![
            13,   // type
            0x84, // SQ=1, N=4
            0x03, 0x00, 0x01, 0x00, // COT=3, CA=1
            0x0a, 0x00, 0x00,       // base IOA=10
            // 4 elements × 5 bytes each
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut map = RewriteMap::default();
        map.ioa.insert(10, 500);
        assert_eq!(rewrite_asdu(&mut asdu, &map), 1);
        assert_eq!(read_ioa(&asdu, DUI_LEN), 500);
    }

    #[test]
    fn load_from_json_string_keys() {
        let json = r#"{
            "common_address": {"1": 100, "2": 200},
            "cot": {"3": 20},
            "ioa": {"10": 500, "11": 501}
        }"#;
        let m = RewriteMap::from_json(json).unwrap();
        assert_eq!(m.common_address.get(&1), Some(&100));
        assert_eq!(m.common_address.get(&2), Some(&200));
        assert_eq!(m.cot.get(&3), Some(&20));
        assert_eq!(m.ioa.get(&10), Some(&500));
        assert_eq!(m.ioa.get(&11), Some(&501));
    }

    #[test]
    fn load_rewrite_map_empty_cases() {
        assert!(load_rewrite_map(None).unwrap().is_empty());
        assert!(load_rewrite_map(Some("")).unwrap().is_empty());
        assert!(load_rewrite_map(Some("null")).unwrap().is_empty());
        assert!(load_rewrite_map(Some("{}")).unwrap().is_empty());
    }

    #[test]
    fn unknown_type_rewrites_first_ioa_only() {
        // Type 200 is not in the table. SQ=0, N=2.
        let mut asdu = vec![
            200,
            0x02,
            0x03, 0x00, 0x01, 0x00,
            0x0a, 0x00, 0x00,
            // unknown-length body — we don't touch this
            0xff, 0xff,
            0x0b, 0x00, 0x00,
            0xff, 0xff,
        ];
        let mut map = RewriteMap::default();
        map.ioa.insert(10, 999);
        map.ioa.insert(11, 888);
        // Should rewrite only the first IOA (conservative fallback).
        assert_eq!(rewrite_asdu(&mut asdu, &map), 1);
        assert_eq!(read_ioa(&asdu, DUI_LEN), 999);
    }
}
