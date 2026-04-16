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

/// CP56Time2a (7-byte) time-tag offset within a single information
/// element, for ASDU types whose elements end with a CP56Time2a field.
/// Returns `None` for types without CP56Time2a (or that use the older
/// CP24Time2a — those are intentionally skipped, see `rewrite_cp56time2a_to_now`).
pub fn cp56_offset_in_element(type_id: u8) -> Option<usize> {
    // Every CP56-bearing type in the table above ends its element with
    // 7 bytes of CP56Time2a, so the offset is element_len - 7.
    match type_id {
        30 | 31 | 32 | 33 | 34 | 35 | 36 | 37
        | 58 | 59 | 60 | 61 | 62 | 63 | 64
        | 103 | 107 => element_len(type_id).map(|e| e - 7),
        _ => None,
    }
}

/// Timezone convention for encoding / decoding a CP56Time2a field.
///
/// IEC 60870-5-4 §6.8 does not mandate whether the seven bytes carry
/// UTC or local time — it's an implementation choice. In practice
/// ICCP links use UTC, while plant-level SCADA (Siemens, ABB, Schneider,
/// OSI) overwhelmingly use local time with the SU (summer-time) flag
/// set while DST is in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cp56Zone {
    /// Bytes encode UTC calendar components. SU flag is always 0.
    Utc,
    /// Bytes encode the server's **local** calendar components. SU flag
    /// follows the local timezone's current DST state (`tm_isdst`).
    Local,
}

impl Cp56Zone {
    pub fn as_str(self) -> &'static str {
        match self {
            Cp56Zone::Utc => "utc",
            Cp56Zone::Local => "local",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "utc" => Some(Cp56Zone::Utc),
            "local" => Some(Cp56Zone::Local),
            _ => None,
        }
    }
}

/// Break a Unix epoch seconds value into LOCAL calendar components
/// using the server's timezone. Returns `(year, month, day, hour, min,
/// sec, is_dst)` with year on the 0..99 scale that CP56 wants
/// (`year - 2000`, wrapped modulo 100). Uses libc::localtime_r.
fn break_local(unix_secs: i64) -> (u32, u32, u32, u32, u32, u32, bool) {
    let t: libc::time_t = unix_secs as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&t, &mut tm);
    }
    (
        (tm.tm_year as i64 + 1900) as u32,
        (tm.tm_mon + 1) as u32,
        tm.tm_mday as u32,
        tm.tm_hour as u32,
        tm.tm_min as u32,
        tm.tm_sec as u32,
        tm.tm_isdst > 0,
    )
}

/// Inverse of `break_local`: take local calendar components plus the
/// SU (DST) flag and return the Unix epoch seconds they represent.
/// Uses `libc::mktime`, which respects the server's local timezone
/// and `tm_isdst` when resolving ambiguous times at DST boundaries.
fn assemble_local(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32, su: bool) -> i64 {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = year as i32 - 1900;
    tm.tm_mon = month as i32 - 1;
    tm.tm_mday = day as i32;
    tm.tm_hour = hour as i32;
    tm.tm_min = minute as i32;
    tm.tm_sec = second as i32;
    tm.tm_isdst = if su { 1 } else { 0 };
    unsafe { libc::mktime(&mut tm) as i64 }
}

/// Encode a wall-clock instant as a CP56Time2a 7-byte field per
/// IEC 60870-5-4 §6.8, in UTC. Callers control IV (invalid) and SU
/// (summer time) flag bits — on rewrite of a captured ASDU, pass the
/// source bytes' IV/SU so data-quality / timezone semantics survive.
pub fn encode_cp56time2a(unix_ns: u64, iv: bool, su: bool) -> [u8; 7] {
    let total_secs = unix_ns / 1_000_000_000;
    let ns_in_sec = unix_ns % 1_000_000_000;
    let days = total_secs / 86_400;
    let secs_in_day = total_secs % 86_400;
    let hour = (secs_in_day / 3600) as u8;
    let minute = ((secs_in_day % 3600) / 60) as u8;
    let second = (secs_in_day % 60) as u8;
    let ms_in_min = (second as u32 * 1000) + (ns_in_sec / 1_000_000) as u32;
    debug_assert!(ms_in_min < 60_000);

    // Howard Hinnant's civil_from_days algorithm.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    if m <= 2 {
        y += 1;
    }

    // ISO weekday: 1970-01-01 was a Thursday (4). Mon=1..Sun=7.
    let dow = ((days + 3) % 7 + 1) as u8;

    let year_byte = ((y as i64 - 2000).rem_euclid(100) as u8) & 0x7f;
    let month_byte = m & 0x0f;
    let day_byte = ((dow & 0x07) << 5) | (d & 0x1f);
    let hour_byte = (if su { 0x80 } else { 0 }) | (hour & 0x1f);
    let min_byte = (if iv { 0x80 } else { 0 }) | (minute & 0x3f);

    [
        (ms_in_min & 0xff) as u8,
        ((ms_in_min >> 8) & 0xff) as u8,
        min_byte,
        hour_byte,
        day_byte,
        month_byte,
        year_byte,
    ]
}

/// Encode a wall-clock instant as a CP56Time2a 7-byte field in the
/// server's **local** timezone, setting the SU flag from the local
/// timezone's current DST state. IV (invalid) is caller-supplied
/// (propagate the source ASDU's IV bit on rewrite).
pub fn encode_cp56time2a_local(unix_ns: u64, iv: bool) -> [u8; 7] {
    let total_secs = unix_ns / 1_000_000_000;
    let ns_in_sec = unix_ns % 1_000_000_000;
    let (year, month, day, hour, minute, second, is_dst) = break_local(total_secs as i64);
    let ms_in_min = (second * 1000) + (ns_in_sec / 1_000_000) as u32;
    debug_assert!(ms_in_min < 60_000);

    // ISO weekday from the *local* calendar date (Mon=1..Sun=7).
    // Re-use break_local -> Howard Hinnant-style days_from_civil to
    // compute DOW; easiest is to call the UTC algorithm on a synthetic
    // unix_secs that is the local midnight of this day, but we already
    // have y/m/d so just compute directly.
    let dow = dow_from_ymd(year, month, day);

    let year_byte = ((year as i64 - 2000).rem_euclid(100) as u8) & 0x7f;
    let month_byte = (month as u8) & 0x0f;
    let day_byte = ((dow & 0x07) << 5) | ((day as u8) & 0x1f);
    let hour_byte = (if is_dst { 0x80 } else { 0 }) | ((hour as u8) & 0x1f);
    let min_byte = (if iv { 0x80 } else { 0 }) | ((minute as u8) & 0x3f);

    [
        (ms_in_min & 0xff) as u8,
        ((ms_in_min >> 8) & 0xff) as u8,
        min_byte,
        hour_byte,
        day_byte,
        month_byte,
        year_byte,
    ]
}

/// Day-of-week (Mon=1..Sun=7) from Gregorian year/month/day. Uses
/// Zeller-style math via Howard Hinnant's days_from_civil.
fn dow_from_ymd(year: u32, month: u32, day: u32) -> u8 {
    // Adapted from days_from_civil.
    let y = if month <= 2 { year - 1 } else { year } as i64;
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as i64;
    let m_adj = if month > 2 { month - 3 } else { month + 9 } as i64;
    let doy = (153 * m_adj + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    // 1970-01-01 was a Thursday (4 in ISO). Mon=1..Sun=7.
    let d = ((days + 3).rem_euclid(7) + 1) as u8;
    d
}

/// Decode a CP56Time2a field back to (unix_ns, iv, su). Used by the
/// analyzer to compare captured stamps against actual send times. The
/// day-of-week byte is ignored on decode (it's a derived field).
pub fn decode_cp56time2a(b: &[u8; 7]) -> (u64, bool, bool) {
    let ms_in_min = (b[0] as u32) | ((b[1] as u32) << 8);
    let iv = b[2] & 0x80 != 0;
    let minute = (b[2] & 0x3f) as u64;
    let su = b[3] & 0x80 != 0;
    let hour = (b[3] & 0x1f) as u64;
    let day = (b[4] & 0x1f) as u64;
    let month = (b[5] & 0x0f) as u64;
    let year = 2000u64 + (b[6] & 0x7f) as u64;

    // Howard Hinnant's days_from_civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let m_adj = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * m_adj + 2) / 5 + day.saturating_sub(1);
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    let second = (ms_in_min / 1000) as u64;
    let ms = (ms_in_min % 1000) as u64;
    let total_secs = days * 86_400 + hour * 3600 + minute * 60 + second;
    let unix_ns = total_secs * 1_000_000_000 + ms * 1_000_000;
    (unix_ns, iv, su)
}

/// Decode a CP56Time2a that was encoded in the server's local
/// timezone (SU bit indicates the DST state at encode time). Returns
/// (unix_ns, iv) — SU is consumed to resolve the ambiguity at DST
/// transitions and not returned separately.
pub fn decode_cp56time2a_local(b: &[u8; 7]) -> (u64, bool) {
    let ms_in_min = (b[0] as u32) | ((b[1] as u32) << 8);
    let iv = b[2] & 0x80 != 0;
    let minute = (b[2] & 0x3f) as u32;
    let su = b[3] & 0x80 != 0;
    let hour = (b[3] & 0x1f) as u32;
    let day = (b[4] & 0x1f) as u32;
    let month = (b[5] & 0x0f) as u32;
    let year = 2000u32 + (b[6] & 0x7f) as u32;

    let second = ms_in_min / 1000;
    let ms = ms_in_min % 1000;
    let secs = assemble_local(year, month, day, hour, minute, second, su);
    // `mktime` can return -1 on failure (out-of-range, missing TZ).
    // Clamp negative into 0 so the drift delta remains computable.
    let base_secs = if secs < 0 { 0 } else { secs as u64 };
    (base_secs * 1_000_000_000 + (ms as u64) * 1_000_000, iv)
}

/// Rewrite every CP56Time2a field inside the ASDU to `now_unix_ns`,
/// preserving the source IV (invalid) and SU (summer-time) flag bits
/// per element. Returns the number of timestamp fields rewritten.
///
/// Walks the ASDU using the same SQ=0 / SQ=1 layout rules as
/// [`rewrite_asdu`]. For unknown type IDs or types without a CP56
/// field, returns 0 with no mutation. CP24Time2a (3-byte, in M_*_TA_1
/// types) is intentionally NOT touched — see plan notes.
pub fn rewrite_cp56time2a_to_now(asdu: &mut [u8], now_unix_ns: u64) -> usize {
    if asdu.len() < DUI_LEN {
        return 0;
    }
    let type_id = asdu[0];
    let Some(cp56_off_in_elem) = cp56_offset_in_element(type_id) else {
        return 0;
    };
    let Some(elem) = element_len(type_id) else {
        return 0;
    };
    let (sq, n) = vsq(asdu);
    let n = n as usize;
    if n == 0 {
        return 0;
    }

    let mut rewrites = 0usize;
    if sq {
        // Single base IOA, then n consecutive elements of size `elem`.
        let mut off = DUI_LEN + IOA_LEN;
        for _ in 0..n {
            let cp_start = off + cp56_off_in_elem;
            if cp_start + 7 > asdu.len() {
                break;
            }
            let src: [u8; 7] = asdu[cp_start..cp_start + 7].try_into().unwrap();
            let iv = src[2] & 0x80 != 0;
            let su = src[3] & 0x80 != 0;
            let new = encode_cp56time2a(now_unix_ns, iv, su);
            asdu[cp_start..cp_start + 7].copy_from_slice(&new);
            rewrites += 1;
            off += elem;
        }
    } else {
        // n full objects, each `IOA_LEN + elem` bytes.
        let stride = IOA_LEN + elem;
        let mut off = DUI_LEN;
        for _ in 0..n {
            let cp_start = off + IOA_LEN + cp56_off_in_elem;
            if cp_start + 7 > asdu.len() {
                break;
            }
            let src: [u8; 7] = asdu[cp_start..cp_start + 7].try_into().unwrap();
            let iv = src[2] & 0x80 != 0;
            let su = src[3] & 0x80 != 0;
            let new = encode_cp56time2a(now_unix_ns, iv, su);
            asdu[cp_start..cp_start + 7].copy_from_slice(&new);
            rewrites += 1;
            off += stride;
        }
    }
    rewrites
}

/// Zone-aware variant of [`rewrite_cp56time2a_to_now`]. Encodes each
/// CP56 field in the selected timezone:
///
/// - `Cp56Zone::Utc`: calendar components are UTC, SU bit always 0.
/// - `Cp56Zone::Local`: calendar components are local-time per the
///   server's TZ, SU bit set from `tm_isdst` at the instant of encoding.
///
/// IV (invalid) is always preserved from the source ASDU so
/// data-quality semantics survive the rewrite regardless of zone.
pub fn rewrite_cp56time2a_to_now_zoned(
    asdu: &mut [u8],
    now_unix_ns: u64,
    zone: Cp56Zone,
) -> usize {
    if asdu.len() < DUI_LEN {
        return 0;
    }
    let type_id = asdu[0];
    let Some(cp56_off_in_elem) = cp56_offset_in_element(type_id) else {
        return 0;
    };
    let Some(elem) = element_len(type_id) else {
        return 0;
    };
    let (sq, n) = vsq(asdu);
    let n = n as usize;
    if n == 0 {
        return 0;
    }

    let mut rewrites = 0usize;
    let patch = |asdu: &mut [u8], cp_start: usize| -> bool {
        if cp_start + 7 > asdu.len() {
            return false;
        }
        let src: [u8; 7] = asdu[cp_start..cp_start + 7].try_into().unwrap();
        let iv = src[2] & 0x80 != 0;
        let new = match zone {
            Cp56Zone::Utc => encode_cp56time2a(now_unix_ns, iv, false),
            Cp56Zone::Local => encode_cp56time2a_local(now_unix_ns, iv),
        };
        asdu[cp_start..cp_start + 7].copy_from_slice(&new);
        true
    };

    if sq {
        let mut off = DUI_LEN + IOA_LEN;
        for _ in 0..n {
            if !patch(asdu, off + cp56_off_in_elem) {
                break;
            }
            rewrites += 1;
            off += elem;
        }
    } else {
        let stride = IOA_LEN + elem;
        let mut off = DUI_LEN;
        for _ in 0..n {
            if !patch(asdu, off + IOA_LEN + cp56_off_in_elem) {
                break;
            }
            rewrites += 1;
            off += stride;
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

    /// Reference moment: 2024-03-14 (Pi Day, a Thursday) 15:09:26.535 UTC.
    /// unix epoch seconds = 1710428966; ms in minute = 26535.
    const PI_DAY_2024_NS: u64 = 1_710_428_966_535_000_000;

    #[test]
    fn encode_cp56_known_moment() {
        let b = encode_cp56time2a(PI_DAY_2024_NS, false, false);
        // ms_in_min = 26535 = 0x67A7 → bytes 0x A7 67
        assert_eq!(b[0], 0xA7);
        assert_eq!(b[1], 0x67);
        // minute = 9, IV=0
        assert_eq!(b[2] & 0x3f, 9);
        assert_eq!(b[2] & 0x80, 0);
        // hour = 15, SU=0
        assert_eq!(b[3] & 0x1f, 15);
        assert_eq!(b[3] & 0x80, 0);
        // day = 14, DOW Thursday = 4
        assert_eq!(b[4] & 0x1f, 14);
        assert_eq!((b[4] >> 5) & 0x07, 4);
        // month = 3
        assert_eq!(b[5] & 0x0f, 3);
        // year - 2000 = 24
        assert_eq!(b[6] & 0x7f, 24);
    }

    #[test]
    fn encode_cp56_iv_and_su_propagate() {
        let b = encode_cp56time2a(PI_DAY_2024_NS, true, false);
        assert_eq!(b[2] & 0x80, 0x80, "IV bit should be set");
        assert_eq!(b[3] & 0x80, 0x00, "SU bit should be clear");

        let b = encode_cp56time2a(PI_DAY_2024_NS, false, true);
        assert_eq!(b[2] & 0x80, 0x00);
        assert_eq!(b[3] & 0x80, 0x80, "SU bit should be set");

        let b = encode_cp56time2a(PI_DAY_2024_NS, true, true);
        assert_eq!(b[2] & 0x80, 0x80);
        assert_eq!(b[3] & 0x80, 0x80);
    }

    #[test]
    fn encode_cp56_dow_known_dates() {
        // 2024-03-11 is a Monday → DOW = 1
        // unix epoch seconds for 2024-03-11 00:00:00 UTC = 1710115200
        let mon = encode_cp56time2a(1_710_115_200_000_000_000, false, false);
        assert_eq!((mon[4] >> 5) & 0x07, 1, "Monday should be DOW=1");
        // 2024-03-17 is a Sunday → DOW = 7
        let sun = encode_cp56time2a(1_710_633_600_000_000_000, false, false);
        assert_eq!((sun[4] >> 5) & 0x07, 7, "Sunday should be DOW=7");
    }

    #[test]
    fn cp56_local_round_trip_is_consistent() {
        // Encoding in Local mode and decoding with the local decoder
        // must round-trip to the same unix_ns within millisecond
        // precision, regardless of the server's current timezone.
        let b = encode_cp56time2a_local(PI_DAY_2024_NS, false);
        let (ns, iv) = decode_cp56time2a_local(&b);
        let diff_ms = (ns as i128 - PI_DAY_2024_NS as i128).abs() / 1_000_000;
        assert!(diff_ms < 2, "round-trip diff = {} ms (bytes={:x?})", diff_ms, b);
        assert!(!iv);
        // SU byte reflects whatever the server TZ thinks about DST
        // for 2024-03-14; we don't assert a specific value because the
        // test server's TZ may vary. Just confirm IV is preserved.
    }

    #[test]
    fn cp56_local_iv_preserved() {
        let b = encode_cp56time2a_local(PI_DAY_2024_NS, true);
        assert_eq!(b[2] & 0x80, 0x80, "IV bit must be set");
        let (_, iv) = decode_cp56time2a_local(&b);
        assert!(iv);
    }

    #[test]
    fn rewrite_zoned_utc_mode_matches_plain() {
        // In Utc mode rewrite_cp56time2a_to_now_zoned must produce the
        // same bytes as the plain rewriter when the source SU bit is 0.
        let mut a = vec![
            103, 0x01, 0x06, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let mut b = a.clone();
        let n1 = rewrite_cp56time2a_to_now(&mut a, PI_DAY_2024_NS);
        let n2 = rewrite_cp56time2a_to_now_zoned(&mut b, PI_DAY_2024_NS, Cp56Zone::Utc);
        assert_eq!(n1, n2);
        assert_eq!(a, b);
    }

    #[test]
    fn rewrite_zoned_local_sets_su_from_dst() {
        // In Local mode the rewriter must ignore the source SU bit and
        // derive SU from the current timezone's DST state for the
        // encoded moment.
        let mut asdu = vec![
            103, 0x01, 0x06, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00,
            // Source CP56 with SU=1 and garbage time
            0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        ];
        let n = rewrite_cp56time2a_to_now_zoned(&mut asdu, PI_DAY_2024_NS, Cp56Zone::Local);
        assert_eq!(n, 1);
        // The SU bit of the rewritten stamp depends on the server TZ's
        // DST state for Pi-Day 2024 — we don't assert a specific value,
        // only that the decoded unix_ns is close to the input.
        let stamp: [u8; 7] = asdu[9..16].try_into().unwrap();
        let (ns, _) = decode_cp56time2a_local(&stamp);
        let diff_ms = (ns as i128 - PI_DAY_2024_NS as i128).abs() / 1_000_000;
        assert!(diff_ms < 2, "{} ms off", diff_ms);
    }

    #[test]
    fn cp56_round_trip() {
        let b = encode_cp56time2a(PI_DAY_2024_NS, false, false);
        let mut arr = [0u8; 7];
        arr.copy_from_slice(&b);
        let (ns, iv, su) = decode_cp56time2a(&arr);
        assert_eq!(ns, PI_DAY_2024_NS);
        assert!(!iv && !su);

        // Round-trip with IV+SU set
        let b = encode_cp56time2a(PI_DAY_2024_NS, true, true);
        let (ns, iv, su) = decode_cp56time2a(&b);
        assert_eq!(ns, PI_DAY_2024_NS);
        assert!(iv && su);
    }

    #[test]
    fn cp56_offset_table() {
        // Last 7 bytes of element rule.
        assert_eq!(cp56_offset_in_element(30), Some(1)); // SIQ + CP56
        assert_eq!(cp56_offset_in_element(34), Some(3)); // NVA + QDS + CP56
        assert_eq!(cp56_offset_in_element(36), Some(5)); // float + QDS + CP56
        assert_eq!(cp56_offset_in_element(58), Some(1)); // SCO + CP56
        assert_eq!(cp56_offset_in_element(64), Some(4)); // BSI + CP56
        assert_eq!(cp56_offset_in_element(103), Some(0)); // bare CP56
        // CP24 types intentionally not touched.
        assert_eq!(cp56_offset_in_element(2), None);
        assert_eq!(cp56_offset_in_element(14), None);
        // Untimed types
        assert_eq!(cp56_offset_in_element(1), None);
        assert_eq!(cp56_offset_in_element(13), None);
    }

    #[test]
    fn rewrite_cp56_type36_sq0_three_objects() {
        // Type 36 (M_ME_TF_1): float (4) + QDS (1) + CP56 (7) per element.
        // SQ=0, N=3 → 3 separate (IOA + element) groups.
        let mut asdu = vec![
            36,    // type
            0x03,  // VSQ: SQ=0, N=3
            0x03, 0x00, // COT
            0x01, 0x00, // CA
        ];
        // Three objects, each 3 (IOA) + 4 (float) + 1 (QDS) + 7 (CP56) = 15 bytes
        for i in 0..3u32 {
            asdu.extend_from_slice(&[(i as u8 + 1), 0, 0]); // IOA
            asdu.extend_from_slice(&[0u8; 4]); // float
            asdu.push(0x00); // QDS
            // CP56 stamp: pre-fill with marker so we can prove it changed
            asdu.extend_from_slice(&[0xFF; 7]);
        }
        let pre = asdu.clone();
        let rewrites = rewrite_cp56time2a_to_now(&mut asdu, PI_DAY_2024_NS);
        assert_eq!(rewrites, 3);
        // Header + DUI + per-object IOA/payload bytes must be unchanged
        for (idx, off_in_obj) in [(0, 6), (1, 21), (2, 36)].iter() {
            // first 8 bytes of each object (IOA + float + QDS) untouched
            for k in 0..8usize {
                assert_eq!(asdu[off_in_obj + k], pre[off_in_obj + k],
                    "object {idx}: byte {k} changed");
            }
            // last 7 bytes (CP56) replaced
            let cp_start = off_in_obj + 8;
            let stamp: [u8; 7] = asdu[cp_start..cp_start + 7].try_into().unwrap();
            let (ns, _, _) = decode_cp56time2a(&stamp);
            assert_eq!(ns, PI_DAY_2024_NS, "object {idx} CP56 not equal to expected");
        }
    }

    #[test]
    fn rewrite_cp56_type30_sq1_sequence() {
        // Type 30 (M_SP_TB_1): SIQ (1) + CP56 (7) = 8 bytes per element.
        // SQ=1, N=4 → one IOA, then 4 elements back-to-back.
        let mut asdu = vec![
            30,
            0x84, // SQ=1, N=4
            0x03, 0x00, // COT
            0x01, 0x00, // CA
            0x10, 0x00, 0x00, // base IOA = 16
        ];
        for _ in 0..4 {
            asdu.push(0x01); // SIQ
            asdu.extend_from_slice(&[0xFF; 7]);
        }
        let rewrites = rewrite_cp56time2a_to_now(&mut asdu, PI_DAY_2024_NS);
        assert_eq!(rewrites, 4);
        // Each element: SIQ at +0 (untouched), CP56 at +1
        for i in 0..4 {
            let elem_start = 9 + i * 8; // 6 (DUI) + 3 (IOA) + i * 8
            assert_eq!(asdu[elem_start], 0x01, "SIQ at elem {i} clobbered");
            let stamp: [u8; 7] = asdu[elem_start + 1..elem_start + 8].try_into().unwrap();
            let (ns, _, _) = decode_cp56time2a(&stamp);
            assert_eq!(ns, PI_DAY_2024_NS);
        }
    }

    #[test]
    fn rewrite_cp56_type103_clock_sync() {
        // Type 103 (C_CS_NA_1): just CP56, no other fields.
        let mut asdu = vec![
            103,
            0x01, // SQ=0, N=1
            0x06, 0x00, // COT
            0x01, 0x00, // CA
            0x00, 0x00, 0x00, // IOA = 0
            // CP56 placeholder
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let rewrites = rewrite_cp56time2a_to_now(&mut asdu, PI_DAY_2024_NS);
        assert_eq!(rewrites, 1);
        let stamp: [u8; 7] = asdu[9..16].try_into().unwrap();
        let (ns, _, _) = decode_cp56time2a(&stamp);
        assert_eq!(ns, PI_DAY_2024_NS);
    }

    #[test]
    fn rewrite_cp56_type58_command_with_time() {
        // Type 58 (C_SC_TA_1): SCO (1) + CP56 (7).
        let mut asdu = vec![
            58,
            0x01, // SQ=0, N=1
            0x06, 0x00,
            0x01, 0x00,
            0x05, 0x00, 0x00, // IOA
            0x81,             // SCO
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let rewrites = rewrite_cp56time2a_to_now(&mut asdu, PI_DAY_2024_NS);
        assert_eq!(rewrites, 1);
        assert_eq!(asdu[9], 0x81, "SCO byte clobbered");
        let stamp: [u8; 7] = asdu[10..17].try_into().unwrap();
        let (ns, _, _) = decode_cp56time2a(&stamp);
        assert_eq!(ns, PI_DAY_2024_NS);
    }

    #[test]
    fn rewrite_cp56_preserves_iv_and_su_per_element() {
        // Type 36, SQ=0, N=2: first element IV=1, second element SU=1.
        let mut asdu = vec![
            36, 0x02,
            0x03, 0x00, 0x01, 0x00,
        ];
        // Object 1: IOA + payload + CP56 with IV=1
        asdu.extend_from_slice(&[0x01, 0x00, 0x00]);
        asdu.extend_from_slice(&[0u8; 5]); // float + QDS
        asdu.extend_from_slice(&[0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00]); // CP56 with IV bit set
        // Object 2: IOA + payload + CP56 with SU=1
        asdu.extend_from_slice(&[0x02, 0x00, 0x00]);
        asdu.extend_from_slice(&[0u8; 5]);
        asdu.extend_from_slice(&[0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00]); // CP56 with SU bit set

        let rewrites = rewrite_cp56time2a_to_now(&mut asdu, PI_DAY_2024_NS);
        assert_eq!(rewrites, 2);

        // Object 1 CP56: IV preserved
        let stamp1: [u8; 7] = asdu[14..21].try_into().unwrap();
        assert_eq!(stamp1[2] & 0x80, 0x80, "IV must survive rewrite");
        assert_eq!(stamp1[3] & 0x80, 0x00, "SU must stay clear");
        let (ns, iv, su) = decode_cp56time2a(&stamp1);
        assert_eq!(ns, PI_DAY_2024_NS);
        assert!(iv && !su);

        // Object 2 CP56: SU preserved
        let stamp2: [u8; 7] = asdu[29..36].try_into().unwrap();
        assert_eq!(stamp2[2] & 0x80, 0x00, "IV must stay clear");
        assert_eq!(stamp2[3] & 0x80, 0x80, "SU must survive rewrite");
        let (ns, iv, su) = decode_cp56time2a(&stamp2);
        assert_eq!(ns, PI_DAY_2024_NS);
        assert!(!iv && su);
    }

    #[test]
    fn rewrite_cp56_skips_cp24_types() {
        // Type 2 (M_SP_TA_1): SIQ + CP24Time2a — should NOT be touched.
        let mut asdu = vec![
            2, 0x01,
            0x03, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, // IOA
            0x42,             // SIQ
            0xAA, 0xBB, 0xCC, // CP24
        ];
        let pre = asdu.clone();
        let rewrites = rewrite_cp56time2a_to_now(&mut asdu, PI_DAY_2024_NS);
        assert_eq!(rewrites, 0);
        assert_eq!(asdu, pre, "CP24 type must be left untouched");
    }

    #[test]
    fn rewrite_cp56_untimed_type_is_noop() {
        // Type 1 (M_SP_NA_1): no time tag at all.
        let mut asdu = vec![
            1, 0x01,
            0x03, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00,
            0x42,
        ];
        let pre = asdu.clone();
        let rewrites = rewrite_cp56time2a_to_now(&mut asdu, PI_DAY_2024_NS);
        assert_eq!(rewrites, 0);
        assert_eq!(asdu, pre);
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
