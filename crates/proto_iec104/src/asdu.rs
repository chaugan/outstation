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
            let k: u16 = k
                .parse()
                .map_err(|e| anyhow::anyhow!("bad common_address key {k}: {e}"))?;
            out.common_address.insert(k, v);
        }
        for (k, v) in raw.cot {
            let k: u8 = k
                .parse()
                .map_err(|e| anyhow::anyhow!("bad cot key {k}: {e}"))?;
            out.cot.insert(k, v);
        }
        for (k, v) in raw.ioa {
            let k: u32 = k
                .parse()
                .map_err(|e| anyhow::anyhow!("bad ioa key {k}: {e}"))?;
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
/// 3-byte IOA, per IEC 60870-5-101 §7.3 and IEC 60870-5-104 §8.
/// Returns `None` for type IDs that are undefined, reserved, private
/// or variable-length (F_SG_NA_1, 125).
///
/// Information-element sizes used below: SIQ/DIQ/QDS/QOS/QPM/QPA/QOI/
/// QCC/QRP/COI/SCO/DCO/RCO/SEP/SPE/OCI/QDP = 1, NVA/SVA/FBP/TSC/
/// CP16Time2a/NOF = 2, VTI = 1, CP24Time2a/LOF = 3, BSI/BCR-value/
/// IEEE STD 754 float/SCD = 4 (BCR = 4 + 1 sequence octet = 5),
/// CP56Time2a = 7.
pub fn element_len(type_id: u8) -> Option<usize> {
    Some(match type_id {
        // --- Process information in monitor direction ---
        1 => 1,              // M_SP_NA_1 — SIQ
        2 => 1 + 3,          // M_SP_TA_1 — SIQ + CP24Time2a
        3 => 1,              // M_DP_NA_1 — DIQ
        4 => 1 + 3,          // M_DP_TA_1 — DIQ + CP24
        5 => 1 + 1,          // M_ST_NA_1 — VTI + QDS
        6 => 1 + 1 + 3,      // M_ST_TA_1 — VTI + QDS + CP24
        7 => 4 + 1,          // M_BO_NA_1 — BSI + QDS
        8 => 4 + 1 + 3,      // M_BO_TA_1 — BSI + QDS + CP24
        9 => 2 + 1,          // M_ME_NA_1 — NVA + QDS
        10 => 2 + 1 + 3,     // M_ME_TA_1 — NVA + QDS + CP24
        11 => 2 + 1,         // M_ME_NB_1 — SVA + QDS
        12 => 2 + 1 + 3,     // M_ME_TB_1 — SVA + QDS + CP24
        13 => 4 + 1,         // M_ME_NC_1 — float + QDS
        14 => 4 + 1 + 3,     // M_ME_TC_1 — float + QDS + CP24
        15 => 5,             // M_IT_NA_1 — BCR
        16 => 5 + 3,         // M_IT_TA_1 — BCR + CP24
        17 => 1 + 2 + 3,     // M_EP_TA_1 — SEP + CP16 + CP24
        18 => 1 + 1 + 2 + 3, // M_EP_TB_1 — SPE + QDP + CP16 + CP24
        19 => 1 + 1 + 2 + 3, // M_EP_TC_1 — OCI + QDP + CP16 + CP24
        20 => 4 + 1,         // M_PS_NA_1 — SCD + QDS
        21 => 2,             // M_ME_ND_1 — NVA
        30 => 1 + 7,         // M_SP_TB_1 — SIQ + CP56Time2a
        31 => 1 + 7,         // M_DP_TB_1 — DIQ + CP56
        32 => 1 + 1 + 7,     // M_ST_TB_1 — VTI + QDS + CP56
        33 => 4 + 1 + 7,     // M_BO_TB_1 — BSI + QDS + CP56
        34 => 2 + 1 + 7,     // M_ME_TD_1 — NVA + QDS + CP56
        35 => 2 + 1 + 7,     // M_ME_TE_1 — SVA + QDS + CP56
        36 => 4 + 1 + 7,     // M_ME_TF_1 — float + QDS + CP56
        37 => 5 + 7,         // M_IT_TB_1 — BCR + CP56
        38 => 1 + 2 + 7,     // M_EP_TD_1 — SEP + CP16 + CP56
        39 => 1 + 1 + 2 + 7, // M_EP_TE_1 — SPE + QDP + CP16 + CP56
        40 => 1 + 1 + 2 + 7, // M_EP_TF_1 — OCI + QDP + CP16 + CP56
        // --- Process information in control direction ---
        45 => 1,         // C_SC_NA_1 — SCO
        46 => 1,         // C_DC_NA_1 — DCO
        47 => 1,         // C_RC_NA_1 — RCO
        48 => 2 + 1,     // C_SE_NA_1 — NVA + QOS
        49 => 2 + 1,     // C_SE_NB_1 — SVA + QOS
        50 => 4 + 1,     // C_SE_NC_1 — float + QOS
        51 => 4,         // C_BO_NA_1 — BSI
        58 => 1 + 7,     // C_SC_TA_1 — SCO + CP56
        59 => 1 + 7,     // C_DC_TA_1 — DCO + CP56
        60 => 1 + 7,     // C_RC_TA_1 — RCO + CP56
        61 => 2 + 1 + 7, // C_SE_TA_1 — NVA + QOS + CP56
        62 => 2 + 1 + 7, // C_SE_TB_1 — SVA + QOS + CP56
        63 => 4 + 1 + 7, // C_SE_TC_1 — float + QOS + CP56
        64 => 4 + 7,     // C_BO_TA_1 — BSI + CP56
        // --- System information ---
        70 => 1,      // M_EI_NA_1 — COI
        100 => 1,     // C_IC_NA_1 — QOI
        101 => 1,     // C_CI_NA_1 — QCC
        102 => 0,     // C_RD_NA_1 — no element
        103 => 7,     // C_CS_NA_1 — CP56Time2a
        104 => 2,     // C_TS_NA_1 — FBP (fixed test pattern 0x55AA)
        105 => 1,     // C_RP_NA_1 — QRP
        106 => 2,     // C_CD_NA_1 — CP16Time2a
        107 => 2 + 7, // C_TS_TA_1 — TSC + CP56
        // --- Parameter in control direction ---
        110 => 2 + 1, // P_ME_NA_1 — NVA + QPM
        111 => 2 + 1, // P_ME_NB_1 — SVA + QPM
        112 => 4 + 1, // P_ME_NC_1 — float + QPM
        113 => 1,     // P_AC_NA_1 — QPA
        // --- File transfer (fixed-length ones only) ---
        120 => 2 + 3 + 1,     // F_FR_NA_1 — NOF + LOF + FRQ
        121 => 2 + 1 + 3 + 1, // F_SR_NA_1 — NOF + NOS + LOF + SRQ
        122 => 2 + 1 + 1,     // F_SC_NA_1 — NOF + NOS + SCQ
        123 => 2 + 1 + 1 + 1, // F_LS_NA_1 — NOF + NOS + LSQ + CHS
        124 => 2 + 1 + 1,     // F_AF_NA_1 — NOF + NOS + AFQ
        // 125 F_SG_NA_1 carries a variable-length segment: no fixed size.
        126 => 2 + 3 + 1 + 7, // F_DR_TA_1 — NOF + LOF + SOF + CP56
        127 => 2 + 7 + 7,     // F_SC_NB_1 — NOF + range start + range stop
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
///
/// File-transfer types (126, 127) carry file-system times, not event
/// times, and are deliberately excluded so a rewrite never touches them.
pub fn cp56_offset_in_element(type_id: u8) -> Option<usize> {
    // Every CP56-bearing type listed here ends its element with 7 bytes
    // of CP56Time2a, so the offset is element_len - 7.
    match type_id {
        30..=40 | 58..=64 | 103 | 107 => element_len(type_id).map(|e| e - 7),
        _ => None,
    }
}

/// Byte offset (within `asdu`) of every CP56Time2a field the ASDU
/// carries, walking SQ=0 and SQ=1 layouts. Fields that would run past
/// the end of the buffer are not returned. This is the single shared
/// CP56 walk used by the rewriters and the analyzer.
pub fn cp56_field_offsets(asdu: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if asdu.len() < DUI_LEN {
        return out;
    }
    let type_id = asdu[0];
    let (Some(cp56_off_in_elem), Some(elem)) =
        (cp56_offset_in_element(type_id), element_len(type_id))
    else {
        return out;
    };
    let (sq, n) = vsq(asdu);
    // SQ=1: one IOA, then n consecutive elements. SQ=0: n (IOA, element)
    // pairs. Either way the first element starts right after an IOA.
    let first = DUI_LEN + IOA_LEN + cp56_off_in_elem;
    let stride = if sq { elem } else { IOA_LEN + elem };
    for k in 0..n as usize {
        let cp_start = first + k * stride;
        if cp_start + 7 > asdu.len() {
            break;
        }
        out.push(cp_start);
    }
    out
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

/// Local calendar components `(year, month, day, hour, minute, second)`
/// with a 4-digit year and 1-based month.
type Ymdhms = (u32, u32, u32, u32, u32, u32);

/// Run `mktime` on local calendar components with the given
/// `tm_isdst` hint. Returns the epoch seconds plus the normalised
/// components mktime wrote back, or `None` if mktime failed.
fn mktime_local(ymdhms: Ymdhms, isdst: i32) -> Option<(i64, Ymdhms)> {
    let (year, month, day, hour, minute, second) = ymdhms;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = year as i32 - 1900;
    tm.tm_mon = month as i32 - 1;
    tm.tm_mday = day as i32;
    tm.tm_hour = hour as i32;
    tm.tm_min = minute as i32;
    tm.tm_sec = second as i32;
    tm.tm_isdst = isdst;
    let t = unsafe { libc::mktime(&mut tm) };
    // CP56 years are 2000..=2127, so -1 is never a legitimate result:
    // it is mktime's error value.
    if t == -1 {
        return None;
    }
    Some((
        t as i64,
        (
            (tm.tm_year + 1900) as u32,
            (tm.tm_mon + 1) as u32,
            tm.tm_mday as u32,
            tm.tm_hour as u32,
            tm.tm_min as u32,
            tm.tm_sec as u32,
        ),
    ))
}

/// Inverse of `break_local`: local calendar components to Unix epoch
/// seconds, using the host's timezone rules.
///
/// The TZ rules decide; the SU flag is only a hint. Each of the two
/// `tm_isdst` interpretations is tried and kept only if mktime did not
/// have to normalise the wall-clock time (i.e. it really exists with
/// that DST state). If both exist (the repeated hour when DST ends),
/// SU picks between them. If neither does (the skipped hour when DST
/// starts, which a correct encoder never produces), mktime's own
/// `tm_isdst = -1` resolution is used. Returns `None` when mktime
/// fails.
fn assemble_local(ymdhms: Ymdhms, su: bool) -> Option<i64> {
    let exact = |isdst: i32| -> Option<i64> {
        let (t, norm) = mktime_local(ymdhms, isdst)?;
        (norm == ymdhms).then_some(t)
    };
    let dst = exact(1);
    let std = exact(0);
    match (dst, std) {
        (Some(d), Some(s)) if d != s => Some(if su { d } else { s }),
        (Some(t), _) | (None, Some(t)) => Some(t),
        (None, None) => mktime_local(ymdhms, -1).map(|(t, _)| t),
    }
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
    let yoe = y - era * 400;
    let m_adj = if month > 2 { month - 3 } else { month + 9 } as i64;
    let doy = (153 * m_adj + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    // 1970-01-01 was a Thursday (4 in ISO). Mon=1..Sun=7.

    ((days + 3).rem_euclid(7) + 1) as u8
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
/// timezone. Returns `Some((unix_ns, iv))`.
///
/// The host's TZ rules are authoritative; the SU bit only breaks the
/// tie for the repeated hour at the end of DST (see `assemble_local`).
/// Returns `None` when the field is not a valid calendar time (month
/// 0 or > 12, day 0, hour > 23, minute > 59, ms >= 60000) or mktime
/// cannot convert it. Callers should count such stamps as undecodable
/// rather than treat them as the epoch.
pub fn decode_cp56time2a_local(b: &[u8; 7]) -> Option<(u64, bool)> {
    let ms_in_min = (b[0] as u32) | ((b[1] as u32) << 8);
    let iv = b[2] & 0x80 != 0;
    let minute = (b[2] & 0x3f) as u32;
    let su = b[3] & 0x80 != 0;
    let hour = (b[3] & 0x1f) as u32;
    let day = (b[4] & 0x1f) as u32;
    let month = (b[5] & 0x0f) as u32;
    let year = 2000u32 + (b[6] & 0x7f) as u32;
    if ms_in_min >= 60_000 || minute > 59 || hour > 23 || day == 0 || !(1..=12).contains(&month) {
        return None;
    }

    let second = ms_in_min / 1000;
    let ms = ms_in_min % 1000;
    let secs = assemble_local((year, month, day, hour, minute, second), su)?;
    let secs = u64::try_from(secs).ok()?;
    Some((secs * 1_000_000_000 + (ms as u64) * 1_000_000, iv))
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
    let offsets = cp56_field_offsets(asdu);
    for &cp_start in &offsets {
        let field = &mut asdu[cp_start..cp_start + 7];
        let iv = field[2] & 0x80 != 0;
        let su = field[3] & 0x80 != 0;
        field.copy_from_slice(&encode_cp56time2a(now_unix_ns, iv, su));
    }
    offsets.len()
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
pub fn rewrite_cp56time2a_to_now_zoned(asdu: &mut [u8], now_unix_ns: u64, zone: Cp56Zone) -> usize {
    let offsets = cp56_field_offsets(asdu);
    for &cp_start in &offsets {
        let field = &mut asdu[cp_start..cp_start + 7];
        let iv = field[2] & 0x80 != 0;
        let new = match zone {
            Cp56Zone::Utc => encode_cp56time2a(now_unix_ns, iv, false),
            Cp56Zone::Local => encode_cp56time2a_local(now_unix_ns, iv),
        };
        field.copy_from_slice(&new);
    }
    offsets.len()
}

/// Parse the JSON proto_config into a [`RewriteMap`]. Returns an empty
/// map if the JSON is `null` or an empty object. Used by
/// [`crate::session`].
///
/// The full IEC 104 `proto_config` shape supports both the rewrite-map
/// keys (flat at top level) and an optional `cp56` sub-object handled
/// by [`Iec104ProtoConfig`]. This loader only extracts the rewrite map
/// and silently ignores the `cp56` sub-object.
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

/// Structured view of the IEC 104 `proto_config` JSON, narrowed to the
/// CP56-rewrite section. Used by [`crate::session`] and webui's
/// analyzer to read the CP56 settings without touching the rewrite
/// map keys.
///
/// Wire shape (full proto_config):
/// ```json
/// {
///   "common_address": {...},
///   "cot": {...},
///   "ioa": {...},
///   "cp56": { "rewrite_to_now": false, "zone": "local" },
///   "session": { "k": 12, "w": 8, "t1": 15, "t2": 10, "t3": 20 }
/// }
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Iec104ProtoConfig {
    #[serde(default)]
    pub cp56: Cp56Config,
    /// APCI link parameters and live-session behaviour.
    #[serde(default)]
    pub session: SessionConfig,
}

/// IEC 60870-5-104 §5 link parameters plus session behaviour knobs.
/// Timers are in seconds and may be fractional. Defaults are the IEC
/// recommended values (k=12, w=8, t0=30, t1=15, t2=10, t3=20).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// Max unacknowledged I-frames we send before stalling.
    #[serde(default = "default_k")]
    pub k: u16,
    /// Acknowledge (S-frame) at the latest after receiving w I-frames.
    #[serde(default = "default_w")]
    pub w: u16,
    /// Connection-establishment timeout (master mode TCP connect).
    /// When absent the run's `connect_timeout` is used.
    #[serde(default)]
    pub t0: Option<f64>,
    /// Timeout for the peer to acknowledge a sent I-frame or to
    /// confirm a STARTDT/STOPDT/TESTFR act. Expiry closes the link.
    #[serde(default = "default_t1")]
    pub t1: f64,
    /// Acknowledge received I-frames at the latest t2 after the first
    /// unacknowledged one arrived. Must be below t1.
    #[serde(default = "default_t2")]
    pub t2: f64,
    /// Send TESTFR act after t3 without receiving anything.
    #[serde(default = "default_t3")]
    pub t3: f64,
    /// Slave mode: how long to keep serving the master (GI/CI, TESTFR,
    /// acks) after the captured script has ended, unless the master
    /// closes first or the run is cancelled. Absent =
    /// [`DEFAULT_IDLE_SERVE_SECS`], so a run (and each outer iteration)
    /// still finishes on its own; set a large value to impersonate an
    /// RTU that never hangs up.
    #[serde(default)]
    pub idle_serve_secs: Option<f64>,
}

/// Default slave idle-serve window after the script ends (seconds).
pub const DEFAULT_IDLE_SERVE_SECS: f64 = 30.0;

fn default_k() -> u16 {
    12
}
fn default_w() -> u16 {
    8
}
fn default_t1() -> f64 {
    15.0
}
fn default_t2() -> f64 {
    10.0
}
fn default_t3() -> f64 {
    20.0
}

/// IEC default t0 in seconds.
pub const DEFAULT_T0_SECS: f64 = 30.0;
/// Largest sequence-number distance; k and w must stay below it.
const MAX_WINDOW: u16 = 32767;

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            k: default_k(),
            w: default_w(),
            t0: None,
            t1: default_t1(),
            t2: default_t2(),
            t3: default_t3(),
            idle_serve_secs: None,
        }
    }
}

impl SessionConfig {
    /// Hard errors: out-of-range k/w, non-positive or non-finite
    /// timers, t2 >= t1.
    pub fn validate(&self) -> Result<()> {
        if !(1..=MAX_WINDOW).contains(&self.k) {
            bail!("session.k must be 1..={MAX_WINDOW}, got {}", self.k);
        }
        if !(1..=MAX_WINDOW).contains(&self.w) {
            bail!("session.w must be 1..={MAX_WINDOW}, got {}", self.w);
        }
        let timers = [
            ("t0", self.t0),
            ("t1", Some(self.t1)),
            ("t2", Some(self.t2)),
            ("t3", Some(self.t3)),
        ];
        for (name, v) in timers {
            if let Some(v) = v {
                if !v.is_finite() || v <= 0.0 || v > 86_400.0 {
                    bail!("session.{name} must be > 0 and <= 86400 seconds, got {v}");
                }
            }
        }
        if let Some(v) = self.idle_serve_secs {
            if !v.is_finite() || v < 0.0 {
                bail!("session.idle_serve_secs must be >= 0, got {v}");
            }
        }
        if self.t2 >= self.t1 {
            bail!(
                "session.t2 ({}) must be less than session.t1 ({})",
                self.t2,
                self.t1
            );
        }
        Ok(())
    }

    /// Non-fatal advice (IEC 60870-5-104 §5.5 recommends w <= 2k/3).
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if 3 * u32::from(self.w) > 2 * u32::from(self.k) {
            out.push(format!(
                "session.w ({}) exceeds the recommended 2/3 of k ({})",
                self.w, self.k
            ));
        }
        out
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cp56Config {
    /// Whether to rewrite every CP56Time2a in outgoing ASDUs to the
    /// wall-clock moment the carrying frame hits the wire.
    #[serde(default, alias = "rewrite_cp56_to_now")]
    pub rewrite_to_now: bool,
    /// Timezone convention used by the rewrite. `"utc"` or `"local"`.
    /// Validated by [`Iec104ProtoConfig::parse`]; use
    /// [`Cp56Config::zone`] for the typed value.
    #[serde(default = "default_cp56_zone", alias = "cp56_zone")]
    pub zone: String,
}

impl Default for Cp56Config {
    fn default() -> Self {
        Self {
            rewrite_to_now: false,
            zone: default_cp56_zone(),
        }
    }
}

impl Cp56Config {
    /// Typed zone. A config that came through
    /// [`Iec104ProtoConfig::parse`] always has a valid zone string;
    /// for a hand-built config an unknown string maps to `Local`.
    pub fn zone(&self) -> Cp56Zone {
        Cp56Zone::parse(&self.zone).unwrap_or(Cp56Zone::Local)
    }
}

fn default_cp56_zone() -> String {
    "local".into()
}

impl Iec104ProtoConfig {
    /// Parse `proto_config` JSON. `None`, an empty string, `"null"`,
    /// `"{}"` and a missing `cp56` sub-object all give the default
    /// (no rewrite, local zone).
    ///
    /// Malformed input is an error, never a silent default: invalid
    /// JSON, a wrongly typed field (`"rewrite_to_now": "true"`), an
    /// unknown key inside `cp56` (a typo), or a zone other than
    /// `"utc"` / `"local"`.
    pub fn parse(proto_config: Option<&str>) -> Result<Self> {
        let Some(s) = proto_config else {
            return Ok(Self::default());
        };
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed == "null" || trimmed == "{}" {
            return Ok(Self::default());
        }
        let cfg: Self = serde_json::from_str(trimmed)
            .map_err(|e| anyhow::anyhow!("proto_config (cp56): {e}"))?;
        if Cp56Zone::parse(&cfg.cp56.zone).is_none() {
            bail!(
                "proto_config (cp56): unknown zone {:?} (expected \"utc\" or \"local\")",
                cfg.cp56.zone
            );
        }
        cfg.session
            .validate()
            .map_err(|e| anyhow::anyhow!("proto_config (session): {e}"))?;
        Ok(cfg)
    }
}

/// Validate a full IEC 104 `proto_config` (rewrite map and `cp56`
/// section) without starting a run. Intended for submit-time
/// validation so a malformed config is rejected before any run id is
/// allocated.
pub fn validate_proto_config(proto_config: Option<&str>) -> Result<()> {
    load_rewrite_map(proto_config)?;
    Iec104ProtoConfig::parse(proto_config)?;
    Ok(())
}

/// Convenience for tests and callers that already hold a map in memory.
pub fn rewrite_or_skip(asdu: &mut [u8], map: &RewriteMap) -> Result<usize> {
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
        let mut asdu = vec![
            0x0d, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
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
            1,
            0x01,
            0xC0 | 6,
            0x00, // COT=6 with both P/N and T flags set
            0x01,
            0x00,
            0x02,
            0x00,
            0x00,
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
            0x0a, 0x00, 0x00, // base IOA=10
            // 4 elements × 5 bytes each
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
        let (ns, iv) = decode_cp56time2a_local(&b).expect("decodable");
        let diff_ms = (ns as i128 - PI_DAY_2024_NS as i128).abs() / 1_000_000;
        assert!(
            diff_ms < 2,
            "round-trip diff = {} ms (bytes={:x?})",
            diff_ms,
            b
        );
        assert!(!iv);
        // SU byte reflects whatever the server TZ thinks about DST
        // for 2024-03-14; we don't assert a specific value because the
        // test server's TZ may vary. Just confirm IV is preserved.
    }

    #[test]
    fn cp56_local_iv_preserved() {
        let b = encode_cp56time2a_local(PI_DAY_2024_NS, true);
        assert_eq!(b[2] & 0x80, 0x80, "IV bit must be set");
        let (_, iv) = decode_cp56time2a_local(&b).expect("decodable");
        assert!(iv);
    }

    #[test]
    fn rewrite_zoned_utc_mode_matches_plain() {
        // In Utc mode rewrite_cp56time2a_to_now_zoned must produce the
        // same bytes as the plain rewriter when the source SU bit is 0.
        let mut a = vec![
            103, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0,
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
            103, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            // Source CP56 with SU=1 and garbage time
            0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        ];
        let n = rewrite_cp56time2a_to_now_zoned(&mut asdu, PI_DAY_2024_NS, Cp56Zone::Local);
        assert_eq!(n, 1);
        // The SU bit of the rewritten stamp depends on the server TZ's
        // DST state for Pi-Day 2024 — we don't assert a specific value,
        // only that the decoded unix_ns is close to the input.
        let stamp: [u8; 7] = asdu[9..16].try_into().unwrap();
        let (ns, _) = decode_cp56time2a_local(&stamp).expect("decodable");
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
        assert_eq!(cp56_offset_in_element(107), Some(2)); // TSC + CP56
        assert_eq!(cp56_offset_in_element(38), Some(3)); // SEP + CP16 + CP56
        assert_eq!(cp56_offset_in_element(40), Some(4)); // OCI + QDP + CP16 + CP56
                                                         // File-transfer times are left alone.
        assert_eq!(cp56_offset_in_element(126), None);
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
            36,   // type
            0x03, // VSQ: SQ=0, N=3
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
                assert_eq!(
                    asdu[off_in_obj + k],
                    pre[off_in_obj + k],
                    "object {idx}: byte {k} changed"
                );
            }
            // last 7 bytes (CP56) replaced
            let cp_start = off_in_obj + 8;
            let stamp: [u8; 7] = asdu[cp_start..cp_start + 7].try_into().unwrap();
            let (ns, _, _) = decode_cp56time2a(&stamp);
            assert_eq!(
                ns, PI_DAY_2024_NS,
                "object {idx} CP56 not equal to expected"
            );
        }
    }

    #[test]
    fn rewrite_cp56_type30_sq1_sequence() {
        // Type 30 (M_SP_TB_1): SIQ (1) + CP56 (7) = 8 bytes per element.
        // SQ=1, N=4 → one IOA, then 4 elements back-to-back.
        let mut asdu = vec![
            30, 0x84, // SQ=1, N=4
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
            103, 0x01, // SQ=0, N=1
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
            58, 0x01, // SQ=0, N=1
            0x06, 0x00, 0x01, 0x00, 0x05, 0x00, 0x00, // IOA
            0x81, // SCO
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
        let mut asdu = vec![36, 0x02, 0x03, 0x00, 0x01, 0x00];
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
            2, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // IOA
            0x42, // SIQ
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
        let mut asdu = vec![1, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x42];
        let pre = asdu.clone();
        let rewrites = rewrite_cp56time2a_to_now(&mut asdu, PI_DAY_2024_NS);
        assert_eq!(rewrites, 0);
        assert_eq!(asdu, pre);
    }

    #[test]
    fn unknown_type_rewrites_first_ioa_only() {
        // Type 200 is not in the table. SQ=0, N=2.
        let mut asdu = vec![
            200, 0x02, 0x03, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x00,
            // unknown-length body — we don't touch this
            0xff, 0xff, 0x0b, 0x00, 0x00, 0xff, 0xff,
        ];
        let mut map = RewriteMap::default();
        map.ioa.insert(10, 999);
        map.ioa.insert(11, 888);
        // Should rewrite only the first IOA (conservative fallback).
        assert_eq!(rewrite_asdu(&mut asdu, &map), 1);
        assert_eq!(read_ioa(&asdu, DUI_LEN), 999);
    }

    /// Table test against the information-element sizes in
    /// IEC 60870-5-101 §7.3 / IEC 60870-5-104 §8 (sizes exclude the IOA).
    #[test]
    fn element_len_matches_standard_table() {
        #[rustfmt::skip]
        let table: &[(u8, &str, usize)] = &[
            (1, "M_SP_NA_1", 1), (2, "M_SP_TA_1", 4), (3, "M_DP_NA_1", 1),
            (4, "M_DP_TA_1", 4), (5, "M_ST_NA_1", 2), (6, "M_ST_TA_1", 5),
            (7, "M_BO_NA_1", 5), (8, "M_BO_TA_1", 8), (9, "M_ME_NA_1", 3),
            (10, "M_ME_TA_1", 6), (11, "M_ME_NB_1", 3), (12, "M_ME_TB_1", 6),
            (13, "M_ME_NC_1", 5), (14, "M_ME_TC_1", 8), (15, "M_IT_NA_1", 5),
            (16, "M_IT_TA_1", 8), (17, "M_EP_TA_1", 6), (18, "M_EP_TB_1", 7),
            (19, "M_EP_TC_1", 7), (20, "M_PS_NA_1", 5), (21, "M_ME_ND_1", 2),
            (30, "M_SP_TB_1", 8), (31, "M_DP_TB_1", 8), (32, "M_ST_TB_1", 9),
            (33, "M_BO_TB_1", 12), (34, "M_ME_TD_1", 10), (35, "M_ME_TE_1", 10),
            (36, "M_ME_TF_1", 12), (37, "M_IT_TB_1", 12), (38, "M_EP_TD_1", 10),
            (39, "M_EP_TE_1", 11), (40, "M_EP_TF_1", 11),
            (45, "C_SC_NA_1", 1), (46, "C_DC_NA_1", 1), (47, "C_RC_NA_1", 1),
            (48, "C_SE_NA_1", 3), (49, "C_SE_NB_1", 3), (50, "C_SE_NC_1", 5),
            (51, "C_BO_NA_1", 4), (58, "C_SC_TA_1", 8), (59, "C_DC_TA_1", 8),
            (60, "C_RC_TA_1", 8), (61, "C_SE_TA_1", 10), (62, "C_SE_TB_1", 10),
            (63, "C_SE_TC_1", 12), (64, "C_BO_TA_1", 11),
            (70, "M_EI_NA_1", 1),
            (100, "C_IC_NA_1", 1), (101, "C_CI_NA_1", 1), (102, "C_RD_NA_1", 0),
            (103, "C_CS_NA_1", 7), (104, "C_TS_NA_1", 2), (105, "C_RP_NA_1", 1),
            (106, "C_CD_NA_1", 2), (107, "C_TS_TA_1", 9),
            (110, "P_ME_NA_1", 3), (111, "P_ME_NB_1", 3), (112, "P_ME_NC_1", 5),
            (113, "P_AC_NA_1", 1),
            (120, "F_FR_NA_1", 6), (121, "F_SR_NA_1", 7), (122, "F_SC_NA_1", 4),
            (123, "F_LS_NA_1", 5), (124, "F_AF_NA_1", 4), (126, "F_DR_TA_1", 13),
            (127, "F_SC_NB_1", 16),
        ];
        for &(t, name, len) in table {
            assert_eq!(element_len(t), Some(len), "{name} (type {t})");
        }
        // Everything not in the table is unknown (undefined, reserved,
        // private, or variable-length F_SG_NA_1).
        for t in 0..=255u8 {
            if !table.iter().any(|&(tt, _, _)| tt == t) {
                assert_eq!(element_len(t), None, "type {t} should be unknown");
            }
        }
    }

    #[test]
    fn rewrite_cp56_type107_keeps_tsc() {
        // C_TS_TA_1: TSC (2 octets, 0xBEEF) + CP56. The TSC must survive.
        let mut asdu = vec![
            107, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe,
        ];
        asdu.extend_from_slice(&[0u8; 7]);
        let n = rewrite_cp56time2a_to_now(&mut asdu, PI_DAY_2024_NS);
        assert_eq!(n, 1);
        assert_eq!(&asdu[9..11], &[0xef, 0xbe]);
        assert_eq!(
            &asdu[11..18],
            &encode_cp56time2a(PI_DAY_2024_NS, false, false)
        );
    }

    #[test]
    fn cp56_field_offsets_sq0_and_sq1() {
        // Type 31 (DIQ + CP56 = 8 octets).
        let mut sq0 = vec![31, 0x02, 3, 0, 1, 0];
        sq0.extend_from_slice(&[0u8; 2 * (IOA_LEN + 8)]);
        assert_eq!(cp56_field_offsets(&sq0), vec![10, 21]);
        let mut sq1 = vec![31, 0x82, 3, 0, 1, 0, 0, 0, 0];
        sq1.extend_from_slice(&[0u8; 2 * 8]);
        assert_eq!(cp56_field_offsets(&sq1), vec![10, 18]);
        // Truncated second element is not returned.
        sq1.truncate(sq1.len() - 1);
        assert_eq!(cp56_field_offsets(&sq1), vec![10]);
        // Untimed type.
        assert!(cp56_field_offsets(&[1, 1, 3, 0, 1, 0, 0, 0, 0, 1]).is_empty());
    }

    #[test]
    fn proto_config_parse_defaults_and_errors() {
        for ok in [
            None,
            Some(""),
            Some("null"),
            Some("{}"),
            Some(r#"{"ioa":{}}"#),
        ] {
            let c = Iec104ProtoConfig::parse(ok).unwrap();
            assert_eq!(c.session, SessionConfig::default());
            assert!(!c.cp56.rewrite_to_now);
            assert_eq!(c.cp56.zone(), Cp56Zone::Local);
        }
        let c = Iec104ProtoConfig::parse(Some(r#"{"cp56":{"rewrite_to_now":true,"zone":"UTC"}}"#))
            .unwrap();
        assert!(c.cp56.rewrite_to_now);
        assert_eq!(c.cp56.zone(), Cp56Zone::Utc);
        // Legacy aliases still accepted.
        let c = Iec104ProtoConfig::parse(Some(
            r#"{"cp56":{"rewrite_cp56_to_now":true,"cp56_zone":"local"}}"#,
        ))
        .unwrap();
        assert!(c.cp56.rewrite_to_now);
        for bad in [
            r#"{"cp56":{"rewrite_to_now":"true"}}"#,
            r#"{"cp56":{"rewrite_to_nwo":true}}"#,
            r#"{"cp56":{"zone":"cet"}}"#,
            r#"{"cp56":"#,
            r#"{"cp56":5}"#,
        ] {
            assert!(Iec104ProtoConfig::parse(Some(bad)).is_err(), "{bad}");
            assert!(validate_proto_config(Some(bad)).is_err(), "{bad}");
        }
        assert!(validate_proto_config(Some(r#"{"ioa":{"x":1}}"#)).is_err());
        assert!(validate_proto_config(Some(r#"{"ioa":{"1":2},"cp56":{"zone":"utc"}}"#)).is_ok());
    }

    #[test]
    fn cp56_local_rejects_invalid_fields() {
        let good = encode_cp56time2a_local(PI_DAY_2024_NS, false);
        assert!(decode_cp56time2a_local(&good).is_some());
        let mut b = good;
        b[5] = 0; // month 0
        assert!(decode_cp56time2a_local(&b).is_none());
        let mut b = good;
        b[5] = 13;
        assert!(decode_cp56time2a_local(&b).is_none());
        let mut b = good;
        b[4] &= 0xe0; // day 0
        assert!(decode_cp56time2a_local(&b).is_none());
        let mut b = good;
        b[3] = (b[3] & 0x80) | 24; // hour 24
        assert!(decode_cp56time2a_local(&b).is_none());
        let mut b = good;
        b[0] = 0x60;
        b[1] = 0xea; // 60000 ms
        assert!(decode_cp56time2a_local(&b).is_none());
    }

    /// Local-zone CP56 decoding across the Europe/Oslo DST transitions.
    /// glibc reads `TZ` process-wide, so the checks run in a child
    /// process of this test binary with `TZ=Europe/Oslo` (see
    /// `oslo_dst_child`). Skipped when the tz database is not installed.
    #[test]
    fn cp56_local_dst_transitions_europe_oslo() {
        if !std::path::Path::new("/usr/share/zoneinfo/Europe/Oslo").exists() {
            eprintln!("skipping: /usr/share/zoneinfo/Europe/Oslo not installed");
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args([
                "--ignored",
                "--exact",
                "asdu::tests::oslo_dst_child",
                "--nocapture",
            ])
            .env("TZ", "Europe/Oslo")
            .env("OUTSTATION_OSLO_DST_CHILD", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "child failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(stdout.contains("1 passed"), "child did not run: {stdout}");
    }

    /// Child half of `cp56_local_dst_transitions_europe_oslo`. Only does
    /// anything when launched by the parent with `TZ=Europe/Oslo`.
    #[test]
    #[ignore = "run by cp56_local_dst_transitions_europe_oslo with TZ=Europe/Oslo"]
    fn oslo_dst_child() {
        if std::env::var_os("OUTSTATION_OSLO_DST_CHILD").is_none() {
            return;
        }
        const S: u64 = 1_000_000_000;
        // Build a local-time CP56 stamp by hand: 2024-mm-dd hh:mm:00.
        let stamp = |month: u8, day: u8, hour: u8, minute: u8, su: bool| -> [u8; 7] {
            [
                0,
                0,
                minute,
                hour | if su { 0x80 } else { 0 },
                day,
                month,
                24,
            ]
        };
        let dec = |b: [u8; 7]| decode_cp56time2a_local(&b).map(|(ns, _)| ns / S);

        // DST ends 2024-10-27 03:00 CEST -> 02:00 CET. 02:30 occurs twice.
        // 02:30 CEST = 00:30 UTC = 1729989000; 02:30 CET = 01:30 UTC.
        assert_eq!(dec(stamp(10, 27, 2, 30, true)), Some(1_729_989_000));
        assert_eq!(dec(stamp(10, 27, 2, 30, false)), Some(1_729_992_600));
        // Outside the ambiguous hour the TZ rules win over a wrong SU:
        // 2024-11-05 12:00 is CET (11:00 UTC) whatever SU says.
        assert_eq!(dec(stamp(11, 5, 12, 0, false)), Some(1_730_804_400));
        assert_eq!(dec(stamp(11, 5, 12, 0, true)), Some(1_730_804_400));
        // 2024-07-01 12:00 is CEST (10:00 UTC), even with SU=0.
        assert_eq!(dec(stamp(7, 1, 12, 0, true)), Some(1_719_828_000));
        assert_eq!(dec(stamp(7, 1, 12, 0, false)), Some(1_719_828_000));
        // DST starts 2024-03-31 02:00 CET -> 03:00 CEST. 01:59 CET and
        // 03:00 CEST are one minute apart in real time.
        let before = dec(stamp(3, 31, 1, 59, false)).unwrap();
        let after = dec(stamp(3, 31, 3, 0, true)).unwrap();
        assert_eq!(before, 1_711_846_740);
        assert_eq!(after - before, 60);
        // 02:30 on that day does not exist; it still decodes (to a time
        // inside the transition window) rather than to the epoch.
        let gap = dec(stamp(3, 31, 2, 30, false)).unwrap();
        assert!((before - 3600..=after + 3600).contains(&gap), "gap={gap}");

        // Encoder/decoder round trip every 10 minutes across both
        // transition days.
        for start in [1_711_839_600u64, 1_729_980_000] {
            for k in 0..(6 * 6) {
                let t = start + k * 600;
                let b = encode_cp56time2a_local(t * S, false);
                assert_eq!(dec(b), Some(t), "round trip at {t} bytes={b:x?}");
            }
        }
    }

    #[test]
    fn session_config_parse_and_validate() {
        let c = Iec104ProtoConfig::parse(Some(
            r#"{"cot":{"3":5},"session":{"k":20,"w":10,"t0":5,"t1":2.5,"t2":0.5,"t3":4,"idle_serve_secs":0}}"#,
        ))
        .unwrap();
        assert_eq!(c.session.k, 20);
        assert_eq!(c.session.w, 10);
        assert_eq!(c.session.t0, Some(5.0));
        assert_eq!(c.session.t1, 2.5);
        assert_eq!(c.session.t2, 0.5);
        assert_eq!(c.session.t3, 4.0);
        assert_eq!(c.session.idle_serve_secs, Some(0.0));
        assert!(c.session.warnings().is_empty());
        // The rewrite-map loader ignores the session section.
        assert!(validate_proto_config(Some(r#"{"session":{"k":4,"w":2}}"#)).is_ok());
        // w above 2k/3 is only a warning.
        let c = Iec104ProtoConfig::parse(Some(r#"{"session":{"k":12,"w":12}}"#)).unwrap();
        assert_eq!(c.session.warnings().len(), 1);
        for bad in [
            r#"{"session":{"t1":10,"t2":10}}"#,
            r#"{"session":{"t2":20}}"#,
            r#"{"session":{"k":0}}"#,
            r#"{"session":{"w":40000}}"#,
            r#"{"session":{"t3":-1}}"#,
            r#"{"session":{"t0":0}}"#,
            r#"{"session":{"idle_serve_secs":-2}}"#,
            r#"{"session":{"kk":3}}"#,
        ] {
            assert!(Iec104ProtoConfig::parse(Some(bad)).is_err(), "{bad}");
            assert!(validate_proto_config(Some(bad)).is_err(), "{bad}");
        }
    }
}
