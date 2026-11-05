//! Command echo: how the impersonated RTU (slave role) answers the
//! control-direction commands of a live master, plus the shared rules
//! the replayer, the link's command metrics and the post-run analyzer
//! use to recognise command exchanges.
//!
//! Like [`crate::responder`] for GI/CI, the builder here is pure: it
//! takes the command ASDU and the point inventory and returns the ASDUs
//! a real outstation would send back, in wire order. The live link
//! queues them behind the same k-window and flood caps as GI/CI
//! responses and tags them as synthesized.
//!
//! | command | answer |
//! |---|---|
//! | C_SC/C_DC/C_RC (45/46/47), C_SE_NA/NB/NC (48/49/50), C_BO (51) and the time-tagged 58..=64, COT 6, S/E = 1 (select) | ActCon (COT 7) |
//! | same, S/E = 0 (execute; C_BO has no S/E) | ActCon, optional return information, ActTerm (COT 10) |
//! | same, COT 8 (deactivate) | DeactCon (COT 9) |
//! | C_RD_NA_1 (102), COT 5 | the point's current value with COT 5 (requested) |
//! | C_CS_NA_1 (103) clock sync, COT 6 | ActCon with the time echoed |
//! | C_RP_NA_1 (105) reset process, C_TS_TA_1 (107) test, COT 6 | ActCon |
//!
//! Rejections are mirrors of the command with P/N = 1:
//!
//! * unknown type (any control-direction type not listed above) → COT 44;
//! * a COT the type does not take → COT 45;
//! * unknown common address (or broadcast for anything but 103/105) → COT 46;
//! * unknown IOA → COT 47 (process commands with `unknown_ioa:
//!   "negative"`, reads of a point the inventory lacks, system
//!   commands whose IOA is not 0);
//! * time-tagged command older (or newer) than `max_age_ms`, a
//!   double/regulating command with a not-permitted state (0 or 3), or
//!   a malformed ASDU → negative ActCon (COT 7) / DeactCon (COT 9).
//!
//! A process command's IOA is known when the capture shows the RTU
//! confirming a command at that address ([`CommandBook`]) or carries a
//! monitor point at it. Return information (`return_info`:
//! `"spontaneous"` = COT 3, `"retrem"` = COT 11) is sent only when the
//! inventory has a monitor point at the commanded (CA, IOA) whose type
//! can carry the commanded value; the point's stored value is updated
//! so later GI/read answers reflect the command.

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::asdu::{
    common_address, cot_value, decode_cp56time2a, decode_cp56time2a_local, element_len,
    encode_cp56time2a, encode_cp56time2a_local, read_ioa, write_ioa, Cp56Zone, DUI_LEN, IOA_LEN,
};
use crate::inventory::{Inventory, CA_BROADCAST};

/// `proto_config` key of the command-echo section.
pub const COMMANDS_KEY: &str = "commands";

pub const COT_SPONTANEOUS: u8 = 3;
pub const COT_REQUEST: u8 = 5;
pub const COT_ACT: u8 = 6;
pub const COT_ACT_CON: u8 = 7;
pub const COT_DEACT: u8 = 8;
pub const COT_DEACT_CON: u8 = 9;
pub const COT_ACT_TERM: u8 = 10;
pub const COT_RETREM: u8 = 11;
pub const COT_UNKNOWN_TYPE: u8 = 44;
pub const COT_UNKNOWN_COT: u8 = 45;
pub const COT_UNKNOWN_CA: u8 = 46;
pub const COT_UNKNOWN_IOA: u8 = 47;

/// Largest accepted `max_age_ms` (one day).
pub const MAX_AGE_LIMIT_MS: u64 = 86_400_000;

/// Return information after an executed command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReturnInfo {
    /// No monitor update.
    #[default]
    None,
    /// Monitor update with COT 3 (spontaneous).
    Spontaneous,
    /// Monitor update with COT 11 (return information, remote command).
    Retrem,
}

/// What to do with a process command for an IOA the capture never
/// showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownIoa {
    /// Negative ActCon, COT 47.
    #[default]
    Negative,
    /// Answer as if the IOA were known.
    Accept,
}

/// `proto_config.commands`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandsConfig {
    /// Answer control-direction commands in slave mode. Default on.
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub return_info: ReturnInfo,
    /// Time-tagged commands whose CP56Time2a differs from our clock by
    /// more than this are rejected. 0 disables the check.
    #[serde(default = "default_max_age_ms")]
    pub max_age_ms: u64,
    #[serde(default)]
    pub unknown_ioa: UnknownIoa,
}

fn default_true() -> bool {
    true
}

fn default_max_age_ms() -> u64 {
    10_000
}

impl Default for CommandsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            return_info: ReturnInfo::None,
            max_age_ms: default_max_age_ms(),
            unknown_ioa: UnknownIoa::Negative,
        }
    }
}

impl CommandsConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.max_age_ms > MAX_AGE_LIMIT_MS {
            anyhow::bail!(
                "commands.max_age_ms must be <= {MAX_AGE_LIMIT_MS}, got {}",
                self.max_age_ms
            );
        }
        Ok(())
    }
}

/// The command-echo settings of a run, read leniently (malformed JSON
/// or a bad `commands` object gives the default). For the analyzer;
/// the run itself validates strictly via
/// [`crate::asdu::Iec104ProtoConfig::parse`].
pub fn commands_config(proto_config: Option<&str>) -> CommandsConfig {
    let Some(s) = proto_config.map(str::trim).filter(|s| !s.is_empty()) else {
        return CommandsConfig::default();
    };
    serde_json::from_str::<serde_json::Value>(s)
        .ok()
        .and_then(|v| v.get(COMMANDS_KEY).cloned())
        .and_then(|c| serde_json::from_value(c).ok())
        .unwrap_or_default()
}

/// Process commands: 45..=51 and their time-tagged variants 58..=64.
pub fn is_process_command(type_id: u8) -> bool {
    matches!(type_id, 45..=51 | 58..=64)
}

/// Types a controlling station sends that the command echo handles or
/// rejects: everything from 45 up except end of initialisation (70)
/// and GI/CI (100/101, answered by [`crate::responder`]).
pub fn is_command_type(type_id: u8) -> bool {
    type_id >= 45 && !matches!(type_id, 70 | 100 | 101)
}

/// Is this frame, sent by a controlled station, part of a captured
/// command exchange: a command mirror (ActCon, DeactCon, ActTerm, or a
/// COT 44..=47 rejection) or data requested by a read command (COT 5)?
/// With command echo on, the slave strips these from its script (it
/// answers the live master instead) and the analyzer drops them from
/// the expected side.
pub fn is_captured_command_frame(asdu: &[u8]) -> bool {
    if asdu.len() < DUI_LEN {
        return false;
    }
    let cot = cot_value(asdu);
    if is_command_type(asdu[0]) {
        return matches!(cot, COT_ACT_CON | COT_DEACT_CON | COT_ACT_TERM | 44..=47);
    }
    asdu[0] < 45 && cot == COT_REQUEST
}

/// Is this ASDU (from a controlling station) a request the command
/// echo or the master-side metrics treat as a command: a command type
/// with COT 5 (read), 6 or 8?
pub fn is_command_request(asdu: &[u8]) -> bool {
    asdu.len() >= DUI_LEN
        && (is_command_type(asdu[0]) || matches!(asdu[0], 100 | 101))
        && matches!(cot_value(asdu), COT_REQUEST | COT_ACT | COT_DEACT)
}

/// Command addresses learned from the capture: every (CA, IOA) at
/// which the RTU confirmed or rejected a process command.
#[derive(Debug, Clone, Default)]
pub struct CommandBook {
    points: BTreeSet<(u16, u32)>,
}

impl CommandBook {
    /// Learn from one server-side ASDU (SQ=0 only; command mirrors
    /// always carry one object).
    pub fn ingest_asdu(&mut self, asdu: &[u8]) {
        if asdu.len() >= DUI_LEN + IOA_LEN && is_process_command(asdu[0]) {
            self.points
                .insert((common_address(asdu), read_ioa(asdu, DUI_LEN)));
        }
    }

    pub fn knows(&self, ca: u16, ioa: u32) -> bool {
        self.points.contains(&(ca, ioa))
    }

    pub fn len(&self) -> usize {
        self.points.len()
    }

    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }
}

/// Role of one ASDU in a command response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    ActCon,
    DeactCon,
    /// Negative confirmation (P/N = 1).
    Negative,
    ReturnInfo,
    /// Requested data answering a read command.
    ReadReply,
    ActTerm,
}

/// Reply to one command, in wire order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandResponse {
    pub frames: Vec<(Part, Vec<u8>)>,
}

impl CommandResponse {
    fn one(part: Part, asdu: Vec<u8>) -> Self {
        Self {
            frames: vec![(part, asdu)],
        }
    }

    pub fn negative(&self) -> bool {
        self.frames.iter().any(|(p, _)| *p == Part::Negative)
    }

    pub fn into_asdus(self) -> Vec<Vec<u8>> {
        self.frames.into_iter().map(|(_, a)| a).collect()
    }
}

/// Inputs of [`respond_command`] besides the command and inventory.
#[derive(Debug, Clone, Copy)]
pub struct CommandContext<'a> {
    pub cfg: &'a CommandsConfig,
    pub book: &'a CommandBook,
    /// Wall clock for the time-tag age check and the return
    /// information's time tag.
    pub now_unix_ns: u64,
    pub zone: Cp56Zone,
}

/// The command's mirror with `cot` and the P/N bit set; T and OA are
/// kept.
fn mirror(cmd: &[u8], cot: u8, negative: bool) -> Vec<u8> {
    let mut a = cmd.to_vec();
    a[2] = (cmd[2] & 0x80) | if negative { 0x40 } else { 0 } | (cot & 0x3f);
    a
}

/// Offset (within the element) of the byte carrying S/E, if any.
fn qualifier_offset(type_id: u8) -> Option<usize> {
    match type_id {
        45..=47 | 58..=60 => Some(0),
        48 | 49 | 61 | 62 => Some(2),
        50 | 63 => Some(4),
        _ => None, // 51 / 64: bitstring, no S/E
    }
}

/// Is `cmd` a select (S/E = 1) process command?
pub fn is_select(cmd: &[u8]) -> bool {
    cmd.len() > DUI_LEN + IOA_LEN
        && qualifier_offset(cmd[0])
            .and_then(|o| cmd.get(DUI_LEN + IOA_LEN + o))
            .is_some_and(|b| b & 0x80 != 0)
}

/// Decode a CP56Time2a in `zone`, rejecting invalid calendar fields.
fn decode_stamp(b: &[u8; 7], zone: Cp56Zone) -> Option<u64> {
    match zone {
        Cp56Zone::Local => decode_cp56time2a_local(b).map(|(t, _)| t),
        Cp56Zone::Utc => {
            let ms = u16::from_le_bytes([b[0], b[1]]);
            let ok = ms < 60_000
                && b[2] & 0x3f <= 59
                && b[3] & 0x1f <= 23
                && b[4] & 0x1f != 0
                && (1..=12).contains(&(b[5] & 0x0f));
            ok.then(|| decode_cp56time2a(b).0)
        }
    }
}

fn encode_stamp(unix_ns: u64, zone: Cp56Zone) -> [u8; 7] {
    match zone {
        Cp56Zone::Utc => encode_cp56time2a(unix_ns, false, false),
        Cp56Zone::Local => encode_cp56time2a_local(unix_ns, false),
    }
}

/// Answer one command from the live master, or `None` if `cmd` is not
/// a command (monitor-direction types, end of initialisation, GI/CI).
/// May update `inv` (return information).
pub fn respond_command(
    inv: &mut Inventory,
    ctx: &CommandContext,
    cmd: &[u8],
) -> Option<CommandResponse> {
    if cmd.len() < DUI_LEN || !is_command_type(cmd[0]) {
        return None;
    }
    let t = cmd[0];
    let cot = cot_value(cmd);
    let neg = |c: u8| Some(CommandResponse::one(Part::Negative, mirror(cmd, c, true)));
    let supported = is_process_command(t) || matches!(t, 102 | 103 | 105 | 107);
    if !supported {
        return neg(COT_UNKNOWN_TYPE);
    }
    let cot_ok = match t {
        102 => cot == COT_REQUEST,
        103 | 105 | 107 => cot == COT_ACT,
        _ => cot == COT_ACT || cot == COT_DEACT,
    };
    if !cot_ok {
        return neg(COT_UNKNOWN_COT);
    }
    let con_cot = if cot == COT_DEACT {
        COT_DEACT_CON
    } else {
        COT_ACT_CON
    };
    let elem = element_len(t).unwrap_or(0);
    if cmd[1] != 1 || cmd.len() != DUI_LEN + IOA_LEN + elem {
        // SQ=1 or N != 1, or a length that does not match the type.
        return neg(con_cot);
    }
    let ca = common_address(cmd);
    let ioa = read_ioa(cmd, DUI_LEN);
    let stations: Vec<u16> = if ca == CA_BROADCAST {
        if matches!(t, 103 | 105) {
            inv.cas.iter().copied().collect()
        } else {
            Vec::new()
        }
    } else if inv.knows_ca(ca) {
        vec![ca]
    } else {
        Vec::new()
    };
    if stations.is_empty() {
        return neg(COT_UNKNOWN_CA);
    }
    match t {
        102 => {
            let Some(e) = inv.entries.get(&(ca, ioa)) else {
                return neg(COT_UNKNOWN_IOA);
            };
            let mut a = Vec::with_capacity(DUI_LEN + IOA_LEN + e.element_body.len());
            a.extend_from_slice(&[e.type_id, 1, (cmd[2] & 0x80) | COT_REQUEST, cmd[3]]);
            a.extend_from_slice(&ca.to_le_bytes());
            a.extend_from_slice(&cmd[DUI_LEN..DUI_LEN + IOA_LEN]);
            a.extend_from_slice(&e.element_body);
            Some(CommandResponse::one(Part::ReadReply, a))
        }
        103 | 105 | 107 => {
            if ioa != 0 {
                return neg(COT_UNKNOWN_IOA);
            }
            let frames = stations
                .into_iter()
                .map(|st| {
                    let mut a = mirror(cmd, COT_ACT_CON, false);
                    a[4..6].copy_from_slice(&st.to_le_bytes());
                    (Part::ActCon, a)
                })
                .collect();
            Some(CommandResponse { frames })
        }
        _ => respond_process(inv, ctx, cmd, ca, ioa, con_cot),
    }
}

fn respond_process(
    inv: &mut Inventory,
    ctx: &CommandContext,
    cmd: &[u8],
    ca: u16,
    ioa: u32,
    con_cot: u8,
) -> Option<CommandResponse> {
    let t = cmd[0];
    let neg = |c: u8| Some(CommandResponse::one(Part::Negative, mirror(cmd, c, true)));
    let known = ctx.book.knows(ca, ioa) || inv.entries.contains_key(&(ca, ioa));
    if !known && ctx.cfg.unknown_ioa == UnknownIoa::Negative {
        return neg(COT_UNKNOWN_IOA);
    }
    let body = &cmd[DUI_LEN + IOA_LEN..];
    if matches!(t, 58..=64) && ctx.cfg.max_age_ms > 0 {
        let mut b = [0u8; 7];
        b.copy_from_slice(&body[body.len() - 7..]);
        let fresh = decode_stamp(&b, ctx.zone)
            .is_some_and(|ts| ts.abs_diff(ctx.now_unix_ns) <= ctx.cfg.max_age_ms * 1_000_000);
        if !fresh {
            return neg(con_cot);
        }
    }
    if con_cot == COT_DEACT_CON {
        return Some(CommandResponse::one(
            Part::DeactCon,
            mirror(cmd, COT_DEACT_CON, false),
        ));
    }
    // DCS / RCS 0 and 3 are "not permitted".
    if matches!(t, 46 | 47 | 59 | 60) && matches!(body[0] & 0x03, 0 | 3) {
        return neg(COT_ACT_CON);
    }
    let select = qualifier_offset(t).is_some_and(|o| body[o] & 0x80 != 0);
    let mut frames = vec![(Part::ActCon, mirror(cmd, COT_ACT_CON, false))];
    if !select {
        let cot = match ctx.cfg.return_info {
            ReturnInfo::None => None,
            ReturnInfo::Spontaneous => Some(COT_SPONTANEOUS),
            ReturnInfo::Retrem => Some(COT_RETREM),
        };
        // A test command (T = 1) is confirmed but not executed.
        if let Some(cot) = cot.filter(|_| cmd[2] & 0x80 == 0) {
            if let Some(ri) = return_info(inv, ctx, cmd, ca, ioa, cot) {
                frames.push((Part::ReturnInfo, ri));
            }
        }
        frames.push((Part::ActTerm, mirror(cmd, COT_ACT_TERM, false)));
    }
    Some(CommandResponse { frames })
}

/// Commanded value, by command family.
enum Value<'a> {
    Single(bool),
    /// Double command state (1 = off, 2 = on).
    Double(u8),
    /// Regulating step: true = higher.
    Step(bool),
    Normalized(&'a [u8]),
    Scaled(&'a [u8]),
    Float(&'a [u8]),
    Bits(&'a [u8]),
}

fn commanded_value(t: u8, body: &[u8]) -> Option<Value<'_>> {
    Some(match t {
        45 | 58 => Value::Single(body[0] & 1 != 0),
        46 | 59 => Value::Double(body[0] & 3),
        47 | 60 => Value::Step(body[0] & 3 == 2),
        48 | 61 => Value::Normalized(&body[..2]),
        49 | 62 => Value::Scaled(&body[..2]),
        50 | 63 => Value::Float(&body[..4]),
        51 | 64 => Value::Bits(&body[..4]),
        _ => return None,
    })
}

/// Monitor update for the commanded point, applied to the inventory.
/// `None` when the inventory has no point at (CA, IOA) or its type
/// cannot carry the commanded value.
fn return_info(
    inv: &mut Inventory,
    ctx: &CommandContext,
    cmd: &[u8],
    ca: u16,
    ioa: u32,
    cot: u8,
) -> Option<Vec<u8>> {
    let e = inv.entries.get(&(ca, ioa))?;
    let mt = e.type_id;
    let mut body = e.element_body.clone();
    if body.len() != element_len(mt)? {
        return None;
    }
    let value = commanded_value(cmd[0], &cmd[DUI_LEN + IOA_LEN..])?;
    match (mt, value) {
        // Single-point information (SIQ): SPI in bit 0, quality cleared.
        (1 | 2 | 30, Value::Single(v)) => body[0] = u8::from(v),
        (1 | 2 | 30, Value::Double(d)) => body[0] = u8::from(d == 2),
        // Double-point information (DIQ): DPI in bits 0-1.
        (3 | 4 | 31, Value::Double(d)) => body[0] = d,
        (3 | 4 | 31, Value::Single(v)) => body[0] = if v { 2 } else { 1 },
        // Step position (VTI, 7-bit signed) + QDS.
        (5 | 6 | 32, Value::Step(up)) => {
            let v = ((body[0] << 1) as i8) >> 1;
            let v = if up {
                v.saturating_add(1)
            } else {
                v.saturating_sub(1)
            }
            .clamp(-64, 63);
            body[0] = (v as u8) & 0x7f;
            body[1] = 0;
        }
        (7 | 8 | 33, Value::Bits(b)) => {
            body[..4].copy_from_slice(b);
            body[4] = 0;
        }
        (9 | 10 | 34, Value::Normalized(b)) | (11 | 12 | 35, Value::Scaled(b)) => {
            body[..2].copy_from_slice(b);
            body[2] = 0;
        }
        (21, Value::Normalized(b)) => body[..2].copy_from_slice(b),
        (13 | 14 | 36, Value::Float(b)) => {
            body[..4].copy_from_slice(b);
            body[4] = 0;
        }
        _ => return None,
    }
    // Fresh time tag: CP24Time2a (the low three CP56 octets) or
    // CP56Time2a, at the end of the element.
    let stamp = encode_stamp(ctx.now_unix_ns, ctx.zone);
    let n = body.len();
    match mt {
        2 | 4 | 6 | 8 | 10 | 12 | 14 => body[n - 3..].copy_from_slice(&stamp[..3]),
        30..=36 => body[n - 7..].copy_from_slice(&stamp),
        _ => {}
    }
    let mut a = vec![mt, 1, cot, cmd[3]];
    a.extend_from_slice(&ca.to_le_bytes());
    let mut ioa_buf = [0u8; IOA_LEN];
    write_ioa(&mut ioa_buf, 0, ioa);
    a.extend_from_slice(&ioa_buf);
    a.extend_from_slice(&body);
    inv.ingest_asdu(&a);
    Some(a)
}

/// Is `reply` (from a controlled station) an answer to `cmd` (from the
/// controlling station)? Used by the master-side metrics and the
/// analyzer. A broadcast command matches any station.
pub fn answers(cmd: &[u8], reply: &[u8]) -> bool {
    if cmd.len() < DUI_LEN + IOA_LEN || reply.len() < DUI_LEN + IOA_LEN {
        return false;
    }
    let ca_ok = {
        let c = common_address(cmd);
        c == CA_BROADCAST || c == common_address(reply)
    };
    let ioa_ok = read_ioa(cmd, DUI_LEN) == read_ioa(reply, DUI_LEN);
    if !(ca_ok && ioa_ok) {
        return false;
    }
    if reply[0] == cmd[0] {
        return matches!(
            cot_value(reply),
            COT_ACT_CON | COT_DEACT_CON | COT_ACT_TERM | 44..=47
        );
    }
    // Requested data answering a read.
    cmd[0] == 102 && reply[0] < 45 && cot_value(reply) == COT_REQUEST
}

/// Classify a reply that [`answers`] a command.
pub fn reply_part(reply: &[u8]) -> Part {
    let cot = cot_value(reply);
    if reply[2] & 0x40 != 0 || (44..=47).contains(&cot) {
        Part::Negative
    } else if reply[0] < 45 {
        Part::ReadReply
    } else {
        match cot {
            COT_DEACT_CON => Part::DeactCon,
            COT_ACT_TERM => Part::ActTerm,
            _ => Part::ActCon,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000_000_000_000;

    fn inv() -> Inventory {
        let mut inv = Inventory::default();
        // M_SP_NA_1 at IOA 100, M_DP_TB_1 at 200, M_ME_NC_1 at 300,
        // M_ST_NA_1 at 400 (step 5), all CA 1.
        inv.ingest_asdu(&[1, 1, 3, 0, 1, 0, 100, 0, 0, 0]);
        let mut dp = vec![31, 1, 3, 0, 1, 0, 200, 0, 0, 1];
        dp.extend_from_slice(&[0u8; 7]);
        inv.ingest_asdu(&dp);
        inv.ingest_asdu(&[13, 1, 3, 0, 1, 0, 0x2c, 1, 0, 0, 0, 0, 0, 0]);
        inv.ingest_asdu(&[5, 1, 3, 0, 1, 0, 0x90, 1, 0, 5, 0]);
        inv
    }

    fn book() -> CommandBook {
        let mut b = CommandBook::default();
        // Captured C_SC_NA_1 ActCon at IOA 5000.
        b.ingest_asdu(&[45, 1, 7, 0, 1, 0, 0x88, 0x13, 0, 1]);
        b
    }

    fn run(cfg: &CommandsConfig, inv: &mut Inventory, cmd: &[u8]) -> CommandResponse {
        let book = book();
        let ctx = CommandContext {
            cfg,
            book: &book,
            now_unix_ns: NOW,
            zone: Cp56Zone::Utc,
        };
        respond_command(inv, &ctx, cmd).expect("command")
    }

    fn cots(r: &CommandResponse) -> Vec<u8> {
        r.frames.iter().map(|(_, a)| a[2]).collect()
    }

    fn sc(ioa: u16, sco: u8) -> Vec<u8> {
        vec![45, 1, 6, 0, 1, 0, ioa as u8, (ioa >> 8) as u8, 0, sco]
    }

    #[test]
    fn select_then_execute() {
        let cfg = CommandsConfig::default();
        let mut inv = inv();
        let r = run(&cfg, &mut inv, &sc(5000, 0x81));
        assert_eq!(cots(&r), vec![7]);
        let mut mirror = sc(5000, 0x81);
        mirror[2] = 7;
        assert_eq!(r.frames[0].1, mirror);
        let r = run(&cfg, &mut inv, &sc(5000, 0x01));
        assert_eq!(cots(&r), vec![7, 10]);
        assert_eq!(r.frames[1].0, Part::ActTerm);
        // Deactivation.
        let mut d = sc(5000, 0x81);
        d[2] = 8;
        assert_eq!(cots(&run(&cfg, &mut inv, &d)), vec![9]);
    }

    #[test]
    fn rejections() {
        let cfg = CommandsConfig::default();
        let mut inv = inv();
        // Unknown IOA.
        assert_eq!(cots(&run(&cfg, &mut inv, &sc(7, 1))), vec![0x40 | 47]);
        // ... accepted when configured.
        let accept = CommandsConfig {
            unknown_ioa: UnknownIoa::Accept,
            ..CommandsConfig::default()
        };
        assert_eq!(cots(&run(&accept, &mut inv, &sc(7, 1))), vec![7, 10]);
        // Known through a monitor point at the same IOA.
        assert_eq!(cots(&run(&cfg, &mut inv, &sc(100, 1))), vec![7, 10]);
        // Unknown type (P_ME_NA_1), unknown COT, unknown CA.
        assert_eq!(
            cots(&run(
                &cfg,
                &mut inv,
                &[110, 1, 6, 0, 1, 0, 1, 0, 0, 0, 0, 0]
            )),
            vec![0x40 | 44]
        );
        let mut c = sc(5000, 1);
        c[2] = 3;
        assert_eq!(cots(&run(&cfg, &mut inv, &c)), vec![0x40 | 45]);
        let mut c = sc(5000, 1);
        c[4] = 9;
        assert_eq!(cots(&run(&cfg, &mut inv, &c)), vec![0x40 | 46]);
        // Broadcast only for clock sync / reset process.
        c[4] = 0xff;
        c[5] = 0xff;
        assert_eq!(cots(&run(&cfg, &mut inv, &c)), vec![0x40 | 46]);
        // DCS 0 is not permitted.
        assert_eq!(
            cots(&run(&cfg, &mut inv, &[46, 1, 6, 0, 1, 0, 200, 0, 0, 0])),
            vec![0x40 | 7]
        );
        // Length mismatch.
        assert_eq!(
            cots(&run(&cfg, &mut inv, &[45, 1, 6, 0, 1, 0, 100, 0, 0])),
            vec![0x40 | 7]
        );
        // Test bit and OA are echoed.
        let mut c = sc(5000, 1);
        c[2] |= 0x80;
        c[3] = 9;
        let r = run(&cfg, &mut inv, &c);
        assert_eq!(cots(&r), vec![0x87, 0x8a]);
        assert!(r.frames.iter().all(|(_, a)| a[3] == 9));
        // Not commands at all.
        let book = book();
        let ctx = CommandContext {
            cfg: &cfg,
            book: &book,
            now_unix_ns: NOW,
            zone: Cp56Zone::Utc,
        };
        assert!(respond_command(&mut inv, &ctx, &[1, 1, 3, 0, 1, 0, 1, 0, 0, 1]).is_none());
        assert!(respond_command(&mut inv, &ctx, &[100, 1, 6, 0, 1, 0, 0, 0, 0, 20]).is_none());
    }

    fn sc_ta(ioa: u16, stamp_ns: u64) -> Vec<u8> {
        let mut a = vec![58, 1, 6, 0, 1, 0, ioa as u8, (ioa >> 8) as u8, 0, 1];
        a.extend_from_slice(&encode_cp56time2a(stamp_ns, false, false));
        a
    }

    #[test]
    fn time_tagged_commands_are_age_checked() {
        let cfg = CommandsConfig::default();
        let mut inv = inv();
        let r = run(&cfg, &mut inv, &sc_ta(5000, NOW - 2_000_000_000));
        assert_eq!(cots(&r), vec![7, 10]);
        // The mirror echoes the command's own time tag.
        assert_eq!(r.frames[0].1[10..], sc_ta(5000, NOW - 2_000_000_000)[10..]);
        let r = run(&cfg, &mut inv, &sc_ta(5000, NOW - 11_000_000_000));
        assert_eq!(cots(&r), vec![0x40 | 7]);
        let r = run(&cfg, &mut inv, &sc_ta(5000, NOW + 11_000_000_000));
        assert_eq!(cots(&r), vec![0x40 | 7]);
        let off = CommandsConfig {
            max_age_ms: 0,
            ..CommandsConfig::default()
        };
        assert_eq!(cots(&run(&off, &mut inv, &sc_ta(5000, 0))), vec![7, 10]);
        // Garbage stamp.
        let mut bad = sc_ta(5000, NOW);
        bad[15] = 0; // month 0
        assert_eq!(cots(&run(&cfg, &mut inv, &bad)), vec![0x40 | 7]);
    }

    #[test]
    fn return_information_updates_the_inventory() {
        let cfg = CommandsConfig {
            return_info: ReturnInfo::Retrem,
            ..CommandsConfig::default()
        };
        let mut inv = inv();
        let r = run(&cfg, &mut inv, &sc(100, 1));
        assert_eq!(cots(&r), vec![7, 11, 10]);
        assert_eq!(r.frames[1].0, Part::ReturnInfo);
        assert_eq!(r.frames[1].1, vec![1, 1, 11, 0, 1, 0, 100, 0, 0, 1]);
        assert_eq!(inv.entries[&(1, 100)].element_body, vec![1]);
        // Double command to a timed double point: fresh CP56.
        let r = run(&cfg, &mut inv, &[46, 1, 6, 0, 1, 0, 200, 0, 0, 2]);
        let ri = &r.frames[1].1;
        assert_eq!(ri[..10], [31, 1, 11, 0, 1, 0, 200, 0, 0, 2]);
        let mut b = [0u8; 7];
        b.copy_from_slice(&ri[10..17]);
        assert_eq!(decode_cp56time2a(&b).0 / 1_000_000, NOW / 1_000_000);
        // Set-point float.
        let mut se = vec![50, 1, 6, 0, 1, 0, 0x2c, 1, 0];
        se.extend_from_slice(&1.5f32.to_le_bytes());
        se.push(0);
        let r = run(&cfg, &mut inv, &se);
        assert_eq!(r.frames[1].1[9..13], 1.5f32.to_le_bytes());
        // Regulating step higher: 5 -> 6.
        let r = run(&cfg, &mut inv, &[47, 1, 6, 0, 1, 0, 0x90, 1, 0, 2]);
        assert_eq!(r.frames[1].1[9], 6);
        // Spontaneous variant; select carries no return information.
        let spont = CommandsConfig {
            return_info: ReturnInfo::Spontaneous,
            ..CommandsConfig::default()
        };
        assert_eq!(cots(&run(&spont, &mut inv, &sc(100, 0))), vec![7, 3, 10]);
        assert_eq!(cots(&run(&spont, &mut inv, &sc(100, 0x80))), vec![7]);
        // Incompatible type (float set-point to a single point): none.
        let mut se = vec![50, 1, 6, 0, 1, 0, 100, 0, 0];
        se.extend_from_slice(&[0, 0, 0, 0, 0]);
        assert_eq!(cots(&run(&spont, &mut inv, &se)), vec![7, 10]);
    }

    #[test]
    fn read_clock_sync_reset_and_test() {
        let cfg = CommandsConfig::default();
        let mut inv = inv();
        let r = run(&cfg, &mut inv, &[102, 1, 5, 3, 1, 0, 100, 0, 0]);
        assert_eq!(
            r.frames,
            vec![(Part::ReadReply, vec![1, 1, 5, 3, 1, 0, 100, 0, 0, 0])]
        );
        let r = run(&cfg, &mut inv, &[102, 1, 5, 0, 1, 0, 101, 0, 0]);
        assert_eq!(cots(&r), vec![0x40 | 47]);
        let mut cs = vec![103, 1, 6, 0, 1, 0, 0, 0, 0];
        cs.extend_from_slice(&encode_cp56time2a(NOW, false, false));
        let r = run(&cfg, &mut inv, &cs);
        assert_eq!(cots(&r), vec![7]);
        assert_eq!(r.frames[0].1[9..], cs[9..]);
        // Broadcast clock sync: one ActCon per station.
        inv.ingest_asdu(&[1, 1, 3, 0, 2, 0, 1, 0, 0, 0]);
        cs[4] = 0xff;
        cs[5] = 0xff;
        let r = run(&cfg, &mut inv, &cs);
        let cas: Vec<u16> = r.frames.iter().map(|(_, a)| common_address(a)).collect();
        assert_eq!(cas, vec![1, 2]);
        assert_eq!(
            cots(&run(&cfg, &mut inv, &[105, 1, 6, 0, 1, 0, 0, 0, 0, 1])),
            vec![7]
        );
        let mut ts = vec![107, 1, 6, 0, 1, 0, 0, 0, 0, 0x34, 0x12];
        ts.extend_from_slice(&[0u8; 7]);
        assert_eq!(cots(&run(&cfg, &mut inv, &ts)), vec![7]);
        // C_TS_NA_1 (104) does not exist in IEC 104.
        assert_eq!(
            cots(&run(
                &cfg,
                &mut inv,
                &[104, 1, 6, 0, 1, 0, 0, 0, 0, 0xaa, 0x55]
            )),
            vec![0x40 | 44]
        );
    }

    #[test]
    fn capture_rules_and_matching() {
        assert!(is_captured_command_frame(&[45, 1, 7, 0, 1, 0, 0, 0, 0, 1]));
        assert!(is_captured_command_frame(&[45, 1, 10, 0, 1, 0, 0, 0, 0, 1]));
        assert!(is_captured_command_frame(&[103, 1, 0x47, 0, 1, 0, 0, 0, 0]));
        assert!(is_captured_command_frame(&[1, 1, 5, 0, 1, 0, 0, 0, 0, 1]));
        assert!(!is_captured_command_frame(&[1, 1, 3, 0, 1, 0, 0, 0, 0, 1]));
        assert!(!is_captured_command_frame(&[1, 1, 11, 0, 1, 0, 0, 0, 0, 1]));
        assert!(!is_captured_command_frame(&[
            100, 1, 7, 0, 1, 0, 0, 0, 0, 20
        ]));
        let cmd = sc(5000, 1);
        let mut con = cmd.clone();
        con[2] = 7;
        assert!(answers(&cmd, &con));
        assert_eq!(reply_part(&con), Part::ActCon);
        con[2] = 10;
        assert_eq!(reply_part(&con), Part::ActTerm);
        con[2] = 0x47;
        assert_eq!(reply_part(&con), Part::Negative);
        con[6] = 1;
        assert!(!answers(&cmd, &con));
        let rd = [102, 1, 5, 0, 1, 0, 100, 0, 0];
        assert!(answers(&rd, &[1, 1, 5, 0, 1, 0, 100, 0, 0, 1]));
        assert!(!answers(&rd, &[1, 1, 3, 0, 1, 0, 100, 0, 0, 1]));
        assert!(is_command_request(&rd));
        assert!(is_command_request(&[100, 1, 6, 0, 1, 0, 0, 0, 0, 20]));
        assert!(!is_command_request(&con));
    }

    #[test]
    fn lenient_config_reader() {
        assert_eq!(commands_config(None), CommandsConfig::default());
        assert!(!commands_config(Some(r#"{"commands":{"enabled":false}}"#)).enabled);
        assert_eq!(
            commands_config(Some(r#"{"commands":{"return_info":"retrem"}}"#)).return_info,
            ReturnInfo::Retrem
        );
        assert_eq!(commands_config(Some("junk")), CommandsConfig::default());
    }
}
