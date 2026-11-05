//! Pcap library storage: ids, sidecars, quick inspection, viability.

use std::path::{Path as StdPath, PathBuf};

use pcapload::load;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

// ---------------------------------------------------------------------------
// Pcap library: upload, list, rename, delete.
//
// Files live in `<library_dir>/pcr_<nanos>.pcap` with a sibling
// `pcr_<nanos>.json` sidecar holding the display name + quick-inspect
// metadata. The id is the filename stem (no extension).

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LibraryEntry {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) uploaded_at_ms: u64,
    pub(crate) size_bytes: u64,
    pub(crate) packets: u64,
    pub(crate) ip_sources: u64,
    pub(crate) non_ip_sources: u64,
    pub(crate) tcp_flows: u64,
    pub(crate) duration_ms: f64,
    /// Absolute UTC start / end of the pcap (unix epoch ms), so the
    /// UI can show "captured 2026-02-14 — 2026-02-14" alongside the
    /// duration. Makes it easy to spot when the pcap is old enough
    /// that SCADA will treat its CP56Time2a stamps as stale.
    #[serde(default)]
    pub(crate) pcap_start_unix_ms: Option<u64>,
    #[serde(default)]
    pub(crate) pcap_end_unix_ms: Option<u64>,
    /// Number of source IPs whose MAC was ambiguous in the pcap
    /// (multiple MACs observed for the same IP). Surfaced in the UI
    /// so the user knows the replay-side MAC is a "most-common" pick.
    #[serde(default)]
    pub(crate) mac_collisions: u64,
    /// Optional viability advisory computed at upload time.
    /// Older library entries written before this field existed
    /// deserialize with `viability: None` thanks to serde(default).
    #[serde(default)]
    pub(crate) viability: Option<Viability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Viability {
    /// Sum of TCP payload bytes from the client side of all
    /// server_port=2404 flows. Approximates the master-mode wire load.
    pub(crate) client_payload_bytes: u64,
    /// Sum of TCP payload bytes from the server side of all
    /// server_port=2404 flows. Approximates the slave-mode wire load.
    pub(crate) server_payload_bytes: u64,
    /// Distinct client IPs observed talking to port 2404. This is
    /// the number of sessions a master-mode benchmark would spawn.
    pub(crate) sessions_master_mode: u64,
    /// Distinct server IPs observed listening on port 2404. This is
    /// the number of listeners a slave-mode benchmark would spawn.
    pub(crate) sessions_slave_mode: u64,
    /// Rough peak working-set estimate in MB for replaying this
    /// pcap, accounting for the parsed packet store, per-session
    /// payloads (post move-out), reservoir sample buffers and a
    /// per-thread stack budget. Worst-case of master vs slave.
    pub(crate) estimated_peak_mb: u64,
    /// One of: "ok", "caution", "heavy", "not_recommended".
    pub(crate) verdict: String,
    /// Human-readable reason for the verdict.
    pub(crate) verdict_reason: String,
    /// Extra observations the UI can render as bullet notes.
    pub(crate) notes: Vec<String>,
    /// Per-RTU breakdown for slave-mode (one entry per server IP).
    /// Drives the run-config "select RTUs" picker + traffic chart.
    #[serde(default)]
    pub(crate) slave_rtus: Vec<RtuTraffic>,
    /// Same shape per master client (master-mode picker).
    #[serde(default)]
    pub(crate) master_clients: Vec<RtuTraffic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RtuTraffic {
    pub(crate) ip: String,
    pub(crate) payload_bytes: u64,
    pub(crate) messages: u64,
    pub(crate) duration_ms: u64,
}

impl From<protoplay::RtuTraffic> for RtuTraffic {
    fn from(p: protoplay::RtuTraffic) -> Self {
        Self {
            ip: p.ip,
            payload_bytes: p.payload_bytes,
            messages: p.messages,
            duration_ms: p.duration_ms,
        }
    }
}

pub(crate) fn library_entry_id_valid(id: &str) -> bool {
    !id.is_empty()
        && id.len() < 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

pub(crate) fn library_pcap_path(dir: &StdPath, id: &str) -> Result<PathBuf, AppError> {
    if !library_entry_id_valid(id) {
        return Err(AppError::BadRequest(format!("invalid pcap id: {id}")));
    }
    let p = dir.join(format!("{id}.pcap"));
    if !p.exists() {
        return Err(AppError::NotFound(format!("pcap id not found: {id}")));
    }
    Ok(p)
}

pub(crate) fn library_sidecar_path(dir: &StdPath, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

pub(crate) fn load_library_entry(dir: &StdPath, id: &str) -> Option<LibraryEntry> {
    let bytes = std::fs::read(library_sidecar_path(dir, id)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub(crate) fn save_library_entry(dir: &StdPath, entry: &LibraryEntry) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(entry).unwrap();
    std::fs::write(library_sidecar_path(dir, &entry.id), bytes)
}

pub(crate) struct QuickInspect {
    pub(crate) packets: u64,
    pub(crate) ip_sources: u64,
    pub(crate) non_ip_sources: u64,
    pub(crate) tcp_flows: u64,
    pub(crate) duration_ms: f64,
    pub(crate) pcap_start_unix_ms: Option<u64>,
    pub(crate) pcap_end_unix_ms: Option<u64>,
    pub(crate) mac_collisions: u64,
    pub(crate) viability: Option<Viability>,
}

pub(crate) fn quick_inspect(path: &StdPath) -> QuickInspect {
    match load(path) {
        Ok(p) => {
            let viability = compute_viability(&p, path);
            let mac_collisions = p.sources.values().filter(|s| s.mac_collision).count() as u64;
            QuickInspect {
                packets: p.packets.len() as u64,
                ip_sources: p.sources.len() as u64,
                non_ip_sources: p.non_ip_sources.len() as u64,
                tcp_flows: p.flows.len() as u64,
                duration_ms: (p.last_ts_ns.saturating_sub(p.first_ts_ns)) as f64 / 1e6,
                pcap_start_unix_ms: (p.first_ts_ns > 0).then_some(p.first_ts_ns / 1_000_000),
                pcap_end_unix_ms: (p.last_ts_ns > 0).then_some(p.last_ts_ns / 1_000_000),
                mac_collisions,
                viability: Some(viability),
            }
        }
        Err(_) => QuickInspect {
            packets: 0,
            ip_sources: 0,
            non_ip_sources: 0,
            tcp_flows: 0,
            duration_ms: 0.0,
            pcap_start_unix_ms: None,
            pcap_end_unix_ms: None,
            mac_collisions: 0,
            viability: None,
        },
    }
}

/// Walk the loaded pcap and compute a feasibility advisory aimed at
/// the IEC 104 benchmark workflow. Counts unique client/server IPs on
/// port 2404, sums TCP payload bytes per direction, and produces a
/// bucketed verdict. Cheap enough to run on every upload.
/// Adapter that lets a [`pcapload::LoadedPcap`] satisfy the
/// [`protoplay::LoadedPcapView`] contract without dragging pcapload
/// into protoplay or duplicating types. Each protocol replayer's
/// `quick_viability` impl walks this view, so the same loaded pcap
/// can be analysed by IEC 104 today and Modbus / DNP3 / etc. when
/// they implement the trait.
pub(crate) struct LoadedPcapAdapter<'a> {
    pub(crate) inner: &'a pcapload::LoadedPcap,
}

impl<'a> protoplay::LoadedPcapView for LoadedPcapAdapter<'a> {
    fn flows(&self) -> Box<dyn Iterator<Item = protoplay::FlowView> + '_> {
        Box::new(
            self.inner
                .flows
                .iter()
                .enumerate()
                .map(|(idx, f)| protoplay::FlowView {
                    flow_idx: idx,
                    client: f.client,
                    server: f.server,
                    saw_syn: f.saw_syn,
                }),
        )
    }
    fn flow_payload_bytes(&self, flow_idx: usize) -> (u64, u64) {
        let cb = self
            .inner
            .reassemble_client_payload(flow_idx)
            .map(|rf| rf.payload.len() as u64)
            .unwrap_or(0);
        let sb = self
            .inner
            .reassemble_server_payload(flow_idx)
            .map(|rf| rf.payload.len() as u64)
            .unwrap_or(0);
        (cb, sb)
    }
    fn flow_server_payload(&self, flow_idx: usize) -> Vec<u8> {
        self.inner
            .reassemble_server_payload(flow_idx)
            .map(|rf| rf.payload.to_vec())
            .unwrap_or_default()
    }
}

/// Convert a generic [`protoplay::ProtoViability`] into the
/// JSON-serialised [`Viability`] shape the HTTP response uses. Field
/// names are preserved 1:1 so existing UI code keeps working.
pub(crate) fn viability_from_proto(p: protoplay::ProtoViability) -> Viability {
    Viability {
        client_payload_bytes: p.client_payload_bytes,
        server_payload_bytes: p.server_payload_bytes,
        sessions_master_mode: p.sessions_master_mode,
        sessions_slave_mode: p.sessions_slave_mode,
        estimated_peak_mb: p.estimated_peak_mb,
        verdict: p.verdict,
        verdict_reason: p.verdict_reason,
        notes: p.notes,
        slave_rtus: p.slave_rtus.into_iter().map(Into::into).collect(),
        master_clients: p.master_clients.into_iter().map(Into::into).collect(),
    }
}

pub(crate) fn compute_viability(p: &pcapload::LoadedPcap, path: &StdPath) -> Viability {
    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let view = LoadedPcapAdapter { inner: p };
    // Today only IEC 104 is wired in. When a future caller supplies
    // the protocol name (e.g. taken from the upload metadata), look
    // it up via proto_registry::lookup(name) instead and dispatch.
    let replayer = proto_registry::lookup("iec104").expect("iec104 replayer always registered");
    let proto = replayer.quick_viability(&view, file_size);
    viability_from_proto(proto)
}
