//! Run requests: the `POST /api/run` body, its validation, and the
//! scheduler configuration built from it.
//!
//! Shared by the web server (`POST /api/run`, re-runs, profiles) and
//! the headless `outstation bench` CLI, so both build identical
//! configurations from the same JSON (T09). The validated request is
//! persisted with each run as `request` (T08).

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;

use netctl::parse_mac;
use sched::{BenchmarkConfig, ConcurrencyModel, RunConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Raw,
    Benchmark,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleReq {
    Master,
    Slave,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacingReq {
    Fast,
    Original,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConcurrencyReq {
    AllAtOnce,
    Staggered,
}

/// Body of `POST /api/run`, a stored run's `request`, a profile's
/// `request` and the `outstation bench --profile` file. Unknown enum
/// values are rejected (422 over HTTP, F056); the pcap is referenced by
/// library id only (F052, F148). Serializing a deserialized request
/// gives its canonical form, with every default filled in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRequest {
    /// Rejected when present: raw filesystem paths are not accepted.
    #[serde(default, skip_serializing)]
    pub pcap: Option<serde_json::Value>,
    #[serde(default)]
    pub pcap_id: Option<String>,
    pub target_ip: Ipv4Addr,
    /// Required for raw replay; ignored in benchmark mode.
    #[serde(default)]
    pub target_mac: String,
    #[serde(default)]
    pub nic: Option<String>,
    /// Accepted for compatibility and IGNORED: names derive from the
    /// run id (F035). Never echoed back.
    #[serde(default = "default_bridge", skip_serializing)]
    pub bridge: String,
    /// Accepted for compatibility and IGNORED, like `bridge`.
    #[serde(default = "default_tap_prefix", skip_serializing)]
    pub tap_prefix: String,
    #[serde(default = "default_speed")]
    pub speed: f64,
    #[serde(default)]
    pub top_speed: bool,
    #[serde(default)]
    pub realtime: bool,
    #[serde(default)]
    pub skip_non_ip: bool,
    #[serde(default)]
    pub only_src: Vec<Ipv4Addr>,
    /// Pre-run RTU subset (slave: server IPs; master: client IPs).
    #[serde(default)]
    pub selected_rtus: Vec<Ipv4Addr>,
    /// Slave-mode only: loop the script within one TCP session.
    #[serde(default)]
    pub loop_within_session: bool,
    #[serde(default = "default_warmup")]
    pub warmup_secs: u64,
    #[serde(default = "default_mode")]
    pub mode: RunMode,
    #[serde(default = "default_target_port")]
    pub target_port: u16,
    #[serde(default = "default_proto_name")]
    pub proto_name: String,
    #[serde(default = "default_concurrency")]
    pub concurrency: ConcurrencyReq,
    #[serde(default)]
    pub proto_config: Option<String>,
    #[serde(default = "default_role")]
    pub role: RoleReq,
    #[serde(default = "default_listen_port_base")]
    pub listen_port_base: u16,
    #[serde(default = "default_pacing")]
    pub pacing: PacingReq,
    /// Number of times to repeat the captured script. `0` = unlimited.
    #[serde(default = "default_iterations")]
    pub iterations: u64,
    #[serde(default)]
    pub scada_gateway_ip: Option<Ipv4Addr>,
    #[serde(default)]
    pub scada_gateway_iface: Option<String>,
    #[serde(default)]
    pub upstream_nat_iface: Option<String>,
    #[serde(default)]
    pub master_bind_ip: Option<Ipv4Addr>,
    #[serde(default)]
    pub tcp_nodelay: Option<bool>,
    /// Slave mode: interface that receives RTU listen-IP aliases when
    /// they are not already local. Defaults to the default-route NIC,
    /// which is protected (refused unless `force`).
    #[serde(default)]
    pub alias_iface: Option<String>,
    /// Operator override for netctl's NIC / address protection (default
    /// route NIC, the address this UI is reached on, bridge ports,
    /// addresses held by other interfaces). Absolute refusals
    /// (loopback, gateway, multicast, …) still apply.
    #[serde(default)]
    pub force: bool,
}

fn default_iterations() -> u64 {
    1
}
fn default_pacing() -> PacingReq {
    PacingReq::Fast
}
fn default_role() -> RoleReq {
    RoleReq::Master
}
fn default_listen_port_base() -> u16 {
    2404
}
fn default_mode() -> RunMode {
    RunMode::Raw
}
fn default_target_port() -> u16 {
    2404
}
fn default_concurrency() -> ConcurrencyReq {
    ConcurrencyReq::AllAtOnce
}
fn default_warmup() -> u64 {
    5
}
fn default_bridge() -> String {
    "pcr_br0".into()
}
fn default_tap_prefix() -> String {
    "pcr_t".into()
}
fn default_speed() -> f64 {
    1.0
}
fn default_proto_name() -> String {
    crate::dto::default_proto_name()
}

/// Longest warmup accepted, in seconds.
pub const MAX_WARMUP_SECS: u64 = 3600;

/// A request that failed validation. `code` is the API error code
/// (`invalid_request`, `raw_path_rejected`, `protocol_not_ready`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for RequestError {}

fn bad(msg: impl Into<String>) -> RequestError {
    RequestError {
        code: "invalid_request",
        message: msg.into(),
    }
}

/// Interface-name check: kernel IFNAMSIZ (15 usable chars), no
/// wildcard (`+`), no option-like leading `-` (F042).
pub fn validate_ifname(field: &str, name: &str, max_len: usize) -> Result<(), RequestError> {
    let ok = !name.is_empty()
        && name.len() <= max_len
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if ok {
        Ok(())
    } else {
        Err(bad(format!(
            "{field}: {name:?} is not a valid interface name (1..={max_len} chars of \
             [A-Za-z0-9._-], not starting with '-')"
        )))
    }
}

/// Every check except "which pcap": used for profiles (which may be
/// pcap-agnostic) and by the CLI (which takes `--pcap`). Raw paths are
/// still rejected.
pub fn validate_settings(req: &RunRequest) -> Result<(), RequestError> {
    if req.pcap.is_some() {
        return Err(RequestError {
            code: "raw_path_rejected",
            message: "raw filesystem paths are not accepted; upload the pcap to the library \
                      and pass its pcap_id"
                .into(),
        });
    }
    if !(req.speed.is_finite() && (0.001..=1000.0).contains(&req.speed)) {
        return Err(bad(format!(
            "speed must be a finite number in 0.001..=1000, got {}",
            req.speed
        )));
    }
    if req.warmup_secs > MAX_WARMUP_SECS {
        return Err(bad(format!("warmup_secs must be <= {MAX_WARMUP_SECS}")));
    }
    validate_ifname("bridge", &req.bridge, 15)?;
    validate_ifname("tap_prefix", &req.tap_prefix, 10)?;
    for (field, v) in [
        ("nic", &req.nic),
        ("scada_gateway_iface", &req.scada_gateway_iface),
        ("upstream_nat_iface", &req.upstream_nat_iface),
        ("alias_iface", &req.alias_iface),
    ] {
        if let Some(n) = v.as_deref().filter(|s| !s.is_empty()) {
            validate_ifname(field, n, 15)?;
        }
    }
    if req.scada_gateway_ip.is_some()
        != req
            .scada_gateway_iface
            .as_deref()
            .is_some_and(|s| !s.is_empty())
    {
        return Err(bad(
            "scada_gateway_ip and scada_gateway_iface must be given together",
        ));
    }
    if let Some(pc) = req.proto_config.as_deref().filter(|s| !s.trim().is_empty()) {
        serde_json::from_str::<serde_json::Value>(pc)
            .map_err(|e| bad(format!("proto_config is not valid JSON: {e}")))?;
    }
    if let Some(id) = req.pcap_id.as_deref().filter(|s| !s.is_empty()) {
        if !crate::library::library_entry_id_valid(id) {
            return Err(RequestError {
                code: "invalid_id",
                message: format!("pcap_id {id:?} is not a library id"),
            });
        }
    }
    match req.mode {
        RunMode::Raw => {
            parse_mac(&req.target_mac).map_err(|e| bad(format!("target_mac: {e}")))?;
        }
        RunMode::Benchmark => {
            if req.target_port == 0 {
                return Err(bad("target_port must be 1..=65535"));
            }
            // Every slave listens on this same port, each on its own
            // listen IP (sched gives every session `listen_port_base`),
            // so only the port itself needs checking.
            if req.role == RoleReq::Slave && req.listen_port_base == 0 {
                return Err(bad("listen_port_base must be 1..=65535"));
            }
            let Some(rep) = proto_registry::lookup(&req.proto_name) else {
                return Err(bad(format!("unknown proto_name: {}", req.proto_name)));
            };
            if rep.readiness() == protoplay::Readiness::Stub {
                return Err(RequestError {
                    code: "protocol_not_ready",
                    message: format!(
                        "protocol {} is a stub and cannot run benchmarks yet",
                        req.proto_name
                    ),
                });
            }
            // Protocol-specific config (IEC 104: rewrite map, cp56,
            // session timers, commands, fault plan) is checked now, so
            // a typo is a 400 on submit, not a failed session later.
            let pc = req.proto_config.as_deref().filter(|s| !s.trim().is_empty());
            rep.validate_config(pc).map_err(|e| {
                let msg = format!("{e:#}");
                RequestError {
                    code: "invalid_proto_config",
                    // Protocol errors already name the section, e.g.
                    // "proto_config (faults): …", which the UI maps onto
                    // the matching editor field.
                    message: if msg.starts_with("proto_config") {
                        msg
                    } else {
                        format!("proto_config: {msg}")
                    },
                }
            })?;
        }
    }
    Ok(())
}

/// Full validation of a `POST /api/run` body: a library `pcap_id` is
/// required on top of [`validate_settings`].
pub fn validate_request(req: &RunRequest) -> Result<(), RequestError> {
    if req.pcap.is_none() && req.pcap_id.as_deref().unwrap_or("").is_empty() {
        return Err(bad("pcap_id is required"));
    }
    validate_settings(req)
}

/// The canonical JSON of a request: defaults filled in, ignored and
/// rejected fields dropped.
pub fn canonical_json(req: &RunRequest) -> serde_json::Value {
    serde_json::to_value(req).unwrap_or(serde_json::Value::Null)
}

/// Parse a request from JSON (an HTTP body, a stored run's `request`,
/// a profile file).
pub fn from_json(v: serde_json::Value) -> Result<RunRequest, RequestError> {
    serde_json::from_value(v).map_err(|e| bad(format!("invalid run request: {e}")))
}

/// Scheduler configuration for a validated benchmark request.
/// `run_id` and `capture_path` are filled in by the caller once the run
/// is registered. Panics if `req.proto_name` is unknown: validate
/// first.
pub fn benchmark_config(
    req: &RunRequest,
    state_dir: &Path,
    protected_addrs: Vec<std::net::IpAddr>,
) -> (BenchmarkConfig, Arc<dyn protoplay::ProtoReplayer>) {
    let replayer = proto_registry::lookup(&req.proto_name).expect("validated proto");
    let cfg = BenchmarkConfig {
        // run_id is set once the id is allocated; bridge/tap names are
        // then derived from it (F035).
        run_id: 0,
        target_ip: req.target_ip,
        target_port: req.target_port,
        proto_name: req.proto_name.clone(),
        bridge_name: None,
        tap_prefix: None,
        egress_nic: req.nic.clone().filter(|s| !s.is_empty()),
        concurrency: match req.concurrency {
            ConcurrencyReq::Staggered => ConcurrencyModel::StaggeredPcapTiming,
            ConcurrencyReq::AllAtOnce => ConcurrencyModel::AllAtOnce,
        },
        connect_timeout_secs: 5,
        startup_delay_secs: req.warmup_secs,
        capture_path: None,
        proto_config: req.proto_config.clone(),
        role: match req.role {
            RoleReq::Slave => protoplay::Role::Slave,
            RoleReq::Master => protoplay::Role::Master,
        },
        listen_port_base: req.listen_port_base,
        pacing: match req.pacing {
            PacingReq::Original => protoplay::Pacing::OriginalTiming { speed: req.speed },
            PacingReq::Fast => protoplay::Pacing::AsFastAsPossible,
        },
        iterations: req.iterations,
        scada_gateway_ip: req.scada_gateway_ip,
        scada_gateway_iface: req.scada_gateway_iface.clone(),
        upstream_nat_iface: req.upstream_nat_iface.clone().filter(|s| !s.is_empty()),
        state_dir: Some(state_dir.to_path_buf()),
        protected_addrs,
        force_protected_nic: req.force,
        alias_iface: req.alias_iface.clone().filter(|s| !s.is_empty()),
        master_bind_ip: req.master_bind_ip,
        tcp_nodelay: req.tcp_nodelay,
        selected_endpoints: if req.selected_rtus.is_empty() {
            None
        } else {
            Some(req.selected_rtus.iter().copied().collect())
        },
        loop_within_session: req.loop_within_session,
    };
    (cfg, replayer)
}

/// Scheduler configuration for a validated raw-replay request.
pub fn raw_config(
    req: &RunRequest,
    state_dir: &Path,
    protected_addrs: Vec<std::net::IpAddr>,
) -> RunConfig {
    RunConfig {
        run_id: 0,
        target_ip: req.target_ip,
        target_mac: parse_mac(&req.target_mac).expect("validated mac"),
        bridge_name: None,
        tap_prefix: None,
        egress_nic: req.nic.clone().filter(|s| !s.is_empty()),
        speed: req.speed,
        top_speed: req.top_speed,
        realtime: req.realtime,
        filter_sources: if req.only_src.is_empty() {
            None
        } else {
            Some(req.only_src.clone())
        },
        include_non_ip: !req.skip_non_ip,
        startup_delay_secs: req.warmup_secs,
        capture_path: None,
        iterations: req.iterations,
        state_dir: Some(state_dir.to_path_buf()),
        protected_addrs,
        force_protected_nic: req.force,
    }
}

/// Run facts the analyser needs that only the request knows (F060,
/// F066): whether iterations looped inside one session, the pacing
/// speed, and the source pcap's server port.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AnalysisFacts {
    pub loop_within_session: bool,
    /// `Some(speed)` when the run replayed original timing.
    pub paced_speed: Option<f64>,
    /// Server port of the replayed flows in the source pcap. sched
    /// selects flows by `target_port` in both roles; in slave role the
    /// captured side listens on `listen_port_base` instead.
    pub source_port: u16,
}

pub fn analysis_facts(req: &RunRequest) -> AnalysisFacts {
    AnalysisFacts {
        // Master role reconnects per iteration; only slave role can
        // loop inside one session.
        loop_within_session: req.role == RoleReq::Slave && req.loop_within_session,
        paced_speed: (req.pacing == PacingReq::Original).then_some(req.speed),
        source_port: req.target_port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bench(extra: serde_json::Value) -> RunRequest {
        let mut v = json!({"pcap_id": "pcr_1", "target_ip": "10.0.0.50",
            "mode": "benchmark", "role": "slave"});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        from_json(v).unwrap()
    }

    #[test]
    fn canonical_form_round_trips_and_drops_ignored_fields() {
        let r = bench(json!({"bridge": "pcr_x", "warmup_secs": 0}));
        let v = canonical_json(&r);
        assert!(v.get("bridge").is_none() && v.get("tap_prefix").is_none());
        assert!(v.get("pcap").is_none());
        assert_eq!(v["iterations"], 1);
        assert_eq!(v["listen_port_base"], 2404);
        let again = canonical_json(&from_json(v.clone()).unwrap());
        assert_eq!(v, again);
    }

    #[test]
    fn slave_port_is_checked_alone() {
        // T07b: every slave shares the port; 200 RTUs on 65535 is fine.
        let rtus: Vec<String> = (1..=200).map(|n| format!("10.1.0.{n}")).collect();
        let r = bench(json!({"listen_port_base": 65535, "selected_rtus": rtus}));
        assert!(validate_settings(&r).is_ok());
        let r = bench(json!({"listen_port_base": 0}));
        let e = validate_settings(&r).unwrap_err();
        assert!(e.message.contains("listen_port_base"), "{}", e.message);
    }

    #[test]
    fn settings_validation_does_not_need_a_pcap() {
        let mut r = bench(json!({}));
        r.pcap_id = None;
        assert!(validate_settings(&r).is_ok());
        assert_eq!(validate_request(&r).unwrap_err().code, "invalid_request");
        r.pcap = Some(json!("/etc/passwd"));
        assert_eq!(validate_settings(&r).unwrap_err().code, "raw_path_rejected");
        let mut r = bench(json!({"pcap_id": "../x"}));
        assert!(validate_settings(&r).is_err());
        r.pcap_id = Some("pcr_1".into());
        r.speed = f64::NAN;
        assert!(validate_settings(&r).is_err());
    }

    #[test]
    fn facts_follow_role_and_pacing() {
        let f = analysis_facts(&bench(json!({"loop_within_session": true,
            "pacing": "original", "speed": 2.0, "target_port": 2405})));
        assert!(f.loop_within_session);
        assert_eq!(f.paced_speed, Some(2.0));
        assert_eq!(f.source_port, 2405);
        let f = analysis_facts(&bench(
            json!({"role": "master", "loop_within_session": true}),
        ));
        assert!(!f.loop_within_session, "master reconnects per iteration");
        assert_eq!(f.paced_speed, None);
    }
}
