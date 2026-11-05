//! NIC listing, ARP and IP verification endpoints.

use std::net::Ipv4Addr;

use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::netprobe::*;

#[derive(Deserialize)]
pub(crate) struct VerifyIpReq {
    pub(crate) ip: String,
    #[serde(default)]
    pub(crate) iface: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct VerifyIpResp {
    pub(crate) ip: String,
    pub(crate) iface: String,
    pub(crate) in_use: bool,
    /// True if the IP is already assigned to one of this host's
    /// interfaces. When false + in_use=false, the webui tells the
    /// user the IP will be auto-aliased onto the egress interface
    /// when the slave is started.
    pub(crate) locally_assigned: bool,
    pub(crate) mac: Option<String>,
    pub(crate) error: Option<String>,
}

/// Probe an IP to see if it's already taken. Two sources of truth:
///   1. `ip -4 -o addr show` — if the host already owns the IP on any
///      interface, we report "local host" immediately (arping would
///      otherwise come back as "no reply" because the host kernel
///      doesn't ARP-reply to its own addresses).
///   2. `arping -D` — duplicate-address detection probe on the
///      relevant interface. Responds? Someone else owns it.
pub(crate) async fn api_verify_ip(
    Json(req): Json<VerifyIpReq>,
) -> Result<Json<VerifyIpResp>, AppError> {
    // 0.0.0.0 is the "any" sentinel — always valid, skip probing.
    if req.ip.trim() == "0.0.0.0" {
        return Ok(Json(VerifyIpResp {
            ip: "0.0.0.0".into(),
            iface: "any".into(),
            in_use: false,
            locally_assigned: true,
            mac: None,
            error: None,
        }));
    }
    let ip: Ipv4Addr = req
        .ip
        .parse()
        .map_err(|e| AppError::BadRequest(format!("bad ip {:?}: {e}", req.ip)))?;
    let iface = match req.iface {
        Some(i) => i,
        None => default_route_iface()
            .map_err(|e| AppError::Internal(format!("detect default iface: {e}")))?,
    };

    // Check host's own addresses first.
    if let Some(local_iface) = find_local_ip_iface(&ip) {
        return Ok(Json(VerifyIpResp {
            ip: ip.to_string(),
            iface: local_iface,
            in_use: true,
            locally_assigned: true,
            mac: Some("local host".into()),
            error: None,
        }));
    }

    // arping -D -c 2 -w 2 -I <iface> <ip>
    let out = std::process::Command::new("arping")
        .args(["-D", "-c", "2", "-w", "2", "-I", &iface, &ip.to_string()])
        .output();
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            return Ok(Json(VerifyIpResp {
                ip: ip.to_string(),
                iface,
                in_use: false,
                locally_assigned: false,
                mac: None,
                error: Some(format!(
                    "arping not available: {e}. apt install iputils-arping"
                )),
            }));
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // arping -D with iputils semantics: exit 1 means "someone replied
    // (conflict)", exit 0 means "no reply". Also parse the stdout —
    // presence of "Unicast reply" or "reply from" is a strong signal.
    let in_use =
        !out.status.success() || stdout.contains("reply from") || stdout.contains("Unicast reply");
    let mac = extract_mac(&stdout).or_else(|| extract_mac(&stderr));
    Ok(Json(VerifyIpResp {
        ip: ip.to_string(),
        iface,
        in_use,
        locally_assigned: false,
        mac,
        error: None,
    }))
}

#[derive(Serialize)]
pub(crate) struct NicJson {
    pub(crate) name: String,
    pub(crate) mac: Option<String>,
    pub(crate) ipv4: Vec<String>,
    pub(crate) up: bool,
    pub(crate) loopback: bool,
    pub(crate) bridge: bool,
}

pub(crate) async fn api_nics() -> Result<Json<Vec<NicJson>>, AppError> {
    let nics = netctl::list_nics().map_err(|e| AppError::Internal(format!("list nics: {e}")))?;
    let out = nics
        .into_iter()
        .map(|n| NicJson {
            name: n.name,
            mac: n.mac.map(netctl::format_mac),
            ipv4: n.ipv4.into_iter().map(|ip| ip.to_string()).collect(),
            up: n.up,
            loopback: n.loopback,
            bridge: n.bridge,
        })
        .collect();
    Ok(Json(out))
}

#[derive(Deserialize)]
pub(crate) struct ArpReq {
    pub(crate) ip: String,
    #[serde(default)]
    pub(crate) iface: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct ArpResp {
    pub(crate) ip: String,
    pub(crate) iface: String,
    pub(crate) mac: Option<String>,
    pub(crate) error: Option<String>,
}

/// Send an ARP request via `arping` and return the responding MAC.
/// Used by the UI's "ARP" button next to the target_mac field so the
/// user doesn't have to type it.
pub(crate) async fn api_arp(Json(req): Json<ArpReq>) -> Result<Json<ArpResp>, AppError> {
    let ip: Ipv4Addr = req
        .ip
        .parse()
        .map_err(|e| AppError::BadRequest(format!("bad ip {:?}: {e}", req.ip)))?;
    let iface = match req.iface {
        Some(i) if !i.is_empty() => i,
        _ => default_route_iface()
            .map_err(|e| AppError::Internal(format!("detect default iface: {e}")))?,
    };

    // If the IP is one of our own local addresses, return the local MAC immediately.
    if let Some(local_iface) = find_local_ip_iface(&ip) {
        let mac = netctl::list_nics().ok().and_then(|nics| {
            nics.into_iter()
                .find(|n| n.name == local_iface)
                .and_then(|n| n.mac.map(netctl::format_mac))
        });
        return Ok(Json(ArpResp {
            ip: ip.to_string(),
            iface: local_iface,
            mac,
            error: None,
        }));
    }

    let out = std::process::Command::new("arping")
        .args(["-c", "2", "-w", "2", "-I", &iface, &ip.to_string()])
        .output();
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            return Ok(Json(ArpResp {
                ip: ip.to_string(),
                iface,
                mac: None,
                error: Some(format!(
                    "arping not available: {e}. apt install iputils-arping"
                )),
            }));
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mac = extract_mac(&stdout).or_else(|| extract_mac(&stderr));
    if mac.is_none() {
        let msg = format!(
            "no ARP reply within 2 s (is the host live and on the same L2 segment as {iface}?)"
        );
        return Ok(Json(ArpResp {
            ip: ip.to_string(),
            iface,
            mac: None,
            error: Some(msg),
        }));
    }
    Ok(Json(ArpResp {
        ip: ip.to_string(),
        iface,
        mac,
        error: None,
    }))
}
