//! Host network probing helpers (ip, arping).

use std::net::Ipv4Addr;

pub(crate) fn find_local_ip_iface(ip: &Ipv4Addr) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let target = ip.to_string();
    for line in s.lines() {
        // format: "N: <iface> inet X.X.X.X/NN ..."
        let mut it = line.split_ascii_whitespace();
        let _idx = it.next()?;
        let iface = it.next()?;
        let _inet = it.next()?;
        let Some(addr_cidr) = it.next() else {
            continue;
        };
        let addr = addr_cidr
            .split_once('/')
            .map(|(a, _)| a)
            .unwrap_or(addr_cidr);
        if addr == target {
            return Some(iface.trim_end_matches(':').to_string());
        }
    }
    None
}

pub(crate) fn extract_mac(s: &str) -> Option<String> {
    // find any AA:BB:CC:DD:EE:FF pattern
    let bytes = s.as_bytes();
    for i in 0..bytes.len().saturating_sub(16) {
        let slice = &s[i..i + 17];
        if slice.chars().enumerate().all(|(j, c)| match j % 3 {
            0 | 1 => c.is_ascii_hexdigit(),
            2 => c == ':',
            _ => false,
        }) {
            return Some(slice.to_lowercase());
        }
    }
    None
}

pub(crate) fn default_route_iface() -> std::io::Result<String> {
    let out = std::process::Command::new("ip")
        .args(["-o", "route", "get", "1.1.1.1"])
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other("ip route get failed"));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    // format: "1.1.1.1 via X.X.X.X dev <iface> src ..."
    let mut it = s.split_ascii_whitespace();
    while let Some(tok) = it.next() {
        if tok == "dev" {
            if let Some(dev) = it.next() {
                return Ok(dev.to_string());
            }
        }
    }
    Err(std::io::Error::other("no dev in `ip route get` output"))
}
