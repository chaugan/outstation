//! "Is this address local?" and "which interfaces carry it?".
//!
//! On Linux an IPv4 address is local when a `local` route in the
//! `local` routing table covers it, not only when it is configured on an
//! interface. The kernel installs `local 127.0.0.0/8 dev lo`, so every
//! address in 127/8 is local and bindable without an alias, and an
//! operator can add more (`ip route add local 10.9.0.0/24 dev lo`,
//! "AnyIP"). [`ip_is_local`] considers addresses on every interface,
//! every local route, and 127/8.

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::protect::all_local_addrs;

/// A `local` route: `(network, prefix length, device)`.
pub type LocalRoute = (Ipv4Addr, u8, String);

fn ip_out(args: &[&str]) -> Result<String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("spawn `ip {}`", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "`ip {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parse `ip -4 route show table local type local` output.
pub fn parse_local_routes(text: &str) -> Vec<LocalRoute> {
    let mut v = Vec::new();
    for line in text.lines() {
        let toks: Vec<&str> = line.split_ascii_whitespace().collect();
        // With `type local` iproute2 still prints the type first.
        let dst = match toks.first() {
            Some(&"local") => toks.get(1),
            Some(_) if !line.starts_with(char::is_whitespace) => toks.first(),
            _ => None,
        };
        let Some(dst) = dst else { continue };
        let (net, len) = match dst.split_once('/') {
            Some((a, l)) => (a, l.parse::<u8>().ok()),
            None => (*dst, Some(32)),
        };
        let (Ok(net), Some(len)) = (net.parse::<Ipv4Addr>(), len) else {
            continue;
        };
        if len > 32 {
            continue;
        }
        let Some(dev) = toks.windows(2).find(|w| w[0] == "dev").map(|w| w[1]) else {
            continue;
        };
        v.push((net, len, dev.to_string()));
    }
    v
}

/// The live local routes (IPv4).
pub fn local_routes_v4() -> Result<Vec<LocalRoute>> {
    Ok(parse_local_routes(&ip_out(&[
        "-4", "route", "show", "table", "local", "type", "local",
    ])?))
}

fn covers(net: Ipv4Addr, len: u8, ip: Ipv4Addr) -> bool {
    let mask = if len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(len))
    };
    u32::from(net) & mask == u32::from(ip) & mask
}

/// The interface that accepts `ip` as a local address, if any: the
/// interface holding it, else the device of the most specific local
/// route covering it, else `lo` for 127/8. Pure; see [`local_iface_of`].
pub fn local_iface_in(
    ip: Ipv4Addr,
    addrs: &[(String, IpAddr)],
    local_routes: &[LocalRoute],
) -> Option<String> {
    if let Some((iface, _)) = addrs.iter().find(|(_, a)| *a == IpAddr::V4(ip)) {
        return Some(iface.clone());
    }
    if let Some((_, _, dev)) = local_routes
        .iter()
        .filter(|(n, l, _)| covers(*n, *l, ip))
        .max_by_key(|(_, l, _)| *l)
    {
        return Some(dev.clone());
    }
    ip.is_loopback().then(|| "lo".to_string())
}

/// Pure form of [`ip_is_local`].
pub fn ip_is_local_in(
    ip: Ipv4Addr,
    addrs: &[(String, IpAddr)],
    local_routes: &[LocalRoute],
) -> bool {
    local_iface_in(ip, addrs, local_routes).is_some()
}

/// True if `ip` is local to this host (network namespace): configured
/// on any interface, covered by a local route, or in 127/8. Such an
/// address can be bound without adding an alias.
pub fn ip_is_local(ip: Ipv4Addr) -> Result<bool> {
    if ip.is_loopback() {
        return Ok(true);
    }
    let addrs = all_local_addrs()?;
    // The local table is an optional refinement: an `ip` that cannot
    // list it still answers from the address list.
    let routes = local_routes_v4().unwrap_or_default();
    Ok(ip_is_local_in(ip, &addrs, &routes))
}

/// Live form of [`local_iface_in`].
pub fn local_iface_of(ip: Ipv4Addr) -> Result<Option<String>> {
    let addrs = all_local_addrs()?;
    let routes = local_routes_v4().unwrap_or_default();
    Ok(local_iface_in(ip, &addrs, &routes))
}

/// The `dev` of `ip route get` output.
pub fn parse_route_get_dev(text: &str) -> Option<String> {
    let toks: Vec<&str> = text.split_ascii_whitespace().collect();
    toks.windows(2)
        .find(|w| w[0] == "dev")
        .map(|w| w[1].to_string())
}

/// The interface traffic from `src` to `dst` leaves on
/// (`ip route get <dst> from <src>`); `lo` when `dst` is local.
pub fn route_dev(dst: Ipv4Addr, src: Option<Ipv4Addr>) -> Result<Option<String>> {
    let d = dst.to_string();
    let s = src.map(|s| s.to_string());
    let mut args = vec!["-4", "route", "get", d.as_str()];
    if let Some(s) = s.as_deref() {
        args.extend(["from", s]);
    }
    Ok(parse_route_get_dev(&ip_out(&args)?))
}

/// Interfaces that carry the TCP sessions of a listener on the local
/// address `listen_ip` with a peer at `peer` (when known): the
/// interface accepting `listen_ip`, plus the one the route to `peer`
/// uses (`lo` when the peer is local too). Lookups that fail are
/// skipped; the result may be empty.
pub fn session_ifaces(listen_ip: Ipv4Addr, peer: Option<Ipv4Addr>) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    if let Ok(Some(i)) = local_iface_of(listen_ip) {
        v.push(i);
    }
    if let Some(p) = peer.filter(|p| !p.is_unspecified()) {
        if let Ok(Some(i)) = route_dev(p, Some(listen_ip)) {
            if !v.contains(&i) {
                v.push(i);
            }
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    const ROUTES: &str = "\
local 5.9.89.252 dev enp41s0 proto kernel scope host src 5.9.89.252
local 127.0.0.0/8 dev lo proto kernel scope host src 127.0.0.1
local 127.0.0.1 dev lo proto kernel scope host src 127.0.0.1
local 10.9.0.0/24 dev lo scope host
";

    #[test]
    fn local_routes_parse() {
        let r = parse_local_routes(ROUTES);
        assert_eq!(r.len(), 4);
        assert_eq!(r[1], (ip("127.0.0.0"), 8, "lo".to_string()));
        assert_eq!(r[0], (ip("5.9.89.252"), 32, "enp41s0".to_string()));
        assert!(parse_local_routes("garbage\n\nlocal nope dev x").is_empty());
    }

    #[test]
    fn loopback_and_anyip_are_local() {
        let addrs = vec![
            ("lo".to_string(), "127.0.0.1".parse().unwrap()),
            ("eth1".to_string(), "10.77.0.5".parse().unwrap()),
        ];
        let routes = parse_local_routes(ROUTES);
        // Every 127/8 address, even with no routes known at all.
        for a in ["127.0.0.1", "127.0.10.49", "127.255.255.254"] {
            assert!(ip_is_local_in(ip(a), &addrs, &routes), "{a}");
            assert!(ip_is_local_in(ip(a), &[], &[]), "{a} without facts");
            assert_eq!(local_iface_in(ip(a), &[], &[]).as_deref(), Some("lo"));
        }
        // An address on any interface.
        assert_eq!(
            local_iface_in(ip("10.77.0.5"), &addrs, &routes).as_deref(),
            Some("eth1")
        );
        // AnyIP: a local route to lo.
        assert_eq!(
            local_iface_in(ip("10.9.0.77"), &addrs, &routes).as_deref(),
            Some("lo")
        );
        // Not local.
        for a in ["10.77.0.6", "192.168.10.49", "10.9.1.1"] {
            assert!(!ip_is_local_in(ip(a), &addrs, &routes), "{a}");
        }
    }

    #[test]
    fn route_get_dev_parse() {
        assert_eq!(
            parse_route_get_dev("10.79.0.2 from 192.168.10.49 dev s-o uid 0 \n    cache \n")
                .as_deref(),
            Some("s-o")
        );
        assert_eq!(
            parse_route_get_dev(
                "local 127.0.0.1 dev lo src 127.0.0.1 uid 1000 \n    cache <local> \n"
            )
            .as_deref(),
            Some("lo")
        );
        assert_eq!(parse_route_get_dev("unreachable"), None);
    }

    #[test]
    fn covers_prefixes() {
        assert!(covers(ip("0.0.0.0"), 0, ip("1.2.3.4")));
        assert!(covers(ip("10.0.0.0"), 8, ip("10.255.0.1")));
        assert!(!covers(ip("10.0.0.0"), 8, ip("11.0.0.1")));
        assert!(covers(ip("10.0.0.7"), 32, ip("10.0.0.7")));
        assert!(!covers(ip("10.0.0.7"), 32, ip("10.0.0.8")));
    }
}
