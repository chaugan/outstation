//! Host-NIC protection.
//!
//! The web UI is reachable over the LAN without authentication, so the
//! library itself refuses requests that would cut the host off its
//! network, whatever a request says:
//!
//! * enslaving a NIC to a replay bridge, or
//! * adding IP aliases to a NIC
//!
//! is refused for loopback, our own `pcr*` interfaces, and (unless
//! [`Protection::force`] is set) for:
//!
//! * any interface that carries a default route (IPv4 or IPv6, any
//!   routing table);
//! * any interface carrying an address listed in
//!   [`Protection::protected_addrs`] (the web server passes its own
//!   local address here);
//! * real bridges (`/sys/class/net/<if>/bridge` exists);
//! * existing bridge ports (`/sys/class/net/<if>/brport` exists).

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use tracing::warn;

use crate::names::{validate_host_ifname, IFNAME_PREFIX};

/// What the caller wants protected, plus the override.
#[derive(Debug, Clone, Default)]
pub struct Protection {
    /// Addresses whose interfaces must never be enslaved or aliased.
    /// The web UI passes the local address the HTTP request arrived on.
    pub protected_addrs: Vec<IpAddr>,
    /// Allow protected NICs anyway (explicit operator override). Never
    /// overrides the absolute refusals (loopback, missing interface,
    /// our own interfaces, invalid names).
    pub force: bool,
}

impl Protection {
    pub fn new(protected_addrs: Vec<IpAddr>, force: bool) -> Self {
        Self {
            protected_addrs,
            force,
        }
    }
}

/// Why a NIC is protected. Empty means the NIC is fair game.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NicAssessment {
    /// Refusals `force` cannot override.
    pub fatal: Vec<String>,
    /// Refusals `force` can override.
    pub protected: Vec<String>,
}

impl NicAssessment {
    pub fn is_clear(&self) -> bool {
        self.fatal.is_empty() && self.protected.is_empty()
    }
}

/// Network facts a NIC assessment depends on. Split out of the live
/// probes so the decision logic is unit-testable.
#[derive(Debug, Clone, Default)]
pub struct HostNetFacts {
    pub exists: bool,
    pub loopback: bool,
    pub is_bridge: bool,
    pub is_bridge_port: bool,
    pub default_route_ifaces: Vec<String>,
    pub iface_addrs: Vec<IpAddr>,
}

/// Pure decision function: which rules does `iface` trip?
pub fn assess_nic(iface: &str, facts: &HostNetFacts, prot: &Protection) -> NicAssessment {
    let mut a = NicAssessment::default();
    if let Err(e) = validate_host_ifname(iface) {
        a.fatal.push(format!("{e:#}"));
        return a;
    }
    if !facts.exists {
        a.fatal.push(format!("interface {iface} does not exist"));
        return a;
    }
    if facts.loopback || iface == "lo" {
        a.fatal.push(format!("{iface} is the loopback interface"));
    }
    if iface.starts_with(IFNAME_PREFIX) {
        a.fatal
            .push(format!("{iface} is an outstation-managed interface"));
    }
    if facts.default_route_ifaces.iter().any(|d| d == iface) {
        a.protected
            .push(format!("{iface} carries the host's default route"));
    }
    let hits: Vec<String> = prot
        .protected_addrs
        .iter()
        .filter(|p| facts.iface_addrs.contains(p))
        .map(|p| p.to_string())
        .collect();
    if !hits.is_empty() {
        a.protected.push(format!(
            "{iface} carries protected address(es) {} (e.g. the web UI's own address)",
            hits.join(", ")
        ));
    }
    if facts.is_bridge {
        a.protected.push(format!("{iface} is an existing bridge"));
    }
    if facts.is_bridge_port {
        a.protected
            .push(format!("{iface} is already a port of another bridge"));
    }
    a
}

/// Collect [`HostNetFacts`] for `iface` from the live system.
pub fn probe_nic(iface: &str) -> Result<HostNetFacts> {
    validate_host_ifname(iface)?;
    let sys = Path::new("/sys/class/net").join(iface);
    let exists = sys.exists() || crate::iface_exists(iface).unwrap_or(false);
    let flags = std::fs::read_to_string(sys.join("flags"))
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    const IFF_LOOPBACK: u32 = 0x8;
    Ok(HostNetFacts {
        exists,
        loopback: flags & IFF_LOOPBACK != 0,
        is_bridge: is_bridge(iface),
        is_bridge_port: is_bridge_port(iface),
        default_route_ifaces: default_route_ifaces().unwrap_or_default(),
        iface_addrs: iface_addrs(iface).unwrap_or_default(),
    })
}

/// Probe and assess `iface` without deciding.
pub fn nic_assessment(iface: &str, prot: &Protection) -> NicAssessment {
    match probe_nic(iface) {
        Ok(f) => assess_nic(iface, &f, prot),
        Err(e) => NicAssessment {
            fatal: vec![format!("{e:#}")],
            protected: Vec::new(),
        },
    }
}

/// Refuse `iface` for `purpose` ("enslave", "alias", ...) if it trips
/// any rule. Protected-but-forced NICs are allowed with a warning.
pub fn check_nic_allowed(iface: &str, purpose: &str, prot: &Protection) -> Result<()> {
    let a = nic_assessment(iface, prot);
    decide(iface, purpose, &a, prot.force)
}

fn decide(iface: &str, purpose: &str, a: &NicAssessment, force: bool) -> Result<()> {
    if !a.fatal.is_empty() {
        bail!("refusing to {purpose} {iface}: {}", a.fatal.join("; "));
    }
    if !a.protected.is_empty() {
        if force {
            warn!(iface, purpose, reasons = ?a.protected, "protected NIC used because force is set");
            return Ok(());
        }
        bail!(
            "refusing to {purpose} {iface}: {}. Pick another interface, or set force \
             to override if you are sure",
            a.protected.join("; ")
        );
    }
    Ok(())
}

/// True if `iface` is a Linux bridge.
pub fn is_bridge(iface: &str) -> bool {
    validate_host_ifname(iface).is_ok()
        && Path::new("/sys/class/net")
            .join(iface)
            .join("bridge")
            .exists()
}

/// True if `iface` is enslaved to a bridge.
pub fn is_bridge_port(iface: &str) -> bool {
    validate_host_ifname(iface).is_ok()
        && Path::new("/sys/class/net")
            .join(iface)
            .join("brport")
            .exists()
}

fn route_devs_and_gateways(args: &[&str]) -> Result<Vec<(Option<String>, Option<IpAddr>)>> {
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
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(parse_default_routes(&text))
}

/// Parse `ip route show table all` output, keeping only default routes.
/// Returns `(dev, via)` for each (multipath `nexthop` lines included).
pub fn parse_default_routes(text: &str) -> Vec<(Option<String>, Option<IpAddr>)> {
    let mut out = Vec::new();
    let mut in_default = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let is_continuation = line.starts_with(char::is_whitespace);
        if !is_continuation {
            let mut toks = trimmed.split_ascii_whitespace();
            let mut first = toks.next();
            // Skip a leading route type ("unicast", "blackhole", ...).
            if matches!(first, Some("unicast")) {
                first = toks.next();
            }
            in_default = matches!(first, Some("default") | Some("0.0.0.0/0") | Some("::/0"));
            if !in_default {
                continue;
            }
        } else if !in_default {
            continue;
        }
        let toks: Vec<&str> = trimmed.split_ascii_whitespace().collect();
        let dev = toks
            .windows(2)
            .find(|w| w[0] == "dev")
            .map(|w| w[1].to_string());
        let via = toks
            .windows(2)
            .find(|w| w[0] == "via")
            .and_then(|w| w[1].parse::<IpAddr>().ok());
        if dev.is_some() || via.is_some() {
            out.push((dev, via));
        }
    }
    out
}

/// Every interface that carries a default route, IPv4 or IPv6, in any
/// routing table.
pub fn default_route_ifaces() -> Result<Vec<String>> {
    let mut v = Vec::new();
    for fam in ["-4", "-6"] {
        for (dev, _) in route_devs_and_gateways(&[fam, "route", "show", "table", "all"])? {
            if let Some(d) = dev {
                if !v.contains(&d) {
                    v.push(d);
                }
            }
        }
    }
    Ok(v)
}

/// IPv4 next hops of all default routes (the LAN gateways).
pub fn default_gateways_v4() -> Result<Vec<Ipv4Addr>> {
    let mut v = Vec::new();
    for (_, via) in route_devs_and_gateways(&["-4", "route", "show", "table", "all"])? {
        if let Some(IpAddr::V4(g)) = via {
            if !v.contains(&g) {
                v.push(g);
            }
        }
    }
    Ok(v)
}

/// All IPv4 and IPv6 addresses on `iface`.
pub fn iface_addrs(iface: &str) -> Result<Vec<IpAddr>> {
    validate_host_ifname(iface)?;
    let out = Command::new("ip")
        .args(["-o", "addr", "show", "dev", iface])
        .output()
        .context("spawn `ip -o addr show`")?;
    if !out.status.success() {
        bail!(
            "ip addr show dev {iface} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(parse_addr_lines(&String::from_utf8_lossy(&out.stdout))
        .into_iter()
        .map(|(_, a)| a)
        .collect())
}

/// All local addresses with their interface.
pub fn all_local_addrs() -> Result<Vec<(String, IpAddr)>> {
    let out = Command::new("ip")
        .args(["-o", "addr", "show"])
        .output()
        .context("spawn `ip -o addr show`")?;
    if !out.status.success() {
        bail!(
            "ip addr show failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(parse_addr_lines(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse `ip -o addr show` output into `(iface, addr)` pairs.
pub fn parse_addr_lines(text: &str) -> Vec<(String, IpAddr)> {
    let mut v = Vec::new();
    for line in text.lines() {
        let mut it = line.split_ascii_whitespace();
        let _idx = it.next();
        let Some(iface) = it.next() else { continue };
        let iface = iface.trim_end_matches(':');
        let iface = iface.split_once('@').map_or(iface, |(n, _)| n).to_string();
        let Some(fam) = it.next() else { continue };
        if fam != "inet" && fam != "inet6" {
            continue;
        }
        let Some(cidr) = it.next() else { continue };
        let addr = cidr.split_once('/').map_or(cidr, |(a, _)| a);
        if let Ok(a) = addr.parse::<IpAddr>() {
            v.push((iface, a));
        }
    }
    v
}

/// Facts an alias-IP decision depends on.
#[derive(Debug, Clone, Default)]
pub struct AliasIpFacts {
    pub gateways: Vec<Ipv4Addr>,
}

/// Pure check of an IPv4 address outstation is about to add as an
/// alias. Refuses addresses that can never be a sensible RTU/gateway
/// alias, the host's own default gateways, and protected addresses.
/// `force` does not override any of these.
pub fn assess_alias_ip(ip: Ipv4Addr, facts: &AliasIpFacts, prot: &Protection) -> Result<()> {
    if ip.is_unspecified() {
        bail!("{ip} is the unspecified address");
    }
    if ip.is_loopback() {
        bail!("{ip} is a loopback address");
    }
    if ip.is_multicast() {
        bail!("{ip} is a multicast address");
    }
    if ip.is_broadcast() {
        bail!("{ip} is the broadcast address");
    }
    if ip.octets()[0] >= 240 {
        bail!("{ip} is in the reserved 240.0.0.0/4 range");
    }
    if ip.octets()[0] == 0 {
        bail!("{ip} is in 0.0.0.0/8 (\"this network\")");
    }
    if facts.gateways.contains(&ip) {
        bail!("{ip} is this host's default gateway; aliasing it would hijack the LAN's router");
    }
    if prot.protected_addrs.contains(&IpAddr::V4(ip)) {
        bail!("{ip} is a protected address");
    }
    Ok(())
}

/// Live version of [`assess_alias_ip`].
pub fn validate_alias_ip(ip: Ipv4Addr, prot: &Protection) -> Result<()> {
    let facts = AliasIpFacts {
        gateways: default_gateways_v4().unwrap_or_default(),
    };
    assess_alias_ip(ip, &facts, prot).map_err(|e| anyhow::anyhow!("refusing to alias {ip}: {e:#}"))
}

/// Pure check for an address about to be put on one of our own bridge
/// ports (master-mode session source IPs): the [`assess_alias_ip`]
/// rules always apply, and an address already configured on a host
/// interface outside our `pcr*` ports is refused unless `force`, since
/// binding it to a replay port would steal it from that interface.
pub fn assess_port_ip(
    ip: Ipv4Addr,
    local_addrs: &[(String, IpAddr)],
    facts: &AliasIpFacts,
    prot: &Protection,
) -> Result<()> {
    assess_alias_ip(ip, facts, prot)?;
    let holders: Vec<&str> = local_addrs
        .iter()
        .filter(|(iface, a)| *a == IpAddr::V4(ip) && !iface.starts_with(IFNAME_PREFIX))
        .map(|(iface, _)| iface.as_str())
        .collect();
    if !holders.is_empty() {
        if prot.force {
            warn!(%ip, ?holders, "port IP already on a host interface; allowed because force is set");
        } else {
            bail!(
                "{ip} is already configured on host interface(s) {}; \
                 set force to use it as a replay source address anyway",
                holders.join(", ")
            );
        }
    }
    Ok(())
}

/// Live version of [`assess_port_ip`].
pub fn validate_port_ip(ip: Ipv4Addr, prot: &Protection) -> Result<()> {
    let facts = AliasIpFacts {
        gateways: default_gateways_v4().unwrap_or_default(),
    };
    let local = all_local_addrs()?;
    assess_port_ip(ip, &local, &facts, prot)
        .map_err(|e| anyhow::anyhow!("refusing source address {ip}: {e:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> HostNetFacts {
        HostNetFacts {
            exists: true,
            default_route_ifaces: vec!["eth0".into()],
            ..Default::default()
        }
    }

    #[test]
    fn plain_nic_is_clear() {
        let a = assess_nic("eth1", &facts(), &Protection::default());
        assert!(a.is_clear(), "{a:?}");
        assert!(decide("eth1", "enslave", &a, false).is_ok());
    }

    #[test]
    fn default_route_nic_refused_unless_forced() {
        let a = assess_nic("eth0", &facts(), &Protection::default());
        assert_eq!(a.protected.len(), 1);
        let e = decide("eth0", "enslave", &a, false).unwrap_err();
        assert!(format!("{e}").contains("default route"), "{e}");
        assert!(decide("eth0", "enslave", &a, true).is_ok());
    }

    #[test]
    fn protected_addr_nic_refused() {
        let mut f = facts();
        f.iface_addrs = vec!["192.168.1.5".parse().unwrap()];
        let p = Protection::new(vec!["192.168.1.5".parse().unwrap()], false);
        let a = assess_nic("eth1", &f, &p);
        assert!(a.protected[0].contains("192.168.1.5"));
        assert!(decide("eth1", "alias", &a, false).is_err());
    }

    #[test]
    fn bridges_and_ports_refused() {
        let mut f = facts();
        f.is_bridge = true;
        assert!(!assess_nic("br0", &f, &Protection::default()).is_clear());
        let mut f = facts();
        f.is_bridge_port = true;
        assert!(!assess_nic("eth3", &f, &Protection::default()).is_clear());
    }

    #[test]
    fn fatal_reasons_ignore_force() {
        let mut f = facts();
        f.loopback = true;
        let a = assess_nic("lo", &f, &Protection::default());
        assert!(decide("lo", "enslave", &a, true).is_err());
        let a = assess_nic("pcr1_br", &facts(), &Protection::default());
        assert!(decide("pcr1_br", "enslave", &a, true).is_err());
        let mut f = facts();
        f.exists = false;
        let a = assess_nic("eth9", &f, &Protection::default());
        assert!(decide("eth9", "enslave", &a, true).is_err());
        let a = assess_nic("../x", &facts(), &Protection::default());
        assert!(decide("../x", "enslave", &a, true).is_err());
    }

    #[test]
    fn default_route_parsing() {
        let text = "default via 192.168.1.1 dev enp41s0 proto dhcp metric 100\n\
                    10.0.0.0/24 dev eth1 proto kernel scope link src 10.0.0.1\n\
                    default dev wg0 table 51820 scope link\n\
                    default proto static metric 1024\n\
                    \tnexthop via 10.9.9.1 dev eth2 weight 1\n\
                    \tnexthop via 10.9.9.2 dev eth3 weight 1\n\
                    local 10.0.0.1 dev eth1 table local proto kernel\n";
        let r = parse_default_routes(text);
        let devs: Vec<_> = r.iter().filter_map(|(d, _)| d.clone()).collect();
        assert_eq!(devs, vec!["enp41s0", "wg0", "eth2", "eth3"]);
        let gws: Vec<_> = r.iter().filter_map(|(_, g)| *g).collect();
        assert_eq!(gws.len(), 3);
    }

    #[test]
    fn addr_parsing() {
        let text = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n\
                    2: eth0    inet6 fe80::1/64 scope link \\       valid_lft forever\n\
                    5: v0@v1    inet 10.1.1.1/32 scope global v0\n";
        let v = parse_addr_lines(text);
        assert_eq!(v.len(), 3);
        assert_eq!(v[2].0, "v0");
        assert_eq!(v[2].1, "10.1.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn port_ip_rules() {
        let f = AliasIpFacts {
            gateways: vec![Ipv4Addr::new(192, 168, 1, 1)],
        };
        let local: Vec<(String, IpAddr)> = vec![
            ("eth0".into(), "192.168.1.10".parse().unwrap()),
            ("pcr1_b0".into(), "10.5.5.5".parse().unwrap()),
        ];
        let p = Protection::default();
        // Captured client IP that is free: fine.
        assert!(assess_port_ip(Ipv4Addr::new(10, 5, 5, 6), &local, &f, &p).is_ok());
        // Already on one of our own ports (shared master_bind_ip): fine.
        assert!(assess_port_ip(Ipv4Addr::new(10, 5, 5, 5), &local, &f, &p).is_ok());
        // The host's management address: refused unless forced.
        let mgmt = Ipv4Addr::new(192, 168, 1, 10);
        let e = assess_port_ip(mgmt, &local, &f, &p).unwrap_err();
        assert!(format!("{e}").contains("eth0"), "{e}");
        assert!(assess_port_ip(mgmt, &local, &f, &Protection::new(vec![], true)).is_ok());
        // Absolute refusals stay absolute even with force.
        let forced = Protection::new(vec![], true);
        assert!(assess_port_ip(Ipv4Addr::new(192, 168, 1, 1), &local, &f, &forced).is_err());
        assert!(assess_port_ip(Ipv4Addr::LOCALHOST, &local, &f, &forced).is_err());
    }

    #[test]
    fn alias_ip_rules() {
        let f = AliasIpFacts {
            gateways: vec![Ipv4Addr::new(192, 168, 1, 1)],
        };
        let p = Protection::new(vec!["10.0.0.5".parse().unwrap()], true);
        assert!(assess_alias_ip(Ipv4Addr::new(10, 20, 30, 40), &f, &p).is_ok());
        for bad in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(250, 1, 1, 1),
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 5),
        ] {
            assert!(assess_alias_ip(bad, &f, &p).is_err(), "{bad} accepted");
        }
    }
}
