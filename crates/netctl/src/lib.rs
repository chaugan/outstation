//! Manage Linux bridges and veth ports for outstation, safely.
//!
//! v1 shells out to `ip` from iproute2. This keeps the crate tiny and the
//! error messages transparent.
//!
//! Host safety is enforced here, in the library, regardless of what a
//! caller (e.g. an unauthenticated HTTP request) asks for:
//!
//! * [`names`]: interface names are strictly validated and, by default,
//!   derived from the run id; every interface we create carries an
//!   `outstation:<run_id>` ifalias marker, and reclaim only deletes
//!   marked interfaces ([`reclaim_stale`], [`reclaim_run_ifaces`]).
//! * [`protect`]: the default-route NIC, NICs carrying protected
//!   addresses, real bridges and bridge ports are never enslaved or
//!   aliased unless the caller sets an explicit `force`.
//! * [`alias`]: `/32 noprefixroute` aliases, reference-counted, and
//!   never deleting an address we did not add.
//! * [`guard`] + [`journal`]: every sysctl, offload and iptables change
//!   is journaled (locked, atomic writes) before it is applied, and
//!   [`cleanup_all`] restores the host from the journal after a crash.

use std::ffi::OsStr;
use std::process::Command;

use anyhow::{bail, Context, Result};
use tracing::{debug, warn};

pub mod alias;
pub mod cleanup;
pub mod guard;
pub mod journal;
pub mod names;
pub mod protect;

pub use alias::{
    add_ip_alias, del_ip_alias, forget_alias, ip_is_local, reclaim_recorded_aliases, record_alias,
    AliasLease, AliasOutcome,
};
pub use cleanup::{cleanup_all, iface_owner, reclaim_run_ifaces, reclaim_stale, CleanupReport};
pub use guard::{EgressGuard, GatewayGuard};
pub use journal::{aliases_path, guards_path, DEFAULT_STATE_DIR};
pub use names::{IfaceNames, PortKind};
pub use protect::{
    check_nic_allowed, is_bridge, is_bridge_port, nic_assessment, validate_alias_ip,
    validate_port_ip, NicAssessment, Protection,
};

pub type MacAddr = [u8; 6];

pub fn format_mac(mac: MacAddr) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

pub fn parse_mac(s: &str) -> Result<MacAddr> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        bail!("MAC must be XX:XX:XX:XX:XX:XX, got {s:?}");
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16)
            .with_context(|| format!("bad hex byte {p:?} in MAC {s:?}"))?;
    }
    Ok(out)
}

/// Set the `outstation:<run_id>` ownership marker on `iface`.
fn mark_owned(iface: &str, run_id: u64) -> Result<()> {
    ip([
        "link",
        "set",
        "dev",
        iface,
        "alias",
        &names::owner_marker(run_id),
    ])
}

/// A bridge plus the veth ports outstation created on it, all marked
/// with the run's ownership marker.
///
/// [`Topology::teardown`] removes everything explicitly and reports
/// errors. Dropping a topology without teardown also tears it down
/// (best effort, with a warning), so early `?` returns cannot leak
/// interfaces. Use [`Topology::leak`] to keep them on purpose.
pub struct Topology {
    pub bridge: String,
    pub taps: Vec<String>,
    run_id: u64,
    bridge_created: bool,
    /// Pre-existing NICs we enslaved; released (`nomaster`) on teardown.
    enslaved: Vec<String>,
    done: bool,
}

impl Topology {
    /// A topology for `bridge`, owned by `run_id`. The bridge name must
    /// pass [`names::validate_prefix`] (`^pcr[a-z0-9_]{0,8}$`).
    pub fn new(bridge: impl Into<String>, run_id: u64) -> Result<Self> {
        let bridge = bridge.into();
        names::validate_prefix(&bridge).context("bridge name")?;
        Ok(Self {
            bridge,
            taps: Vec::new(),
            run_id,
            bridge_created: false,
            enslaved: Vec::new(),
            done: false,
        })
    }

    pub fn run_id(&self) -> u64 {
        self.run_id
    }

    /// Create the bridge, mark it as ours and bring it up. Refuses to
    /// reuse an interface that already exists: a stale one of ours
    /// must be reclaimed first ([`reclaim_run_ifaces`]), and a foreign
    /// one is never touched.
    pub fn create_bridge(&mut self) -> Result<()> {
        if iface_exists(&self.bridge)? {
            let owner = iface_owner(&self.bridge);
            match owner {
                Some(r) => bail!(
                    "bridge {} already exists (left by outstation run {r}); \
                     run cleanup or pick another name",
                    self.bridge
                ),
                None => bail!(
                    "interface {} already exists and is not managed by outstation; \
                     refusing to reuse or delete it",
                    self.bridge
                ),
            }
        }
        ip(["link", "add", &self.bridge, "type", "bridge"])?;
        self.bridge_created = true;
        mark_owned(&self.bridge, self.run_id)?;
        ip(["link", "set", "dev", &self.bridge, "up"])?;
        Ok(())
    }

    /// Create a veth pair where one end is enslaved to the bridge with
    /// the given MAC and the other end is returned for the caller to
    /// bind an AF_PACKET socket to for injection. The caller writes
    /// frames on the returned "inject-side" interface; the kernel then
    /// delivers them as receive on the bridge-side, which feeds into
    /// the bridge's forwarding path.
    ///
    /// This is the correct primitive for feeding replayed frames into
    /// a Linux bridge from userspace. A plain persistent TAP does not
    /// work for this pattern: AF_PACKET writes on a TAP are directed
    /// toward `/dev/net/tun` (the userspace side), not back into the
    /// bridge's receive path.
    ///
    /// `id` is the bridge-side interface name. The inject-side name is
    /// `{id}i`; both must be valid outstation names within IFNAMSIZ.
    pub fn add_port(&mut self, id: impl Into<String>, mac: Option<MacAddr>) -> Result<String> {
        self.add_port_with_ip(id, mac, None, &Protection::default())
    }

    /// Same as [`Topology::add_port`], but also assigns `src_ip/32` to
    /// the bridge-side end so that the kernel can own TCP sockets bound
    /// to that IP. Needed for protocol-aware modules.
    ///
    /// `src_ip` is checked with [`protect::validate_port_ip`] before
    /// anything is created: loopback/multicast/broadcast/reserved
    /// addresses, the host's default gateways and `prot`'s protected
    /// addresses are always refused, and an address already configured
    /// on any interface other than this topology's own bridge and ports
    /// is refused unless `prot.force`.
    pub fn add_port_with_ip(
        &mut self,
        id: impl Into<String>,
        mac: Option<MacAddr>,
        src_ip: Option<std::net::Ipv4Addr>,
        prot: &Protection,
    ) -> Result<String> {
        let bridge_side = id.into();
        if let Some(ip) = src_ip {
            let own_inject: Vec<String> = self.taps.iter().map(|t| format!("{t}i")).collect();
            let own: Vec<&str> = std::iter::once(self.bridge.as_str())
                .chain(self.taps.iter().map(String::as_str))
                .chain(own_inject.iter().map(String::as_str))
                .collect();
            protect::validate_port_ip(ip, prot, &own)?;
        }
        let inject_side = format!("{bridge_side}i");
        names::validate_owned_ifname(&bridge_side)?;
        names::validate_owned_ifname(&inject_side).with_context(|| {
            format!("port id {bridge_side:?} leaves no room for the 'i' suffix")
        })?;
        for n in [&bridge_side, &inject_side] {
            if iface_exists(n)? {
                bail!("interface {n} already exists");
            }
        }
        ip([
            "link",
            "add",
            &bridge_side,
            "type",
            "veth",
            "peer",
            "name",
            &inject_side,
        ])?;
        // Track it right away so teardown/drop removes it whatever fails next.
        self.taps.push(bridge_side.clone());
        mark_owned(&bridge_side, self.run_id)?;
        mark_owned(&inject_side, self.run_id)?;
        if let Some(mac) = mac {
            set_mac(&bridge_side, mac)?;
        }
        ip(["link", "set", "dev", &bridge_side, "master", &self.bridge])?;
        ip(["link", "set", "dev", &bridge_side, "up"])?;
        ip(["link", "set", "dev", &inject_side, "up"])?;
        if let Some(ip_addr) = src_ip {
            let cidr = format!("{ip_addr}/32");
            ip(["addr", "add", &cidr, "dev", &bridge_side])?;
        }
        Ok(inject_side)
    }

    /// Create a persistent TAP interface and enslave it. Retained for
    /// consumers that genuinely need a TAP (e.g., attaching a userspace
    /// IDS to `/dev/net/tun`) — not suitable for AF_PACKET injection.
    pub fn add_tap(&mut self, name: impl Into<String>, mac: Option<MacAddr>) -> Result<()> {
        let name = name.into();
        names::validate_owned_ifname(&name)?;
        if iface_exists(&name)? {
            bail!("interface {name} already exists");
        }
        ip(["tuntap", "add", "dev", &name, "mode", "tap"])?;
        self.taps.push(name.clone());
        mark_owned(&name, self.run_id)?;
        if let Some(mac) = mac {
            set_mac(&name, mac)?;
        }
        ip(["link", "set", "dev", &name, "master", &self.bridge])?;
        ip(["link", "set", "dev", &name, "up"])?;
        Ok(())
    }

    /// Attach an existing interface (e.g., a physical NIC) to the
    /// bridge after checking it against `prot` (see [`protect`]). The
    /// NIC is released from the bridge on teardown.
    pub fn enslave_existing(&mut self, iface: &str, prot: &Protection) -> Result<()> {
        check_nic_allowed(iface, "enslave", prot)?;
        ip(["link", "set", "dev", iface, "master", &self.bridge])?;
        self.enslaved.push(iface.to_string());
        ip(["link", "set", "dev", iface, "up"])?;
        Ok(())
    }

    fn do_teardown(&mut self) -> usize {
        let mut errors = 0usize;
        for nic in std::mem::take(&mut self.enslaved) {
            if let Err(e) = ip(["link", "set", "dev", &nic, "nomaster"]) {
                warn!(iface = %nic, error = %e, "release of enslaved NIC failed");
                errors += 1;
            }
        }
        for tap in std::mem::take(&mut self.taps) {
            if !iface_exists(&tap).unwrap_or(true) {
                continue;
            }
            if let Err(e) = delete_iface(&tap) {
                warn!(iface = %tap, error = %e, "port teardown failed");
                errors += 1;
            }
        }
        if self.bridge_created && iface_exists(&self.bridge).unwrap_or(false) {
            if let Err(e) = delete_iface(&self.bridge) {
                warn!(iface = %self.bridge, error = %e, "bridge teardown failed");
                errors += 1;
            }
        }
        self.bridge_created = false;
        self.done = true;
        errors
    }

    /// Release enslaved NICs, delete every port we created and the
    /// bridge. Consumes self.
    pub fn teardown(mut self) -> Result<()> {
        let errors = self.do_teardown();
        if errors == 0 {
            Ok(())
        } else {
            bail!("teardown had {errors} errors")
        }
    }

    /// Keep the interfaces after this value is dropped (CLI tools).
    pub fn leak(mut self) {
        self.done = true;
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        if !self.done {
            warn!(
                bridge = %self.bridge,
                taps = ?self.taps,
                "Topology dropped without explicit teardown — tearing down now"
            );
            self.do_teardown();
        }
    }
}

pub fn set_mac(iface: &str, mac: MacAddr) -> Result<()> {
    let s = format_mac(mac);
    ip(["link", "set", "dev", iface, "address", &s])
}

pub fn iface_exists(name: &str) -> Result<bool> {
    let out = Command::new("ip")
        .args(["-o", "link", "show", "dev", name])
        .output()
        .context("spawn `ip link show`")?;
    Ok(out.status.success())
}

/// `ip link del dev <name>`. Only accepts outstation-style names
/// (`pcr...`); use the reclaim functions to delete stale interfaces.
pub fn delete_iface(name: &str) -> Result<()> {
    names::validate_owned_ifname(name)?;
    ip(["link", "del", "dev", name])
}

/// One IPv4 address currently assigned to a local interface.
#[derive(Debug, Clone)]
pub struct LocalIp {
    pub iface: String,
    pub ip: std::net::Ipv4Addr,
    pub prefix: u8,
}

/// List every IPv4 address assigned to any local interface, with its
/// owning iface and CIDR prefix. Parsed from `ip -4 -o addr show`.
pub fn list_local_ipv4() -> Result<Vec<LocalIp>> {
    let out = Command::new("ip")
        .args(["-4", "-o", "addr", "show"])
        .output()
        .context("spawn `ip -4 -o addr show`")?;
    if !out.status.success() {
        bail!(
            "ip addr show failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut result = Vec::new();
    for line in text.lines() {
        // format: "N: <iface> inet X.X.X.X/NN ..."
        let mut it = line.split_ascii_whitespace();
        let _idx = it.next();
        let Some(iface_field) = it.next() else {
            continue;
        };
        let iface = iface_field.trim_end_matches(':').to_string();
        let Some(inet) = it.next() else { continue };
        if inet != "inet" {
            continue;
        }
        let Some(addr_cidr) = it.next() else { continue };
        let (addr_s, prefix_s) = addr_cidr.split_once('/').unwrap_or((addr_cidr, "32"));
        let Ok(ip) = addr_s.parse::<std::net::Ipv4Addr>() else {
            continue;
        };
        let prefix: u8 = prefix_s.parse().unwrap_or(32);
        result.push(LocalIp { iface, ip, prefix });
    }
    Ok(result)
}

/// Parse `ip -o route get 1.1.1.1` to find the interface the kernel
/// would use for outbound traffic along the default route. Used by
/// callers that need to pick an iface to alias onto.
pub fn default_route_iface() -> Result<String> {
    let out = Command::new("ip")
        .args(["-o", "route", "get", "1.1.1.1"])
        .output()
        .context("spawn `ip route get 1.1.1.1`")?;
    if !out.status.success() {
        bail!(
            "ip route get failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let mut it = s.split_ascii_whitespace();
    while let Some(tok) = it.next() {
        if tok == "dev" {
            if let Some(dev) = it.next() {
                return Ok(dev.to_string());
            }
        }
    }
    bail!("no `dev` in `ip route get` output: {s:?}")
}

/// First CIDR prefix found on `iface`, or None if the interface has no
/// IPv4 address. Used so an auto-added alias matches the existing
/// subnet (e.g., /24 if the iface is already /24).
pub fn find_iface_prefix(iface: &str) -> Option<u8> {
    let list = list_local_ipv4().ok()?;
    list.into_iter()
        .find(|x| x.iface == iface)
        .map(|x| x.prefix)
}

/// One network interface candidate for the egress-NIC dropdown.
#[derive(Debug, Clone)]
pub struct NicSummary {
    pub name: String,
    pub mac: Option<MacAddr>,
    pub ipv4: Vec<std::net::Ipv4Addr>,
    pub up: bool,
    pub loopback: bool,
    /// A real Linux bridge (`/sys/class/net/<if>/bridge`).
    pub bridge: bool,
    /// Already a port of some bridge (`/sys/class/net/<if>/brport`).
    pub bridge_port: bool,
    /// Carries a default route (protected; see [`protect`]).
    pub default_route: bool,
}

/// Enumerate every interface on the host. Used by the webui to
/// populate an egress NIC dropdown. Filters out our own pcr_*
/// veth/bridge ports so the user doesn't accidentally pick one.
pub fn list_nics() -> Result<Vec<NicSummary>> {
    let out = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .context("spawn `ip -o link show`")?;
    if !out.status.success() {
        bail!(
            "ip link show failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);

    let local_ipv4 = list_local_ipv4().unwrap_or_default();
    let default_ifaces = protect::default_route_ifaces().unwrap_or_default();
    let mut nics: Vec<NicSummary> = Vec::new();
    for line in text.lines() {
        // format: "N: <name>: <FLAGS> ... link/<type> <mac> brd ..."
        let Some((_, rest)) = line.split_once(": ") else {
            continue;
        };
        let (name_field, after_name) = match rest.split_once(": ") {
            Some(s) => s,
            None => continue,
        };
        // strip "@parent" suffix if any
        let name = name_field
            .split_once('@')
            .map_or(name_field, |(n, _)| n)
            .to_string();
        // skip our own pcr* allocations
        if name.starts_with(names::IFNAME_PREFIX) {
            continue;
        }
        let flags_end = after_name.find('>').unwrap_or(0);
        let flags = &after_name[..flags_end];
        let up = flags.contains("UP");
        let loopback = flags.contains("LOOPBACK");
        // `ip -o link show` never prints the link kind, so ask sysfs.
        let is_bridge = protect::is_bridge(&name);
        let bridge_port = protect::is_bridge_port(&name);
        let default_route = default_ifaces.contains(&name);
        // mac after `link/ether `
        let mac = after_name.find("link/ether ").and_then(|i| {
            let s = &after_name[i + "link/ether ".len()..];
            let mac_str: String = s.chars().take(17).collect();
            parse_mac(&mac_str).ok()
        });
        let ipv4: Vec<std::net::Ipv4Addr> = local_ipv4
            .iter()
            .filter(|x| x.iface == name)
            .map(|x| x.ip)
            .collect();
        nics.push(NicSummary {
            name,
            mac,
            ipv4,
            up,
            loopback,
            bridge: is_bridge,
            bridge_port,
            default_route,
        });
    }
    Ok(nics)
}

/// Return every interface whose name starts with `prefix`. Listing
/// only; reclaim uses ownership markers, never a bare prefix.
pub fn list_with_prefix(prefix: &str) -> Result<Vec<String>> {
    let out = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .context("spawn `ip link show`")?;
    if !out.status.success() {
        bail!(
            "ip link show failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut out = Vec::new();
    for line in text.lines() {
        // format: "N: name@parent: <...>" or "N: name: <...>"
        let Some((_, rest)) = line.split_once(": ") else {
            continue;
        };
        let name_end = rest.find(':').unwrap_or(rest.len());
        let name_field = &rest[..name_end];
        // strip "@parent" suffix, if any
        let name = name_field.split_once('@').map_or(name_field, |(n, _)| n);
        if name.starts_with(prefix) {
            out.push(name.to_string());
        }
    }
    Ok(out)
}

fn ip<I, S>(args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args: Vec<std::ffi::OsString> = args
        .into_iter()
        .map(|s| s.as_ref().to_os_string())
        .collect();
    let pretty: Vec<String> = args
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    debug!(cmd = ?pretty, "running ip");
    let out = Command::new("ip")
        .args(&args)
        .output()
        .with_context(|| format!("spawn `ip {}`", pretty.join(" ")))?;
    if !out.status.success() {
        bail!(
            "`ip {}` failed: {}",
            pretty.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topology_rejects_foreign_bridge_names() {
        assert!(Topology::new("br0", 1).is_err());
        assert!(Topology::new("", 1).is_err());
        assert!(Topology::new("docker0", 1).is_err());
        let t = Topology::new("pcr_br0", 1).unwrap();
        t.leak();
    }

    #[test]
    fn delete_iface_refuses_foreign_names() {
        assert!(delete_iface("eth0").is_err());
        assert!(delete_iface("docker0").is_err());
        assert!(delete_iface("").is_err());
    }

    #[test]
    fn mac_roundtrip() {
        let mac = [0x02, 0x00, 0x00, 0x12, 0x34, 0x56];
        let s = format_mac(mac);
        assert_eq!(s, "02:00:00:12:34:56");
        assert_eq!(parse_mac(&s).unwrap(), mac);
    }

    #[test]
    fn mac_bad_len() {
        assert!(parse_mac("02:00:00:12:34").is_err());
    }

    #[test]
    fn mac_bad_hex() {
        assert!(parse_mac("02:00:00:12:34:ZZ").is_err());
    }
}
