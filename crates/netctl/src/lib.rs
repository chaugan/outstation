//! Manage Linux bridges and TAP interfaces for outstation.
//!
//! v1 shells out to `ip` from iproute2. This keeps the crate tiny and the
//! error messages transparent. A future revision can swap to rtnetlink for
//! fewer process spawns at setup time.

use std::ffi::OsStr;
use std::process::Command;

use anyhow::{bail, Context, Result};
use tracing::{debug, info, warn};

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

/// A bridge plus any number of TAP interfaces enslaved to it.
///
/// Tear down explicitly with [`Topology::teardown`]. Dropping without
/// teardown logs a warning and leaves interfaces in place — which is what
/// you want if the process crashed, so they can be reclaimed on restart.
pub struct Topology {
    pub bridge: String,
    pub taps: Vec<String>,
    /// True if `create_bridge` created the bridge on this run. If the
    /// bridge already existed when we started, we leave it in place on
    /// teardown — the caller owns its lifecycle.
    bridge_owned: bool,
    leaked: bool,
}

impl Topology {
    pub fn new(bridge: impl Into<String>) -> Self {
        Self {
            bridge: bridge.into(),
            taps: Vec::new(),
            bridge_owned: false,
            leaked: false,
        }
    }

    /// Create (or reuse) the bridge and bring it up. If the bridge
    /// already existed, [`Topology::teardown`] will leave it in place.
    pub fn create_bridge(&mut self) -> Result<()> {
        if iface_exists(&self.bridge)? {
            info!(name = %self.bridge, "bridge already exists, reusing — will not delete on teardown");
            self.bridge_owned = false;
        } else {
            ip(["link", "add", &self.bridge, "type", "bridge"])?;
            self.bridge_owned = true;
        }
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
    /// `{id}i` (one extra char, to stay under IFNAMSIZ).
    pub fn add_port(&mut self, id: impl Into<String>, mac: Option<MacAddr>) -> Result<String> {
        self.add_port_with_ip(id, mac, None)
    }

    /// Same as [`Topology::add_port`], but also assigns `src_ip/32` to
    /// the bridge-side end so that the kernel can own TCP sockets bound
    /// to that IP. Needed for `tcp_session` and protocol-aware modules.
    pub fn add_port_with_ip(
        &mut self,
        id: impl Into<String>,
        mac: Option<MacAddr>,
        src_ip: Option<std::net::Ipv4Addr>,
    ) -> Result<String> {
        let bridge_side = id.into();
        let inject_side = format!("{bridge_side}i");
        if bridge_side.len() > 14 {
            bail!("port id {bridge_side:?} too long (max 14 chars to leave room for 'i' suffix)");
        }
        if iface_exists(&bridge_side)? {
            bail!("interface {bridge_side} already exists");
        }
        ip([
            "link", "add", &bridge_side, "type", "veth", "peer", "name", &inject_side,
        ])?;
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
        self.taps.push(bridge_side);
        Ok(inject_side)
    }

    /// Create a persistent TAP interface and enslave it. Retained for
    /// consumers that genuinely need a TAP (e.g., attaching a userspace
    /// IDS to `/dev/net/tun`) — not suitable for AF_PACKET injection.
    pub fn add_tap(&mut self, name: impl Into<String>, mac: Option<MacAddr>) -> Result<()> {
        let name = name.into();
        if iface_exists(&name)? {
            bail!("interface {name} already exists");
        }
        ip(["tuntap", "add", "dev", &name, "mode", "tap"])?;
        if let Some(mac) = mac {
            set_mac(&name, mac)?;
        }
        ip(["link", "set", "dev", &name, "master", &self.bridge])?;
        ip(["link", "set", "dev", &name, "up"])?;
        self.taps.push(name);
        Ok(())
    }

    /// Attach an already-existing interface (e.g., a physical NIC) to the
    /// bridge. The caller owns its lifecycle; we do not add it to `taps`.
    pub fn enslave_existing(&self, iface: &str) -> Result<()> {
        ip(["link", "set", "dev", iface, "master", &self.bridge])?;
        ip(["link", "set", "dev", iface, "up"])?;
        Ok(())
    }

    /// Delete every port we created. Also deletes the bridge, but only
    /// if we created it on this run (i.e., it didn't exist when we
    /// started). Consumes self.
    pub fn teardown(mut self) -> Result<()> {
        let mut errors = 0usize;
        for tap in std::mem::take(&mut self.taps) {
            if let Err(e) = delete_iface(&tap) {
                warn!(iface = %tap, error = %e, "port teardown failed");
                errors += 1;
            }
        }
        if self.bridge_owned && iface_exists(&self.bridge).unwrap_or(false) {
            if let Err(e) = delete_iface(&self.bridge) {
                warn!(iface = %self.bridge, error = %e, "bridge teardown failed");
                errors += 1;
            }
        }
        self.leaked = true; // suppress Drop warning
        if errors == 0 {
            Ok(())
        } else {
            bail!("teardown had {errors} errors")
        }
    }

    /// Suppress the Drop warning. Use when you intentionally leave the
    /// topology up after the process exits.
    pub fn leak(mut self) {
        self.leaked = true;
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        if !self.leaked {
            warn!(
                bridge = %self.bridge,
                taps = ?self.taps,
                "Topology dropped without explicit teardown — interfaces may remain"
            );
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

pub fn delete_iface(name: &str) -> Result<()> {
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
    list.into_iter().find(|x| x.iface == iface).map(|x| x.prefix)
}

// ---------------------------------------------------------------------------
// Tracked IP-alias management.
//
// Because outstation runs as a long-lived service that may crash or get
// killed, a flat-text state file at a caller-supplied path records every
// IP alias we add. On startup the caller calls `reclaim_recorded_aliases`
// which reads the file, removes each leftover alias, and truncates the
// file. Format: one alias per line, "<iface> <ip> <prefix>".

/// Append an alias entry to the state file. Best-effort: if the file
/// can't be written we log and continue (the alias still gets cleaned
/// up on graceful drop, just not on crash).
pub fn record_alias(state_path: &std::path::Path, iface: &str, ip: std::net::Ipv4Addr, prefix: u8) {
    use std::io::Write;
    if let Some(parent) = state_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let line = format!("{iface} {ip} {prefix}\n");
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(state_path)
    {
        Ok(mut f) => {
            if let Err(e) = f.write_all(line.as_bytes()) {
                warn!(error = %e, path = %state_path.display(), "alias record write failed");
            }
        }
        Err(e) => warn!(error = %e, path = %state_path.display(), "alias record open failed"),
    }
}

/// Remove a single alias entry from the state file. Rewrites the file
/// in place without that line. No-op if the file is missing.
pub fn forget_alias(state_path: &std::path::Path, iface: &str, ip: std::net::Ipv4Addr, prefix: u8) {
    let want = format!("{iface} {ip} {prefix}");
    let Ok(content) = std::fs::read_to_string(state_path) else {
        return;
    };
    let mut kept: Vec<&str> = Vec::new();
    let mut removed = false;
    for line in content.lines() {
        if !removed && line.trim() == want {
            removed = true;
            continue;
        }
        kept.push(line);
    }
    if !removed {
        return;
    }
    let new = if kept.is_empty() {
        String::new()
    } else {
        kept.join("\n") + "\n"
    };
    if let Err(e) = std::fs::write(state_path, new) {
        warn!(error = %e, path = %state_path.display(), "alias forget write failed");
    }
}

/// At server startup: read the state file, attempt to remove every
/// recorded alias, and truncate the file so the next clean exit
/// starts fresh. Returns the number of aliases successfully removed.
pub fn reclaim_recorded_aliases(state_path: &std::path::Path) -> Result<usize> {
    let Ok(content) = std::fs::read_to_string(state_path) else {
        return Ok(0);
    };
    let mut removed = 0usize;
    for line in content.lines() {
        let parts: Vec<&str> = line.split_ascii_whitespace().collect();
        if parts.len() != 3 {
            continue;
        }
        let iface = parts[0];
        let Ok(ip) = parts[1].parse::<std::net::Ipv4Addr>() else {
            continue;
        };
        let Ok(prefix) = parts[2].parse::<u8>() else {
            continue;
        };
        match del_ip_alias(iface, ip, prefix) {
            Ok(()) => {
                removed += 1;
                info!(%iface, %ip, prefix, "reclaimed orphaned ip alias from prior run");
            }
            Err(e) => {
                warn!(%iface, %ip, prefix, error = %e, "alias reclaim failed");
            }
        }
    }
    let _ = std::fs::write(state_path, "");
    Ok(removed)
}

/// `ip addr add <ip>/<prefix> dev <iface>`. Idempotent-ish: treats
/// "File exists" as success so repeated adds are harmless.
pub fn add_ip_alias(iface: &str, ip: std::net::Ipv4Addr, prefix: u8) -> Result<()> {
    let cidr = format!("{ip}/{prefix}");
    let out = Command::new("ip")
        .args(["addr", "add", &cidr, "dev", iface])
        .output()
        .with_context(|| format!("spawn `ip addr add {cidr} dev {iface}`"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("File exists") {
        // Already present — fine. Another alias add or a prior crash.
        return Ok(());
    }
    bail!("`ip addr add {cidr} dev {iface}` failed: {}", err.trim())
}

/// One network interface candidate for the egress-NIC dropdown.
#[derive(Debug, Clone)]
pub struct NicSummary {
    pub name: String,
    pub mac: Option<MacAddr>,
    pub ipv4: Vec<std::net::Ipv4Addr>,
    pub up: bool,
    pub loopback: bool,
    pub bridge: bool,
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
        // skip our own pcr_* allocations
        if name.starts_with("pcr_") {
            continue;
        }
        let flags_end = after_name.find('>').unwrap_or(0);
        let flags = &after_name[..flags_end];
        let up = flags.contains("UP");
        let loopback = flags.contains("LOOPBACK");
        // detect bridge or veth from the link/<type>
        let is_bridge = after_name.contains("link/ether") && after_name.contains("bridge");
        // mac after `link/ether `
        let mac = after_name
            .find("link/ether ")
            .and_then(|i| {
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
        });
    }
    Ok(nics)
}

// ---------------------------------------------------------------------------
// Egress safety guard.
//
// When a run enslaves a real physical NIC to our bridge, three host-stack
// gotchas can ruin the replay:
//
//   1. `br_netfilter` makes iptables rules apply to bridged frames. The
//      host firewall may answer ARPs or RST forged TCP flows it didn't
//      originate. Mitigation: set `net.bridge.bridge-nf-call-iptables=0`
//      and install an `iptables -t raw -A PREROUTING -i <bridge> -j DROP`
//      rule so the host stack ignores everything bridged through.
//
//   2. NIC TX checksum offload may rewrite/mangle the L4 checksums we
//      computed in software. Mitigation: `ethtool -K <nic> tx off` for
//      the duration of the run.
//
//   3. (Future) generic-receive-offload, large-receive-offload — not yet
//      handled.
//
// `EgressGuard` snapshots the current state on construction, switches to
// the safe state, and restores everything on `Drop` so a panic mid-run
// still leaves the host as we found it.

/// Best-effort safe-egress guard. Captured state is restored on drop.
pub struct EgressGuard {
    pub bridge: String,
    pub nic: String,
    /// Previous `net.bridge.bridge-nf-call-iptables` value, if the
    /// sysctl was readable. None = sysctl not present (br_netfilter
    /// kernel module not loaded).
    prev_bridge_nf: Option<String>,
    /// Previous `tx-checksumming` state on the NIC, if readable.
    prev_tx_checksum: Option<String>,
    /// Whether we installed the iptables drop rule (so we know to remove it).
    iptables_rule_installed: bool,
    /// Set to true after Drop to suppress cleanup if the caller has
    /// explicitly released the guard.
    released: bool,
}

impl EgressGuard {
    /// Apply safe-egress measures around the bridge + NIC pair. Always
    /// returns a guard, even when individual steps fail (logs warning).
    pub fn install(bridge: &str, nic: &str) -> Self {
        let prev_bridge_nf = read_bridge_nf();
        if prev_bridge_nf.is_some() {
            if let Err(e) = write_bridge_nf("0") {
                warn!(error = %e, "could not disable bridge-nf-call-iptables");
            } else {
                info!("disabled bridge-nf-call-iptables for run");
            }
        } else {
            debug!("bridge-nf-call-iptables sysctl not present (br_netfilter not loaded)");
        }

        let prev_tx_checksum = read_tx_checksum(nic);
        if prev_tx_checksum.is_some() {
            if let Err(e) = set_tx_checksum(nic, false) {
                warn!(nic, error = %e, "could not disable NIC tx-checksum offload");
            } else {
                info!(nic, "disabled NIC tx-checksum offload for run");
            }
        }

        let iptables_rule_installed = match install_iptables_drop(bridge) {
            Ok(()) => {
                info!(bridge, "installed iptables drop rule");
                true
            }
            Err(e) => {
                warn!(bridge, error = %e, "could not install iptables drop rule");
                false
            }
        };

        Self {
            bridge: bridge.to_string(),
            nic: nic.to_string(),
            prev_bridge_nf,
            prev_tx_checksum,
            iptables_rule_installed,
            released: false,
        }
    }

    /// Manually release the guard before drop (e.g., after explicit
    /// teardown). Idempotent.
    pub fn release(mut self) {
        self.do_restore();
        self.released = true;
    }

    fn do_restore(&mut self) {
        if self.released {
            return;
        }
        if self.iptables_rule_installed {
            if let Err(e) = remove_iptables_drop(&self.bridge) {
                warn!(bridge = %self.bridge, error = %e, "could not remove iptables drop rule");
            }
        }
        if let Some(prev) = &self.prev_tx_checksum {
            // Restore the previous on/off state.
            let want_on = prev.contains("on");
            if let Err(e) = set_tx_checksum(&self.nic, want_on) {
                warn!(nic = %self.nic, error = %e, "could not restore NIC tx-checksum offload");
            }
        }
        if let Some(prev) = &self.prev_bridge_nf {
            if let Err(e) = write_bridge_nf(prev.trim()) {
                warn!(error = %e, "could not restore bridge-nf-call-iptables");
            }
        }
    }
}

impl Drop for EgressGuard {
    fn drop(&mut self) {
        self.do_restore();
    }
}

fn read_bridge_nf() -> Option<String> {
    std::fs::read_to_string("/proc/sys/net/bridge/bridge-nf-call-iptables").ok()
}

fn write_bridge_nf(value: &str) -> Result<()> {
    let out = Command::new("sysctl")
        .args(["-w", &format!("net.bridge.bridge-nf-call-iptables={value}")])
        .output()
        .context("spawn sysctl")?;
    if !out.status.success() {
        bail!(
            "sysctl failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn read_tx_checksum(nic: &str) -> Option<String> {
    let out = Command::new("ethtool").args(["-k", nic]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("tx-checksumming:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn set_tx_checksum(nic: &str, on: bool) -> Result<()> {
    let val = if on { "on" } else { "off" };
    let out = Command::new("ethtool")
        .args(["-K", nic, "tx", val])
        .output()
        .context("spawn ethtool")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        // Some virtual NICs report "Cannot change ..." for fixed
        // offload state. Treat as a soft failure rather than crashing.
        if err.contains("not changed") || err.contains("Cannot") {
            return Ok(());
        }
        bail!("`ethtool -K {nic} tx {val}` failed: {}", err.trim());
    }
    Ok(())
}

fn install_iptables_drop(bridge: &str) -> Result<()> {
    let out = Command::new("iptables")
        .args(["-t", "raw", "-I", "PREROUTING", "1", "-i", bridge, "-j", "DROP"])
        .output()
        .context("spawn iptables")?;
    if !out.status.success() {
        bail!(
            "iptables install failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn remove_iptables_drop(bridge: &str) -> Result<()> {
    let out = Command::new("iptables")
        .args(["-t", "raw", "-D", "PREROUTING", "-i", bridge, "-j", "DROP"])
        .output()
        .context("spawn iptables")?;
    if !out.status.success() {
        bail!(
            "iptables remove failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SCADA-gateway mode:
//
// When the outstation box is the only L2 neighbor of a SCADA guest (typical
// virtual-lab setup — see doc/scada-lab.md), we want outstation to act as the
// SCADA's default gateway AND to NAT unrelated egress back out to the real
// lab. This guard owns all the reversible side effects of that setup:
//
//   1. A /32 IP alias on the "inner" NIC so SCADA's gateway ARP gets a reply.
//   2. `net.ipv4.ip_forward=1` (saving the previous value).
//   3. An iptables MASQUERADE rule on the "outer" NIC, if one is set.
//
// On Drop, or via explicit `release()`, all three are undone in reverse
// order. The alias is also recorded in the state file so a server restart
// that misses the drop still reclaims it via `reclaim_recorded_aliases`.
pub struct GatewayGuard {
    pub inner_nic: String,
    pub gateway_ip: std::net::Ipv4Addr,
    pub outer_nic: Option<String>,
    prev_ip_forward: Option<String>,
    masq_rule_installed: bool,
    alias_added: bool,
    state_path: std::path::PathBuf,
    released: bool,
}

impl GatewayGuard {
    /// Install the gateway alias + optional NAT. Never panics; individual
    /// failures are logged and the guard still returns so Drop cleans up
    /// whatever did succeed.
    pub fn install(
        inner_nic: &str,
        gateway_ip: std::net::Ipv4Addr,
        outer_nic: Option<&str>,
        state_path: &std::path::Path,
    ) -> Self {
        // 1. /32 alias for the gateway IP. A /32 prefix means "just this
        //    address, no subnet-level route" — we don't want to steal the
        //    inner NIC's routing table.
        let alias_added = match add_ip_alias(inner_nic, gateway_ip, 32) {
            Ok(()) => {
                record_alias(state_path, inner_nic, gateway_ip, 32);
                info!(inner_nic, %gateway_ip, "installed SCADA-gateway alias /32");
                true
            }
            Err(e) => {
                // "File exists" is fine — alias was already there (reclaim,
                // previous run, whatever). Treat as installed so we clean
                // it up on drop.
                let msg = format!("{e:#}");
                if msg.contains("File exists") {
                    record_alias(state_path, inner_nic, gateway_ip, 32);
                    info!(inner_nic, %gateway_ip, "SCADA-gateway alias already present, adopted");
                    true
                } else {
                    warn!(inner_nic, %gateway_ip, error = %e, "add gateway alias failed");
                    false
                }
            }
        };

        // 2. Enable IP forwarding, saving the previous value for restore.
        let prev_ip_forward = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .ok()
            .map(|s| s.trim().to_string());
        if prev_ip_forward.is_some() {
            if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n") {
                warn!(error = %e, "could not set net.ipv4.ip_forward=1");
            } else {
                info!("enabled net.ipv4.ip_forward for SCADA-gateway mode");
            }
        }

        // 3. MASQUERADE out the outer NIC so SCADA's non-RTU egress reaches
        //    the real lab. Skipped if outer_nic isn't set.
        let masq_rule_installed = if let Some(outer) = outer_nic {
            match install_masquerade(outer) {
                Ok(()) => {
                    info!(outer, "installed MASQUERADE rule for SCADA upstream");
                    true
                }
                Err(e) => {
                    warn!(outer, error = %e, "install masquerade failed");
                    false
                }
            }
        } else {
            false
        };

        Self {
            inner_nic: inner_nic.to_string(),
            gateway_ip,
            outer_nic: outer_nic.map(|s| s.to_string()),
            prev_ip_forward,
            masq_rule_installed,
            alias_added,
            state_path: state_path.to_path_buf(),
            released: false,
        }
    }

    pub fn release(mut self) {
        self.do_restore();
        self.released = true;
    }

    fn do_restore(&mut self) {
        if self.released {
            return;
        }
        if self.masq_rule_installed {
            if let Some(outer) = &self.outer_nic {
                if let Err(e) = remove_masquerade(outer) {
                    warn!(outer = %outer, error = %e, "remove masquerade failed");
                }
            }
        }
        if let Some(prev) = &self.prev_ip_forward {
            if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", format!("{prev}\n")) {
                warn!(error = %e, "could not restore net.ipv4.ip_forward");
            }
        }
        if self.alias_added {
            if let Err(e) = del_ip_alias(&self.inner_nic, self.gateway_ip, 32) {
                warn!(inner_nic = %self.inner_nic, ip = %self.gateway_ip, error = %e,
                    "remove gateway alias failed");
            }
            forget_alias(&self.state_path, &self.inner_nic, self.gateway_ip, 32);
        }
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        self.do_restore();
    }
}

fn install_masquerade(outer_nic: &str) -> Result<()> {
    let out = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            outer_nic,
            "-j",
            "MASQUERADE",
        ])
        .output()
        .context("spawn iptables -t nat -A POSTROUTING")?;
    if !out.status.success() {
        bail!(
            "iptables masquerade install failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn remove_masquerade(outer_nic: &str) -> Result<()> {
    let out = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-o",
            outer_nic,
            "-j",
            "MASQUERADE",
        ])
        .output()
        .context("spawn iptables -t nat -D POSTROUTING")?;
    if !out.status.success() {
        bail!(
            "iptables masquerade remove failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// `ip addr del <ip>/<prefix> dev <iface>`. "Cannot assign" is ignored
/// so we don't complain about double-cleans.
pub fn del_ip_alias(iface: &str, ip: std::net::Ipv4Addr, prefix: u8) -> Result<()> {
    let cidr = format!("{ip}/{prefix}");
    let out = Command::new("ip")
        .args(["addr", "del", &cidr, "dev", iface])
        .output()
        .with_context(|| format!("spawn `ip addr del {cidr} dev {iface}`"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("Cannot assign") || err.contains("does not exist") {
        return Ok(());
    }
    bail!("`ip addr del {cidr} dev {iface}` failed: {}", err.trim())
}

/// Delete every stale interface whose name starts with `tap_prefix`,
/// the hardcoded `pcr_cap` capture port, and the named bridge if it
/// exists. Called by sched at the start of each run so a previously
/// crashed or killed run doesn't block the next one with
/// "interface pcr_t0 already exists".
///
/// Only warns on individual delete failures — the caller still gets
/// Ok, because a stale bridge without stale veths (or vice versa) is
/// still a usable starting point.
pub fn reclaim_stale(bridge: &str, tap_prefix: &str) -> Result<usize> {
    let mut deleted = 0usize;
    // Veth pairs: delete the bridge-side; the peer auto-vanishes.
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(list) = list_with_prefix(tap_prefix) {
        candidates.extend(list);
    }
    if let Ok(cap_list) = list_with_prefix("pcr_cap") {
        candidates.extend(cap_list);
    }
    // Dedup and drop anything ending in 'i' (inject-side peer; deleting
    // the bridge-side takes both ends with it).
    candidates.sort();
    candidates.dedup();
    candidates.retain(|n| !n.ends_with('i') || n == "pcr_capi");
    for name in candidates {
        // Skip the inject-side peers; the bridge-side delete will clean them.
        if name.ends_with('i') && name != "pcr_capi" {
            continue;
        }
        if iface_exists(&name).unwrap_or(false) {
            match delete_iface(&name) {
                Ok(_) => {
                    deleted += 1;
                    info!(iface = %name, "reclaimed stale interface");
                }
                Err(e) => warn!(iface = %name, error = %e, "reclaim delete failed"),
            }
        }
    }
    if iface_exists(bridge).unwrap_or(false) {
        match delete_iface(bridge) {
            Ok(_) => {
                deleted += 1;
                info!(iface = %bridge, "reclaimed stale bridge");
            }
            Err(e) => warn!(iface = %bridge, error = %e, "reclaim bridge delete failed"),
        }
    }
    Ok(deleted)
}

/// Return every interface whose name starts with `prefix`. Useful for
/// reclaiming stale `pr_*` TAPs on startup.
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
    let args: Vec<std::ffi::OsString> =
        args.into_iter().map(|s| s.as_ref().to_os_string()).collect();
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
mod tests {
    use super::*;

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
