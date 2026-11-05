//! Host-stack isolation of a run's interfaces.
//!
//! Master-role benchmark sessions own TCP sockets, so their source IP
//! and MAC live on the inject end of a veth whose other end is a port
//! of the run bridge. That inject end is an ordinary L3 interface in
//! the host namespace, reachable from the bridged LAN. Without care,
//! LAN hosts could reach any host address through it (weak host model)
//! or, with `ip_forward=1`, route through the host into its management
//! network. [`Hardening`] closes that:
//!
//! * per interface (inject ends, the bridge, the capture device), set
//!   before the interface comes up: `net.ipv4.conf.<if>.forwarding=0`,
//!   `rp_filter`, `arp_ignore=1`, `arp_announce=2`, `accept_local=0`
//!   and `net.ipv6.conf.<if>.disable_ipv6=1`. `rp_filter` is strict (1)
//!   on the bridge and the capture device, loose (2) on session inject
//!   ends: the host's own route to the target normally points out of
//!   another interface, so strict mode drops every SYN-ACK (verified in
//!   the netns e2e test, `TcpExtIPReversePathFilter`), while the raw
//!   ACCEPT below already pins accepted traffic to `peer -> src_ip`,
//!   which is stricter than any reverse-path check. These are written
//!   directly and read back (fail closed), not journaled: the
//!   interfaces belong to the run and carry its ownership marker, and
//!   deleting them (teardown, or [`crate::cleanup_all`] after a crash)
//!   removes their per-interface settings with them, so there is no
//!   prior value to restore;
//! * on every interface a topology creates (hardened or not), before it
//!   comes up ([`quiet_iface`]): multicast off and IPv6 off, and the
//!   bridge is created without multicast snooping, so the run's
//!   interfaces never originate IGMP, DAD, router solicitations or
//!   MLD of their own: only replayed and session frames reach the LAN;
//! * journaled, comment-tagged iptables rules (see [`crate::guard`]),
//!   installed with an `iptables -C` check and failing closed:
//!   - `raw PREROUTING -i <prefix>+ -j DROP`: nothing that arrives on
//!     any of the run's interfaces reaches the host stack ...
//!   - ... except, inserted above it per session source IP,
//!     `raw PREROUTING -i <prefix>+ -s <peer> -d <src_ip> -j ACCEPT`:
//!     the run's target talking to a session address;
//!   - `filter FORWARD -i <prefix>+ -j DROP` and
//!     `filter FORWARD -o <prefix>+ -j DROP`: never route in or out of
//!     the run's interfaces.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use tracing::{debug, info};

use crate::guard::{iptables_comment, read_sysctl, write_sysctl, RuleLease, TaggedRule};
use crate::names::{validate_owned_ifname, validate_prefix};

/// IPv4 per-interface settings applied to every hardened interface
/// (plus `rp_filter`, see [`RpFilter`]).
pub const IPV4_IFACE_SYSCTLS: [(&str, &str); 4] = [
    ("forwarding", "0"),
    ("arp_ignore", "1"),
    ("arp_announce", "2"),
    ("accept_local", "0"),
];

/// Reverse-path filter mode for one interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpFilter {
    /// `rp_filter=1`.
    Strict,
    /// `rp_filter=2`: the source must be routable via any interface.
    Loose,
}

impl RpFilter {
    pub fn value(self) -> &'static str {
        match self {
            RpFilter::Strict => "1",
            RpFilter::Loose => "2",
        }
    }
}

fn rule(table: &str, chain: &str, spec: &[&str], run_id: u64, target: &str) -> TaggedRule {
    let mut s: Vec<String> = spec.iter().map(|x| x.to_string()).collect();
    s.extend([
        "-m".into(),
        "comment".into(),
        "--comment".into(),
        iptables_comment(run_id),
        "-j".into(),
        target.into(),
    ]);
    TaggedRule {
        table: table.into(),
        chain: chain.into(),
        spec: s,
    }
}

/// The run-wide rules for interface prefix `prefix` (`pcr<tag>_`).
pub fn prefix_rules(prefix: &str, run_id: u64) -> [TaggedRule; 3] {
    let wild = format!("{prefix}+");
    [
        rule("raw", "PREROUTING", &["-i", &wild], run_id, "DROP"),
        rule("filter", "FORWARD", &["-i", &wild], run_id, "DROP"),
        rule("filter", "FORWARD", &["-o", &wild], run_id, "DROP"),
    ]
}

/// The per-session ACCEPT: `peer` may reach `src` on the run's
/// interfaces. With `peer_port` the rule is narrowed to TCP segments
/// *from* that port (the replies of the target service the session
/// talks to), so a spoofed `peer` source cannot reach any other
/// protocol or port on the session address (security review).
pub fn session_accept_rule(
    prefix: &str,
    peer: Ipv4Addr,
    peer_port: Option<u16>,
    src: Ipv4Addr,
    run_id: u64,
) -> TaggedRule {
    let wild = format!("{prefix}+");
    let (p, s) = (format!("{peer}/32"), format!("{src}/32"));
    let port = peer_port.map(|x| x.to_string());
    let mut spec: Vec<&str> = vec!["-i", &wild, "-s", &p, "-d", &s];
    if let Some(port) = port.as_deref() {
        spec.extend(["-p", "tcp", "--sport", port]);
    }
    rule("raw", "PREROUTING", &spec, run_id, "ACCEPT")
}

/// Apply the per-interface settings to `iface` and verify them.
/// IPv6 settings are skipped when the kernel has no IPv6.
pub fn harden_iface(iface: &str, rp: RpFilter) -> Result<()> {
    validate_owned_ifname(iface)?;
    for (k, v) in IPV4_IFACE_SYSCTLS
        .into_iter()
        .chain([("rp_filter", rp.value())])
    {
        let key = format!("net.ipv4.conf.{iface}.{k}");
        write_sysctl(&key, v).with_context(|| format!("harden {iface}: {key}={v}"))?;
        if read_sysctl(&key)?.as_deref() != Some(v) {
            bail!("harden {iface}: {key} did not stick at {v}");
        }
    }
    let key = format!("net.ipv6.conf.{iface}.disable_ipv6");
    match read_sysctl(&key)? {
        None => debug!(iface, "no IPv6 on this host"),
        Some(_) => {
            write_sysctl(&key, "1").with_context(|| format!("harden {iface}: {key}=1"))?;
            if read_sysctl(&key)?.as_deref() != Some("1") {
                bail!("harden {iface}: {key} did not stick at 1");
            }
        }
    }
    Ok(())
}

/// Keep `iface` from originating frames of its own: multicast off (no
/// IGMP reports, no multicast joins) and, when the kernel has IPv6,
/// `disable_ipv6=1` (no DAD, router solicitations or MLD). Call before
/// the interface comes up. Applied to every interface a topology
/// creates, hardened or not, so that only replayed and session frames
/// ever reach the LAN (O2). Like [`harden_iface`] this is not journaled:
/// the setting dies with the interface.
pub fn quiet_iface(iface: &str) -> Result<()> {
    validate_owned_ifname(iface)?;
    crate::ip(["link", "set", "dev", iface, "multicast", "off"])
        .with_context(|| format!("quiet {iface}: multicast off"))?;
    let key = format!("net.ipv6.conf.{iface}.disable_ipv6");
    match read_sysctl(&key)? {
        None => debug!(iface, "no IPv6 on this host"),
        Some(_) => {
            write_sysctl(&key, "1").with_context(|| format!("quiet {iface}: {key}=1"))?;
            if read_sysctl(&key)?.as_deref() != Some("1") {
                bail!("quiet {iface}: {key} did not stick at 1");
            }
        }
    }
    Ok(())
}

/// Isolation state of one topology: the run-wide rules plus one
/// ACCEPT per session source IP. Rules are removed on drop (and stay
/// journaled for [`crate::cleanup_all`] if that fails).
#[derive(Debug)]
pub struct Hardening {
    pub prefix: String,
    pub peer: Option<Ipv4Addr>,
    /// TCP source port of the peer's replies; narrows every ACCEPT.
    pub peer_port: Option<u16>,
    run_id: u64,
    state_dir: PathBuf,
    // Dropped before `base`: ACCEPTs go first.
    accepts: HashMap<Ipv4Addr, RuleLease>,
    base: Vec<RuleLease>,
}

impl Hardening {
    /// Install the run-wide DROP rules for `prefix` (fail closed).
    pub fn install(
        prefix: &str,
        peer: Option<Ipv4Addr>,
        peer_port: Option<u16>,
        run_id: u64,
        state_dir: &Path,
    ) -> Result<Self> {
        validate_prefix(prefix).context("hardening prefix")?;
        let mut base = Vec::new();
        for r in prefix_rules(prefix, run_id) {
            let l = RuleLease::install(r, true, state_dir)
                .with_context(|| format!("isolate {prefix}+ from the host stack"))?;
            base.push(l);
        }
        info!(
            prefix,
            ?peer,
            ?peer_port,
            "run interfaces isolated from the host stack"
        );
        Ok(Self {
            prefix: prefix.to_string(),
            peer,
            peer_port,
            run_id,
            state_dir: state_dir.to_path_buf(),
            accepts: HashMap::new(),
            base,
        })
    }

    /// Let the run's peer reach session address `src` (once per
    /// address). Errors when the topology has no peer.
    pub fn allow_session(&mut self, src: Ipv4Addr) -> Result<()> {
        let Some(peer) = self.peer else {
            bail!("a port with a source IP needs the run's peer (target) address");
        };
        if self.accepts.contains_key(&src) {
            return Ok(());
        }
        let r = session_accept_rule(&self.prefix, peer, self.peer_port, src, self.run_id);
        let l = RuleLease::install(r, true, &self.state_dir)
            .with_context(|| format!("allow {peer} -> {src}"))?;
        self.accepts.insert(src, l);
        Ok(())
    }

    /// [`Hardening::allow_session`] for many addresses at once: one
    /// journal update and one iptables transaction
    /// ([`RuleLease::install_batch`]). Addresses already allowed (or
    /// repeated) are skipped.
    pub fn allow_sessions(&mut self, srcs: &[Ipv4Addr]) -> Result<()> {
        let Some(peer) = self.peer else {
            bail!("a port with a source IP needs the run's peer (target) address");
        };
        let mut new: Vec<Ipv4Addr> = Vec::new();
        for s in srcs {
            if !self.accepts.contains_key(s) && !new.contains(s) {
                new.push(*s);
            }
        }
        let rules = new
            .iter()
            .map(|s| session_accept_rule(&self.prefix, peer, self.peer_port, *s, self.run_id))
            .collect();
        let leases = RuleLease::install_batch(rules, true, &self.state_dir)
            .with_context(|| format!("allow {peer} -> {} session addresses", new.len()))?;
        self.accepts.extend(new.into_iter().zip(leases));
        Ok(())
    }

    /// Remove every rule now, the session ACCEPTs first, each group in
    /// one batch ([`RuleLease::release_batch`]). Returns the number of
    /// failures (which stay journaled).
    pub fn release(&mut self) -> usize {
        let accepts: Vec<RuleLease> = self.accepts.drain().map(|(_, l)| l).collect();
        let mut errors = RuleLease::release_batch(accepts);
        errors += RuleLease::release_batch(std::mem::take(&mut self.base));
        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_cover_the_run_prefix_and_are_tagged() {
        let [raw, fwd_in, fwd_out] = prefix_rules("pcrab_", 7);
        assert_eq!(
            (raw.table.as_str(), raw.chain.as_str()),
            ("raw", "PREROUTING")
        );
        assert_eq!(raw.spec[..2], ["-i", "pcrab_+"]);
        assert_eq!(raw.spec.last().unwrap(), "DROP");
        assert_eq!(fwd_in.spec[..2], ["-i", "pcrab_+"]);
        assert_eq!(fwd_out.spec[..2], ["-o", "pcrab_+"]);
        for r in [&raw, &fwd_in, &fwd_out] {
            assert!(r.spec.contains(&"outstation-run-7".to_string()));
        }
        let a = session_accept_rule(
            "pcrab_",
            Ipv4Addr::new(10, 0, 0, 1),
            Some(2404),
            Ipv4Addr::new(192, 168, 1, 2),
            7,
        );
        assert_eq!(
            a.spec[..10],
            [
                "-i",
                "pcrab_+",
                "-s",
                "10.0.0.1/32",
                "-d",
                "192.168.1.2/32",
                "-p",
                "tcp",
                "--sport",
                "2404"
            ]
        );
        assert_eq!(a.spec.last().unwrap(), "ACCEPT");
        // Journal lines round-trip.
        let line = crate::journal::GuardEntry::Iptables {
            table: a.table.clone(),
            chain: a.chain.clone(),
            rule: a.spec.clone(),
        }
        .to_line()
        .unwrap();
        assert!(crate::journal::GuardEntry::parse(&line).is_some());
    }

    #[test]
    fn foreign_names_are_refused() {
        assert!(harden_iface("eth0", RpFilter::Strict).is_err());
        assert!(quiet_iface("eth0").is_err());
        assert!(Hardening::install("eth", None, None, 1, Path::new("/nonexistent")).is_err());
    }
}
