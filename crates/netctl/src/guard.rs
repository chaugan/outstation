//! Journaled, fail-closed host guards.
//!
//! Every change a guard makes is written to the guard journal
//! ([`crate::journal::GUARDS_FILE`]) *before* it is applied and removed
//! only once it was undone, so [`crate::cleanup_all`] can restore the
//! host after a crash:
//!
//! * sysctls (`net.bridge.bridge-nf-call-iptables`, `net.ipv4.ip_forward`)
//!   and NIC offloads are reference-counted per process: the first user
//!   records the prior value, the last one restores it;
//! * iptables rules carry `-m comment --comment outstation-run-<id>`,
//!   are inserted only after an `iptables -C` check (never duplicated),
//!   and can also be found by scanning for the comment.
//!
//! [`EgressGuard::install`] and [`GatewayGuard::install`] fail closed:
//! if a step fails they roll back whatever they already did and return
//! the error.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

use anyhow::{bail, Context, Result};
use tracing::{info, warn};

use crate::alias::AliasLease;
use crate::journal::{self, guards_path, GuardEntry};
use crate::names::{validate_host_ifname, validate_owned_ifname};
use crate::protect::{check_nic_allowed, validate_alias_ip, Protection};

/// Comment prefix of every iptables rule outstation installs.
pub const IPTABLES_COMMENT_PREFIX: &str = "outstation-run-";

/// `outstation-run-<run_id>`.
pub fn iptables_comment(run_id: u64) -> String {
    format!("{IPTABLES_COMMENT_PREFIX}{run_id}")
}

pub const SYSCTL_BRIDGE_NF: &str = "net.bridge.bridge-nf-call-iptables";
pub const SYSCTL_IP_FORWARD: &str = "net.ipv4.ip_forward";

// ---------------------------------------------------------------------------
// sysctl / offload knobs

fn sysctl_path(key: &str) -> Result<PathBuf> {
    if key.is_empty()
        || key.contains("..")
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("invalid sysctl key {key:?}");
    }
    Ok(PathBuf::from("/proc/sys").join(key.replace('.', "/")))
}

/// Read a sysctl. `Ok(None)` if it does not exist (e.g. br_netfilter
/// not loaded).
pub fn read_sysctl(key: &str) -> Result<Option<String>> {
    let p = sysctl_path(key)?;
    match std::fs::read_to_string(&p) {
        Ok(s) => Ok(Some(s.trim().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", p.display())),
    }
}

/// Write a sysctl via `/proc/sys`, falling back to `sysctl -w`.
pub fn write_sysctl(key: &str, value: &str) -> Result<()> {
    let p = sysctl_path(key)?;
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        bail!("invalid sysctl value {value:?}");
    }
    let direct = std::fs::write(&p, format!("{value}\n"));
    if direct.is_ok() && read_sysctl(key)?.as_deref() == Some(value) {
        return Ok(());
    }
    let out = Command::new("sysctl")
        .args(["-w", &format!("{key}={value}")])
        .output()
        .context("spawn sysctl")?;
    if !out.status.success() {
        bail!(
            "set {key}={value} failed: {}{}",
            direct.err().map(|e| format!("{e}; ")).unwrap_or_default(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// State of an ethtool feature: `(on, fixed)`.
pub fn read_tx_checksum(nic: &str) -> Result<Option<(bool, bool)>> {
    validate_host_ifname(nic)?;
    let out = match Command::new("ethtool").args(["-k", nic]).output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("spawn ethtool"),
    };
    if !out.status.success() {
        bail!(
            "ethtool -k {nic} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(parse_tx_checksum(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse the `tx-checksumming:` line of `ethtool -k`.
pub fn parse_tx_checksum(text: &str) -> Option<(bool, bool)> {
    text.lines().find_map(|l| {
        let rest = l.trim().strip_prefix("tx-checksumming:")?.trim();
        Some((rest.starts_with("on"), rest.contains("[fixed]")))
    })
}

pub(crate) fn set_tx_checksum(nic: &str, on: bool) -> Result<()> {
    validate_host_ifname(nic)?;
    let val = if on { "on" } else { "off" };
    let out = Command::new("ethtool")
        .args(["-K", nic, "tx", val])
        .output()
        .context("spawn ethtool")?;
    if !out.status.success() {
        bail!(
            "`ethtool -K {nic} tx {val}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// A host setting a guard can override and later restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Knob {
    Sysctl(String),
    TxChecksum(String),
}

impl Knob {
    fn key(&self) -> String {
        match self {
            Knob::Sysctl(k) => format!("sysctl:{k}"),
            Knob::TxChecksum(n) => format!("offload:{n}:tx"),
        }
    }

    fn read(&self) -> Result<Option<String>> {
        match self {
            Knob::Sysctl(k) => read_sysctl(k),
            Knob::TxChecksum(n) => {
                Ok(read_tx_checksum(n)?.map(|(on, _)| if on { "on" } else { "off" }.to_string()))
            }
        }
    }

    fn write(&self, v: &str) -> Result<()> {
        match self {
            Knob::Sysctl(k) => write_sysctl(k, v),
            Knob::TxChecksum(n) => set_tx_checksum(n, v == "on"),
        }
    }

    fn entry(&self, prev: &str) -> GuardEntry {
        match self {
            Knob::Sysctl(k) => GuardEntry::Sysctl {
                key: k.clone(),
                prev: prev.to_string(),
            },
            Knob::TxChecksum(n) => GuardEntry::Offload {
                nic: n.clone(),
                feature: "tx".into(),
                prev_on: prev == "on",
            },
        }
    }
}

#[derive(Debug)]
struct KnobEntry {
    refs: usize,
    /// `Some((prev, journal_line, journal_path))` if we changed it.
    changed: Option<(String, String, PathBuf)>,
}

fn knob_registry() -> MutexGuard<'static, HashMap<String, KnobEntry>> {
    static REG: OnceLock<Mutex<HashMap<String, KnobEntry>>> = OnceLock::new();
    REG.get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Forget every in-process override reference (see
/// [`crate::alias`]'s counterpart).
pub(crate) fn forget_registry() {
    knob_registry().clear();
}

/// A reference to an overridden host setting. The prior value is
/// restored when the last lease on the same setting drops.
#[derive(Debug)]
pub struct KnobLease {
    knob: Knob,
    released: bool,
}

impl KnobLease {
    /// Set `knob` to `value` (journaling the prior value first) or join
    /// an existing override. `Ok(None)` if the setting does not exist.
    pub fn acquire(knob: Knob, value: &str, state_dir: &Path) -> Result<Option<Self>> {
        let key = knob.key();
        let mut reg = knob_registry();
        if let Some(e) = reg.get_mut(&key) {
            e.refs += 1;
            return Ok(Some(Self {
                knob,
                released: false,
            }));
        }
        let Some(prev) = knob.read()? else {
            return Ok(None);
        };
        let changed = if prev == value {
            None
        } else {
            let path = guards_path(state_dir);
            let line = knob.entry(&prev).to_line()?;
            journal::add_line(&path, &line)
                .with_context(|| format!("journal prior value of {key}"))?;
            if let Err(e) = knob.write(value) {
                let _ = journal::remove_line(&path, &line);
                return Err(e);
            }
            info!(key, prev, value, "host setting overridden for run");
            Some((prev, line, path))
        };
        reg.insert(key, KnobEntry { refs: 1, changed });
        Ok(Some(Self {
            knob,
            released: false,
        }))
    }

    pub fn release(mut self) -> Result<()> {
        self.do_release()
    }

    fn do_release(&mut self) -> Result<()> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        let key = self.knob.key();
        let mut reg = knob_registry();
        let Some(e) = reg.get_mut(&key) else {
            return Ok(());
        };
        e.refs = e.refs.saturating_sub(1);
        if e.refs > 0 {
            return Ok(());
        }
        let Some(e) = reg.remove(&key) else {
            return Ok(());
        };
        if let Some((prev, line, path)) = e.changed {
            self.knob
                .write(&prev)
                .with_context(|| format!("restore {key}={prev}"))?;
            info!(key, prev, "host setting restored");
            journal::remove_line(&path, &line)?;
        }
        Ok(())
    }
}

impl Drop for KnobLease {
    fn drop(&mut self) {
        if let Err(e) = self.do_release() {
            warn!(error = %format!("{e:#}"), "restore failed; journal keeps it for cleanup");
        }
    }
}

// ---------------------------------------------------------------------------
// iptables

/// Run `iptables` with `args`.
fn iptables(args: &[&str]) -> Result<std::process::Output> {
    Command::new("iptables")
        .arg("-w")
        .args(args)
        .output()
        .with_context(|| format!("spawn `iptables {}`", args.join(" ")))
}

/// One comment-tagged iptables rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedRule {
    pub table: String,
    pub chain: String,
    /// Rule spec without the chain, e.g. `-i pcr1_br -m comment
    /// --comment outstation-run-1 -j DROP`.
    pub spec: Vec<String>,
}

impl TaggedRule {
    fn args<'a>(&'a self, op: &'a str) -> Vec<&'a str> {
        let mut v = vec!["-t", self.table.as_str(), op, self.chain.as_str()];
        v.extend(self.spec.iter().map(String::as_str));
        v
    }

    /// `iptables -C`: does the rule exist?
    pub fn exists(&self) -> Result<bool> {
        let out = iptables(&self.args("-C"))?;
        if out.status.success() {
            return Ok(true);
        }
        let err = String::from_utf8_lossy(&out.stderr);
        if out.status.code() == Some(1)
            && (err.contains("does a matching rule exist")
                || err.contains("No chain/target/match")
                || err.contains("Bad rule"))
        {
            return Ok(false);
        }
        bail!("iptables -C failed: {}", err.trim())
    }

    /// Delete every copy of the rule (`-D` while `-C` succeeds).
    /// Returns how many were deleted.
    pub fn delete_all(&self) -> Result<usize> {
        let mut n = 0;
        while self.exists()? {
            let out = iptables(&self.args("-D"))?;
            if !out.status.success() {
                bail!(
                    "iptables -D failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            n += 1;
            if n > 64 {
                bail!("rule keeps reappearing after 64 deletes");
            }
        }
        Ok(n)
    }

    fn entry(&self) -> GuardEntry {
        GuardEntry::Iptables {
            table: self.table.clone(),
            chain: self.chain.clone(),
            rule: self.spec.clone(),
        }
    }
}

/// An installed tagged rule; deleted on drop.
#[derive(Debug)]
pub struct RuleLease {
    rule: TaggedRule,
    journal_path: PathBuf,
    line: String,
    released: bool,
}

impl RuleLease {
    /// Journal, `-C` check, then insert at the top of the chain
    /// (`top = true`) or append. An identical rule that already exists
    /// is adopted: it carries our run's comment, so it is ours.
    pub fn install(rule: TaggedRule, top: bool, state_dir: &Path) -> Result<Self> {
        let journal_path = guards_path(state_dir);
        let line = rule.entry().to_line()?;
        journal::add_line(&journal_path, &line).context("journal iptables rule")?;
        let res = (|| -> Result<()> {
            if rule.exists()? {
                info!(
                    ?rule,
                    "tagged iptables rule already present; not inserting a duplicate"
                );
                return Ok(());
            }
            let out = if top {
                let mut a = vec!["-t", rule.table.as_str(), "-I", rule.chain.as_str(), "1"];
                a.extend(rule.spec.iter().map(String::as_str));
                iptables(&a)?
            } else {
                iptables(&rule.args("-A"))?
            };
            if !out.status.success() {
                bail!(
                    "iptables insert failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            Ok(())
        })();
        if let Err(e) = res {
            let _ = journal::remove_line(&journal_path, &line);
            return Err(e);
        }
        Ok(Self {
            rule,
            journal_path,
            line,
            released: false,
        })
    }

    pub fn rule(&self) -> &TaggedRule {
        &self.rule
    }

    pub fn release(mut self) -> Result<()> {
        self.do_release()
    }

    fn do_release(&mut self) -> Result<()> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        self.rule.delete_all()?;
        journal::remove_line(&self.journal_path, &self.line)?;
        Ok(())
    }
}

impl Drop for RuleLease {
    fn drop(&mut self) {
        if let Err(e) = self.do_release() {
            warn!(rule = ?self.rule, error = %format!("{e:#}"),
                "iptables rule removal failed; journal keeps it for cleanup");
        }
    }
}

/// The raw-table DROP rule that keeps bridged frames out of the host
/// stack.
pub fn bridge_drop_rule(bridge: &str, run_id: u64) -> TaggedRule {
    TaggedRule {
        table: "raw".into(),
        chain: "PREROUTING".into(),
        spec: vec![
            "-i".into(),
            bridge.into(),
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            iptables_comment(run_id),
            "-j".into(),
            "DROP".into(),
        ],
    }
}

/// The NAT rule for SCADA-gateway upstream egress.
pub fn masquerade_rule(outer_nic: &str, run_id: u64) -> TaggedRule {
    TaggedRule {
        table: "nat".into(),
        chain: "POSTROUTING".into(),
        spec: vec![
            "-o".into(),
            outer_nic.into(),
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            iptables_comment(run_id),
            "-j".into(),
            "MASQUERADE".into(),
        ],
    }
}

// ---------------------------------------------------------------------------
// Egress guard

/// Safe-egress guard for a bridge with a physical NIC enslaved.
///
/// 1. `iptables -t raw -I PREROUTING 1 -i <bridge> -m comment --comment
///    outstation-run-<id> -j DROP` so the host stack ignores everything
///    bridged through (mandatory).
/// 2. `net.bridge.bridge-nf-call-iptables=0` if br_netfilter is loaded,
///    so the host firewall does not act on bridged frames (mandatory
///    when the sysctl exists).
/// 3. NIC tx-checksum offload off, so the NIC does not rewrite the L4
///    checksums we computed. Mandatory when ethtool reports the feature
///    as changeable; skipped with a warning when ethtool is missing or
///    the feature is `[fixed]` (a fidelity concern, not host safety).
///
/// If a mandatory step fails, the earlier steps are rolled back and
/// `install` returns the error. Everything is restored on drop.
#[derive(Debug)]
pub struct EgressGuard {
    pub bridge: String,
    pub nic: String,
    // Field order is drop order: reverse of install order.
    tx_checksum: Option<KnobLease>,
    bridge_nf: Option<KnobLease>,
    drop_rule: Option<RuleLease>,
    warnings: Vec<String>,
}

impl EgressGuard {
    pub fn install(bridge: &str, nic: &str, run_id: u64, state_dir: &Path) -> Result<Self> {
        validate_owned_ifname(bridge)?;
        validate_host_ifname(nic)?;
        let mut warnings = Vec::new();

        let drop_rule = RuleLease::install(bridge_drop_rule(bridge, run_id), true, state_dir)
            .with_context(|| format!("install iptables DROP rule for {bridge}"))?;
        info!(bridge, "iptables raw DROP rule active");

        let bridge_nf = KnobLease::acquire(Knob::Sysctl(SYSCTL_BRIDGE_NF.into()), "0", state_dir)
            .context("disable bridge-nf-call-iptables")?;
        if bridge_nf.is_none() {
            tracing::debug!("bridge-nf-call-iptables not present (br_netfilter not loaded)");
        }

        let tx_checksum = match read_tx_checksum(nic) {
            Ok(None) => {
                warnings.push(format!(
                    "could not read tx-checksum offload of {nic} (ethtool missing?); \
                     L4 checksums may be rewritten by the NIC"
                ));
                None
            }
            Ok(Some((_, true))) => {
                warnings.push(format!(
                    "tx-checksum offload of {nic} is fixed and cannot be changed"
                ));
                None
            }
            Ok(Some((false, false))) => None,
            Ok(Some((true, false))) => {
                KnobLease::acquire(Knob::TxChecksum(nic.into()), "off", state_dir)
                    .with_context(|| format!("disable tx-checksum offload on {nic}"))?
            }
            Err(e) => {
                warnings.push(format!("ethtool -k {nic}: {e:#}"));
                None
            }
        };
        for w in &warnings {
            warn!(bridge, nic, "{w}");
        }
        Ok(Self {
            bridge: bridge.to_string(),
            nic: nic.to_string(),
            tx_checksum,
            bridge_nf,
            drop_rule: Some(drop_rule),
            warnings,
        })
    }

    /// Non-fatal problems found during install, for the run's status.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Restore everything now, reporting the first failure. Failed
    /// restores stay in the journal for [`crate::cleanup_all`].
    pub fn release(mut self) -> Result<()> {
        let mut first: Option<anyhow::Error> = None;
        for r in [
            self.tx_checksum.take().map(KnobLease::release),
            self.bridge_nf.take().map(KnobLease::release),
            self.drop_rule.take().map(RuleLease::release),
        ]
        .into_iter()
        .flatten()
        {
            if let Err(e) = r {
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(()), Err)
    }
}

// ---------------------------------------------------------------------------
// SCADA gateway guard

/// SCADA-gateway mode: a `/32` alias for the SCADA guest's gateway IP
/// on the inner NIC, plus (if an outer NIC is given) IP forwarding and
/// a tagged MASQUERADE rule out of it. Everything is journaled, fails
/// closed and is undone on drop in reverse order.
#[derive(Debug)]
pub struct GatewayGuard {
    pub inner_nic: String,
    pub gateway_ip: Ipv4Addr,
    pub outer_nic: Option<String>,
    // Field order is drop order: reverse of install order.
    masq: Option<RuleLease>,
    ip_forward: Option<KnobLease>,
    alias: Option<AliasLease>,
}

impl GatewayGuard {
    pub fn install(
        inner_nic: &str,
        gateway_ip: Ipv4Addr,
        outer_nic: Option<&str>,
        run_id: u64,
        state_dir: &Path,
        prot: &Protection,
    ) -> Result<Self> {
        check_nic_allowed(inner_nic, "add the SCADA gateway alias to", prot)?;
        validate_alias_ip(gateway_ip, prot)?;
        if let Some(outer) = outer_nic {
            validate_host_ifname(outer)?;
            if !crate::iface_exists(outer)? {
                bail!("upstream NAT interface {outer} does not exist");
            }
        }
        let alias = AliasLease::acquire(inner_nic, gateway_ip, state_dir)
            .with_context(|| format!("add gateway alias {gateway_ip}/32 on {inner_nic}"))?;
        let (ip_forward, masq) = if let Some(outer) = outer_nic {
            let fwd = KnobLease::acquire(Knob::Sysctl(SYSCTL_IP_FORWARD.into()), "1", state_dir)
                .context("enable net.ipv4.ip_forward")?;
            let masq = RuleLease::install(masquerade_rule(outer, run_id), false, state_dir)
                .with_context(|| format!("install MASQUERADE out of {outer}"))?;
            info!(outer, "SCADA upstream NAT active");
            (fwd, Some(masq))
        } else {
            (None, None)
        };
        Ok(Self {
            inner_nic: inner_nic.to_string(),
            gateway_ip,
            outer_nic: outer_nic.map(str::to_string),
            masq,
            ip_forward,
            alias: Some(alias),
        })
    }

    /// Restore everything now, reporting the first failure.
    pub fn release(mut self) -> Result<()> {
        let mut first: Option<anyhow::Error> = None;
        let results = [
            self.masq.take().map(RuleLease::release),
            self.ip_forward.take().map(KnobLease::release),
            self.alias.take().map(AliasLease::release),
        ];
        for r in results.into_iter().flatten() {
            if let Err(e) = r {
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysctl_keys_validated() {
        assert_eq!(
            sysctl_path("net.ipv4.ip_forward").unwrap(),
            PathBuf::from("/proc/sys/net/ipv4/ip_forward")
        );
        assert!(sysctl_path("../../etc/passwd").is_err());
        assert!(sysctl_path("net/ipv4").is_err());
        assert!(sysctl_path("").is_err());
    }

    #[test]
    fn tx_checksum_parse() {
        assert_eq!(
            parse_tx_checksum("Features for eth0:\ntx-checksumming: on\n"),
            Some((true, false))
        );
        assert_eq!(
            parse_tx_checksum("tx-checksumming: off [fixed]\n"),
            Some((false, true))
        );
        assert_eq!(parse_tx_checksum("rx-checksumming: on\n"), None);
    }

    #[test]
    fn rules_are_tagged() {
        let r = bridge_drop_rule("pcr1_br", 1);
        assert!(r.spec.contains(&"outstation-run-1".to_string()));
        assert_eq!(r.table, "raw");
        let m = masquerade_rule("eth1", 9);
        assert!(m.spec.contains(&"outstation-run-9".to_string()));
        let l = r.entry().to_line().unwrap();
        assert_eq!(
            l,
            "iptables raw PREROUTING -i pcr1_br -m comment --comment outstation-run-1 -j DROP"
        );
    }
}
