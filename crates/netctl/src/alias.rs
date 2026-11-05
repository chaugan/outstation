//! Tracked, reference-counted IP aliases.
//!
//! * Aliases are always `/32 noprefixroute`, so adding one never
//!   installs a connected route that could hijack host traffic.
//! * [`add_ip_alias`] distinguishes [`AliasOutcome::Added`] from
//!   [`AliasOutcome::AlreadyPresent`]. Only addresses outstation added
//!   are journaled and later deleted; an address that already existed
//!   (a VRRP VIP, a static lab address, ...) is never touched.
//! * [`AliasLease`] reference-counts aliases within the process, so two
//!   sessions or runs sharing an IP do not delete it under each other.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

use anyhow::{bail, Context, Result};
use tracing::{info, warn};

use crate::journal::{self, aliases_path};
use crate::names::validate_host_ifname;

/// Result of [`add_ip_alias`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasOutcome {
    /// We added the address; we own it and must remove it.
    Added,
    /// The address was already assigned (on this or another interface).
    /// We do not own it and must never remove it.
    AlreadyPresent,
}

fn alias_line(iface: &str, ip: Ipv4Addr, prefix: u8) -> String {
    format!("{iface} {ip} {prefix}")
}

/// True if `ip` is assigned to any local interface.
pub fn ip_is_local(ip: Ipv4Addr) -> Result<bool> {
    Ok(crate::protect::all_local_addrs()?
        .iter()
        .any(|(_, a)| *a == IpAddr::V4(ip)))
}

fn is_already_assigned_err(stderr: &str) -> bool {
    stderr.contains("File exists") || stderr.contains("already assigned")
}

/// `ip addr add <ip>/32 dev <iface> noprefixroute`.
///
/// Returns [`AliasOutcome::AlreadyPresent`] without changing anything
/// if the address is already local (on any interface), or if the kernel
/// reports it as already assigned.
pub fn add_ip_alias(iface: &str, ip: Ipv4Addr) -> Result<AliasOutcome> {
    validate_host_ifname(iface)?;
    if ip_is_local(ip)? {
        return Ok(AliasOutcome::AlreadyPresent);
    }
    let cidr = format!("{ip}/32");
    let out = Command::new("ip")
        .args(["addr", "add", &cidr, "dev", iface, "noprefixroute"])
        .output()
        .with_context(|| format!("spawn `ip addr add {cidr} dev {iface}`"))?;
    if out.status.success() {
        return Ok(AliasOutcome::Added);
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if is_already_assigned_err(&err) {
        return Ok(AliasOutcome::AlreadyPresent);
    }
    bail!(
        "`ip addr add {cidr} dev {iface} noprefixroute` failed: {}",
        err.trim()
    )
}

/// `ip addr del <ip>/<prefix> dev <iface>`. An address or interface
/// that is already gone counts as success.
pub fn del_ip_alias(iface: &str, ip: Ipv4Addr, prefix: u8) -> Result<()> {
    validate_host_ifname(iface)?;
    let cidr = format!("{ip}/{prefix}");
    let out = Command::new("ip")
        .args(["addr", "del", &cidr, "dev", iface])
        .output()
        .with_context(|| format!("spawn `ip addr del {cidr} dev {iface}`"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("Cannot assign")
        || err.contains("does not exist")
        || err.contains("Cannot find device")
    {
        return Ok(());
    }
    bail!("`ip addr del {cidr} dev {iface}` failed: {}", err.trim())
}

/// Record an alias we added in the alias journal at `state_path`.
pub fn record_alias(state_path: &Path, iface: &str, ip: Ipv4Addr, prefix: u8) -> Result<()> {
    journal::add_line(state_path, &alias_line(iface, ip, prefix))
}

/// Remove one alias record from the alias journal.
pub fn forget_alias(state_path: &Path, iface: &str, ip: Ipv4Addr, prefix: u8) -> Result<()> {
    journal::remove_line(state_path, &alias_line(iface, ip, prefix)).map(|_| ())
}

/// Delete every alias recorded in the alias journal at `state_path`.
/// Lines whose delete succeeded (or whose address/interface is already
/// gone) are removed; lines that failed stay for the next attempt;
/// unparseable lines are dropped. Returns how many were removed.
///
/// Must not run while this process holds live [`AliasLease`]s.
pub fn reclaim_recorded_aliases(state_path: &Path) -> Result<usize> {
    if !state_path.exists() {
        return Ok(0);
    }
    journal::update_lines(state_path, |lines| {
        let mut removed = 0usize;
        lines.retain(|line| {
            let parts: Vec<&str> = line.split_ascii_whitespace().collect();
            let [iface, ip, prefix] = parts.as_slice() else {
                warn!(line, "dropping malformed alias journal line");
                return false;
            };
            let (Ok(ip), Ok(prefix)) = (ip.parse::<Ipv4Addr>(), prefix.parse::<u8>()) else {
                warn!(line, "dropping malformed alias journal line");
                return false;
            };
            match del_ip_alias(iface, ip, prefix) {
                Ok(()) => {
                    removed += 1;
                    info!(%iface, %ip, prefix, "reclaimed orphaned ip alias from prior run");
                    false
                }
                Err(e) => {
                    warn!(%iface, %ip, prefix, error = %e, "alias reclaim failed; keeping record");
                    true
                }
            }
        });
        removed
    })
}

#[derive(Debug)]
struct AliasEntry {
    refs: usize,
    owned: bool,
    journal: PathBuf,
}

fn registry() -> MutexGuard<'static, HashMap<(String, Ipv4Addr), AliasEntry>> {
    static REG: OnceLock<Mutex<HashMap<(String, Ipv4Addr), AliasEntry>>> = OnceLock::new();
    REG.get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Forget every in-process alias reference (after [`crate::cleanup_all`]
/// restored the host, they no longer describe anything real).
pub(crate) fn forget_registry() {
    registry().clear();
}

/// A reference to a `/32` alias. The address is removed when the last
/// lease on it drops, and only if this process added it.
#[derive(Debug)]
pub struct AliasLease {
    iface: String,
    ip: Ipv4Addr,
    outcome: AliasOutcome,
    released: bool,
}

impl AliasLease {
    /// Make sure `ip/32` is assigned to `iface` and take a reference.
    ///
    /// The caller is responsible for policy checks
    /// ([`crate::check_nic_allowed`], [`crate::validate_alias_ip`]).
    /// The alias is journaled under `state_dir` *before* it is added,
    /// so a crash at any point leaves it reclaimable; a journal failure
    /// aborts without touching the host.
    pub fn acquire(iface: &str, ip: Ipv4Addr, state_dir: &Path) -> Result<Self> {
        validate_host_ifname(iface)?;
        let journal_path = aliases_path(state_dir);
        let mut reg = registry();
        if let Some(e) = reg.get_mut(&(iface.to_string(), ip)) {
            e.refs += 1;
            let outcome = if e.owned {
                AliasOutcome::Added
            } else {
                AliasOutcome::AlreadyPresent
            };
            return Ok(Self {
                iface: iface.to_string(),
                ip,
                outcome,
                released: false,
            });
        }
        if ip_is_local(ip)? {
            reg.insert(
                (iface.to_string(), ip),
                AliasEntry {
                    refs: 1,
                    owned: false,
                    journal: journal_path,
                },
            );
            info!(%ip, iface, "address already local; using it without taking ownership");
            return Ok(Self {
                iface: iface.to_string(),
                ip,
                outcome: AliasOutcome::AlreadyPresent,
                released: false,
            });
        }
        record_alias(&journal_path, iface, ip, 32)
            .with_context(|| format!("journal alias {ip} on {iface}"))?;
        let outcome = match add_ip_alias(iface, ip) {
            Ok(o) => o,
            Err(e) => {
                let _ = forget_alias(&journal_path, iface, ip, 32);
                return Err(e);
            }
        };
        if outcome == AliasOutcome::AlreadyPresent {
            // Lost a race with someone else adding it: not ours.
            let _ = forget_alias(&journal_path, iface, ip, 32);
        } else {
            info!(%ip, iface, "added /32 noprefixroute alias");
        }
        reg.insert(
            (iface.to_string(), ip),
            AliasEntry {
                refs: 1,
                owned: outcome == AliasOutcome::Added,
                journal: journal_path,
            },
        );
        Ok(Self {
            iface: iface.to_string(),
            ip,
            outcome,
            released: false,
        })
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    /// Whether the address was added by this process (as opposed to
    /// already present).
    pub fn outcome(&self) -> AliasOutcome {
        self.outcome
    }

    /// Drop the reference now, returning the delete error if this was
    /// the last reference and the delete failed.
    pub fn release(mut self) -> Result<()> {
        self.do_release()
    }

    fn do_release(&mut self) -> Result<()> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        let mut reg = registry();
        let key = (self.iface.clone(), self.ip);
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
        if !e.owned {
            return Ok(());
        }
        del_ip_alias(&self.iface, self.ip, 32)
            .with_context(|| format!("remove alias {} from {}", self.ip, self.iface))?;
        info!(ip = %self.ip, iface = %self.iface, "removed /32 alias");
        // Only forget the journal record once the delete succeeded.
        forget_alias(&e.journal, &self.iface, self.ip, 32)
    }
}

impl Drop for AliasLease {
    fn drop(&mut self) {
        if let Err(e) = self.do_release() {
            warn!(ip = %self.ip, iface = %self.iface, error = %format!("{e:#}"),
                "alias release failed; journal keeps it for cleanup");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn already_assigned_detection() {
        assert!(is_already_assigned_err("RTNETLINK answers: File exists"));
        assert!(is_already_assigned_err(
            "Error: ipv4: Address already assigned."
        ));
        assert!(!is_already_assigned_err("Error: Cannot find device \"x\""));
    }

    #[test]
    fn reclaim_drops_malformed_and_missing_file_is_ok() {
        let d = std::env::temp_dir().join(format!(
            "netctl-alias-{}-{}",
            std::process::id(),
            crate::test_nonce()
        ));
        assert_eq!(reclaim_recorded_aliases(&d.join("nope.txt")).unwrap(), 0);
        let p = d.join("a.txt");
        crate::journal::add_line(&p, "garbage").unwrap();
        crate::journal::add_line(&p, "eth0 notanip 32").unwrap();
        assert_eq!(reclaim_recorded_aliases(&p).unwrap(), 0);
        assert!(crate::journal::read_journal(&p).unwrap().is_empty());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
