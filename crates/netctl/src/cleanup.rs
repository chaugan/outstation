//! Crash recovery: reclaim interfaces and undo guard changes.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::alias::reclaim_recorded_aliases;
use crate::guard::{
    read_sysctl, read_tx_checksum, write_sysctl, TaggedRule, IPTABLES_COMMENT_PREFIX,
};
use crate::journal::{self, aliases_path, guards_path, GuardEntry};
use crate::names::{parse_owner_marker, validate_owned_ifname, validate_prefix, IFNAME_PREFIX};

/// One interface as listed by `ip -o link show`, with its owner marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInfo {
    pub name: String,
    /// `Some(run_id)` if the ifalias is an `outstation:<run_id>` marker.
    pub owner: Option<u64>,
}

/// Parse `ip -o link show` output.
pub fn parse_links(text: &str) -> Vec<LinkInfo> {
    let mut v = Vec::new();
    for line in text.lines() {
        let Some((_, rest)) = line.split_once(": ") else {
            continue;
        };
        let name_end = rest.find(':').unwrap_or(rest.len());
        let name_field = &rest[..name_end];
        let name = name_field
            .split_once('@')
            .map_or(name_field, |(n, _)| n)
            .to_string();
        // `ip -o` joins continuation lines with a backslash.
        let owner = line
            .split('\\')
            .skip(1)
            .map(str::trim)
            .find_map(|seg| seg.strip_prefix("alias "))
            .and_then(parse_owner_marker);
        v.push(LinkInfo { name, owner });
    }
    v
}

/// All interfaces on the host with their owner markers.
pub fn list_links() -> Result<Vec<LinkInfo>> {
    let out = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .context("spawn `ip -o link show`")?;
    if !out.status.success() {
        anyhow::bail!(
            "ip link show failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(parse_links(&String::from_utf8_lossy(&out.stdout)))
}

/// The owner run id of `iface`, if it carries an outstation marker.
pub fn iface_owner(iface: &str) -> Option<u64> {
    list_links()
        .ok()?
        .into_iter()
        .find(|l| l.name == iface)
        .and_then(|l| l.owner)
}

/// Pure selection: which links may reclaim delete?
pub fn select_reclaimable(links: &[LinkInfo], prefix: &str, run: Option<u64>) -> Vec<String> {
    links
        .iter()
        .filter(|l| l.name.starts_with(prefix))
        .filter(|l| validate_owned_ifname(&l.name).is_ok())
        .filter(|l| match (l.owner, run) {
            (Some(o), Some(r)) => o == r,
            (Some(_), None) => true,
            (None, _) => false,
        })
        .map(|l| l.name.clone())
        .collect()
}

fn delete_selected(names: Vec<String>, errors: &mut Vec<String>) -> usize {
    let mut deleted = 0;
    for name in names {
        // Deleting one end of a veth removes its peer too.
        if !crate::iface_exists(&name).unwrap_or(false) {
            continue;
        }
        match crate::delete_iface(&name) {
            Ok(()) => {
                deleted += 1;
                info!(iface = %name, "reclaimed stale outstation interface");
            }
            Err(e) => {
                warn!(iface = %name, error = %e, "reclaim delete failed");
                errors.push(format!("delete {name}: {e:#}"));
            }
        }
    }
    deleted
}

/// Delete stale interfaces that are provably outstation's: the name
/// starts with `prefix` (which must pass [`validate_prefix`], so it is
/// never empty and always starts with `pcr`) **and** the interface
/// carries an `outstation:<run_id>` ifalias marker. Interfaces without
/// the marker are never touched, whatever their name.
///
/// Must not be called while a run in this process is live; use
/// [`reclaim_run_ifaces`] at run start instead.
pub fn reclaim_stale(prefix: &str) -> Result<usize> {
    validate_prefix(prefix)?;
    let links = list_links()?;
    let mut errs = Vec::new();
    let n = delete_selected(select_reclaimable(&links, prefix, None), &mut errs);
    for e in errs {
        warn!("{e}");
    }
    Ok(n)
}

/// Delete leftover interfaces marked as belonging to `run_id` (from a
/// previous process that crashed while using the same id). Safe to
/// call while other runs are live: their interfaces carry other ids.
pub fn reclaim_run_ifaces(run_id: u64) -> Result<usize> {
    let links = list_links()?;
    let mut errs = Vec::new();
    let n = delete_selected(
        select_reclaimable(&links, IFNAME_PREFIX, Some(run_id)),
        &mut errs,
    );
    for e in errs {
        warn!("{e}");
    }
    Ok(n)
}

/// What [`cleanup_all`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanupReport {
    pub interfaces_removed: usize,
    pub iptables_rules_removed: usize,
    pub sysctls_restored: usize,
    pub offloads_restored: usize,
    pub aliases_removed: usize,
    /// Everything that could not be undone. Failed journal entries are
    /// kept, so a later call retries them.
    pub errors: Vec<String>,
}

impl CleanupReport {
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn total_actions(&self) -> usize {
        self.interfaces_removed
            + self.iptables_rules_removed
            + self.sysctls_restored
            + self.offloads_restored
            + self.aliases_removed
    }
}

const SCAN_TABLES: [&str; 4] = ["raw", "nat", "filter", "mangle"];

/// Parse one `iptables -S` line into a deletable rule if it carries an
/// outstation comment.
pub fn parse_tagged_rule(table: &str, line: &str) -> Option<TaggedRule> {
    let toks: Vec<String> = line
        .split_ascii_whitespace()
        .map(|t| t.trim_matches('"').to_string())
        .collect();
    if toks.first().map(String::as_str) != Some("-A") || toks.len() < 3 {
        return None;
    }
    let tagged = toks
        .windows(2)
        .any(|w| w[0] == "--comment" && w[1].starts_with(IPTABLES_COMMENT_PREFIX));
    if !tagged {
        return None;
    }
    Some(TaggedRule {
        table: table.to_string(),
        chain: toks[1].clone(),
        spec: toks[2..].to_vec(),
    })
}

fn scan_tagged_rules(errors: &mut Vec<String>) -> Vec<TaggedRule> {
    let mut v = Vec::new();
    for table in SCAN_TABLES {
        let out = match Command::new("iptables")
            .args(["-w", "-t", table, "-S"])
            .output()
        {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return v,
            Err(e) => {
                errors.push(format!("iptables -t {table} -S: {e}"));
                continue;
            }
        };
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            // A table that does not exist has nothing of ours in it.
            if !err.contains("does not exist") && !err.contains("Table does not exist") {
                errors.push(format!("iptables -t {table} -S: {}", err.trim()));
            }
            continue;
        }
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(r) = parse_tagged_rule(table, line) {
                if !v.contains(&r) {
                    v.push(r);
                }
            }
        }
    }
    v
}

fn restore_entry(e: &GuardEntry, report: &mut CleanupReport) -> Result<()> {
    match e {
        GuardEntry::Sysctl { key, prev } => {
            if read_sysctl(key)?.is_none() {
                return Ok(()); // setting vanished (module unloaded): nothing to restore
            }
            write_sysctl(key, prev)?;
            report.sysctls_restored += 1;
            info!(key, prev, "restored sysctl from journal");
        }
        GuardEntry::Offload {
            nic,
            feature,
            prev_on,
        } => {
            if feature != "tx" {
                anyhow::bail!("unknown offload feature {feature:?}");
            }
            if !crate::iface_exists(nic)? {
                return Ok(()); // NIC gone: nothing to restore
            }
            match read_tx_checksum(nic)? {
                Some((on, _)) if on == *prev_on => {}
                _ => {
                    let v = if *prev_on { "on" } else { "off" };
                    let out = Command::new("ethtool")
                        .args(["-K", nic, "tx", v])
                        .output()
                        .context("spawn ethtool")?;
                    if !out.status.success() {
                        anyhow::bail!(
                            "ethtool -K {nic} tx {v}: {}",
                            String::from_utf8_lossy(&out.stderr).trim()
                        );
                    }
                }
            }
            report.offloads_restored += 1;
            info!(nic, prev_on, "restored tx-checksum offload from journal");
        }
        GuardEntry::Iptables { table, chain, rule } => {
            let r = TaggedRule {
                table: table.clone(),
                chain: chain.clone(),
                spec: rule.clone(),
            };
            report.iptables_rules_removed += r.delete_all()?;
        }
    }
    Ok(())
}

/// Undo everything outstation may have left behind on this host,
/// using the journals in `state_dir` plus comment-tagged rule scanning:
///
/// 1. delete interfaces marked `outstation:<run>` (frees enslaved NICs);
/// 2. delete iptables rules from the guard journal, then any remaining
///    rule tagged `--comment outstation-run-*` (raw, nat, filter, mangle);
/// 3. restore journaled sysctl and offload values;
/// 4. delete journaled IP aliases (only ones outstation added).
///
/// Journal entries are removed only when undone; failures are kept and
/// listed in [`CleanupReport::errors`]. Idempotent: a second call finds
/// nothing to do. Must run when no run is live in this process (at
/// startup, after all runs were cancelled and joined, or from a
/// separate `outstation cleanup` process while the service is stopped).
pub fn cleanup_all(state_dir: &Path) -> Result<CleanupReport> {
    let mut report = CleanupReport::default();

    // 1. Interfaces.
    match list_links() {
        Ok(links) => {
            let names = select_reclaimable(&links, IFNAME_PREFIX, None);
            report.interfaces_removed = delete_selected(names, &mut report.errors);
        }
        Err(e) => report.errors.push(format!("list interfaces: {e:#}")),
    }

    // 2 + 3. Guard journal: iptables first, then settings.
    let gpath = guards_path(state_dir);
    let entries = journal::read_journal(&gpath)
        .with_context(|| format!("read guard journal {}", gpath.display()))?;
    let parsed: Vec<(String, Option<GuardEntry>)> = entries
        .into_iter()
        .map(|l| {
            let e = GuardEntry::parse(&l);
            (l, e)
        })
        .collect();
    // Rules before settings; settings in reverse journal order (LIFO).
    let (rules, mut settings): (Vec<_>, Vec<_>) = parsed
        .into_iter()
        .partition(|(_, e)| matches!(e, Some(GuardEntry::Iptables { .. })));
    settings.reverse();
    for (line, entry) in rules.into_iter().chain(settings) {
        let done = match &entry {
            None => {
                warn!(line, "dropping unparseable guard journal line");
                true
            }
            Some(e) => match restore_entry(e, &mut report) {
                Ok(()) => true,
                Err(err) => {
                    report.errors.push(format!("{line}: {err:#}"));
                    false
                }
            },
        };
        if done {
            if let Err(e) = journal::remove_line(&gpath, &line) {
                report.errors.push(format!("update guard journal: {e:#}"));
            }
        }
    }
    for r in scan_tagged_rules(&mut report.errors) {
        match r.delete_all() {
            Ok(n) => report.iptables_rules_removed += n,
            Err(e) => report.errors.push(format!("delete {r:?}: {e:#}")),
        }
    }

    // 4. Aliases.
    let apath = aliases_path(state_dir);
    match reclaim_recorded_aliases(&apath) {
        Ok(n) => report.aliases_removed = n,
        Err(e) => report.errors.push(format!("alias journal: {e:#}")),
    }
    if let Ok(left) = journal::read_journal(&apath) {
        for l in left {
            report.errors.push(format!("alias not removed: {l}"));
        }
    }

    if report.total_actions() > 0 || !report.errors.is_empty() {
        info!(?report, "cleanup_all finished");
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_parsing_reads_markers() {
        let text = "1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n\
                    2: pcr1_br: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN\\    link/ether da:ed:c2:c7:10:42 brd ff:ff:ff:ff:ff:ff\\    alias outstation:1\n\
                    3: pcr1_t0i@pcr1_t0: <BROADCAST> mtu 1500\\    link/ether 76:aa:75:78:04:6e brd ff:ff:ff:ff:ff:ff\\    alias outstation:1\n\
                    4: pcr_foreign: <BROADCAST> mtu 1500\\    link/ether 76:aa:75:78:04:6f brd ff:ff:ff:ff:ff:ff\n\
                    5: pcr_spoof: <BROADCAST> mtu 1500\\    link/ether 76:aa:75:78:04:6f brd ff:ff:ff:ff:ff:ff\\    alias outstation:x\n\
                    6: docker0: <BROADCAST> mtu 1500\\    link/ether 76:aa:75:78:04:70 brd ff:ff:ff:ff:ff:ff\\    alias outstation:3\n";
        let l = parse_links(text);
        assert_eq!(l.len(), 6);
        assert_eq!(l[1].owner, Some(1));
        assert_eq!(l[2].name, "pcr1_t0i");
        assert_eq!(l[2].owner, Some(1));
        assert_eq!(l[3].owner, None);
        assert_eq!(l[4].owner, None);

        let all = select_reclaimable(&l, "pcr", None);
        assert_eq!(all, vec!["pcr1_br", "pcr1_t0i"]);
        // docker0 has a marker but not our name: never selected.
        assert!(!all.contains(&"docker0".to_string()));
        assert_eq!(select_reclaimable(&l, "pcr", Some(2)), Vec::<String>::new());
        assert_eq!(select_reclaimable(&l, "pcr1_t", Some(1)), vec!["pcr1_t0i"]);
    }

    #[test]
    fn reclaim_refuses_bad_prefixes() {
        assert!(reclaim_stale("").is_err());
        assert!(reclaim_stale("br").is_err());
        assert!(reclaim_stale("docker").is_err());
    }

    #[test]
    fn tagged_rule_parsing() {
        let r = parse_tagged_rule(
            "raw",
            "-A PREROUTING -i pcr1_br -m comment --comment outstation-run-1 -j DROP",
        )
        .unwrap();
        assert_eq!(r.chain, "PREROUTING");
        assert_eq!(r.spec[0], "-i");
        let q = parse_tagged_rule(
            "nat",
            "-A POSTROUTING -o eth1 -m comment --comment \"outstation-run-7\" -j MASQUERADE",
        )
        .unwrap();
        assert!(q.spec.contains(&"outstation-run-7".to_string()));
        assert!(parse_tagged_rule("raw", "-A PREROUTING -i br0 -j DROP").is_none());
        assert!(parse_tagged_rule("raw", "-P PREROUTING ACCEPT").is_none());
        assert!(parse_tagged_rule(
            "raw",
            "-A PREROUTING -m comment --comment someone-else -j DROP"
        )
        .is_none());
    }
}
