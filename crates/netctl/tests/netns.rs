//! Privileged integration tests for netctl's host-safety guarantees.
//!
//! Every test here changes interfaces, addresses, iptables rules and
//! sysctls, so they are `#[ignore]`d and refuse to run unless they are
//! inside a throwaway network namespace named `ostest-*` with
//! `OUTSTATION_NETNS_TEST=1` set. Never run them in the host namespace.
//!
//! Run them with `scripts/netns-test.sh`, which builds this binary,
//! creates the namespace, runs `--ignored --test-threads=1` inside it
//! via `sudo ip netns exec`, and deletes the namespace again. By hand:
//!
//! ```sh
//! cargo test -p netctl --test netns --no-run   # note the binary path
//! sudo ip netns add ostest-hs-1
//! sudo ip netns exec ostest-hs-1 env OUTSTATION_NETNS_TEST=1 \
//!     <binary> --ignored --test-threads=1
//! sudo ip netns del ostest-hs-1
//! ```

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::Command;

use netctl::guard::{read_sysctl, read_tx_checksum, write_sysctl};
use netctl::{
    check_nic_allowed, cleanup_all, reclaim_stale, AliasLease, AliasOutcome, EgressGuard,
    GatewayGuard, Protection, Topology,
};

/// Panic unless we are inside an `ostest-*` namespace. This is the only
/// thing standing between these tests and the host's network config.
fn require_test_netns() {
    assert_eq!(
        std::env::var("OUTSTATION_NETNS_TEST").as_deref(),
        Ok("1"),
        "set OUTSTATION_NETNS_TEST=1 and run inside an ostest-* netns (scripts/netns-test.sh)"
    );
    let out = Command::new("ip")
        .args(["netns", "identify"])
        .output()
        .expect("run `ip netns identify`");
    let ns = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(
        ns.starts_with("ostest-"),
        "refusing to run outside an ostest-* network namespace (current: {ns:?})"
    );
}

fn sh(args: &[&str]) -> String {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| panic!("spawn {args:?}: {e}"));
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn sh_ok(args: &[&str]) -> bool {
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn exists(iface: &str) -> bool {
    sh_ok(&["ip", "link", "show", "dev", iface])
}

fn has_addr(iface: &str, ip: &str) -> bool {
    sh(&["ip", "-o", "addr", "show", "dev", iface]).contains(&format!(" {ip}/"))
}

/// Count rules in `table` mentioning `needle`.
fn rule_count(table: &str, needle: &str) -> usize {
    sh(&["iptables", "-t", table, "-S"])
        .lines()
        .filter(|l| l.contains(needle))
        .count()
}

/// Baseline topology inside the namespace (idempotent):
/// * `nsup0` (10.99.0.1/24) carries the default route via 10.99.0.254;
/// * `nsfree0` is an unremarkable NIC (10.99.3.1/24).
fn setup() {
    require_test_netns();
    sh(&["ip", "link", "set", "lo", "up"]);
    if !exists("nsup0") {
        sh(&[
            "ip", "link", "add", "nsup0", "type", "veth", "peer", "name", "nsup1",
        ]);
        sh(&["ip", "addr", "add", "10.99.0.1/24", "dev", "nsup0"]);
        sh(&["ip", "link", "set", "nsup0", "up"]);
        sh(&["ip", "link", "set", "nsup1", "up"]);
        sh(&[
            "ip",
            "route",
            "add",
            "default",
            "via",
            "10.99.0.254",
            "dev",
            "nsup0",
        ]);
    }
    if !exists("nsfree0") {
        sh(&[
            "ip", "link", "add", "nsfree0", "type", "veth", "peer", "name", "nsfree1",
        ]);
        sh(&["ip", "addr", "add", "10.99.3.1/24", "dev", "nsfree0"]);
        sh(&["ip", "link", "set", "nsfree0", "up"]);
        sh(&["ip", "link", "set", "nsfree1", "up"]);
    }
}

fn state_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("netctl-netns-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Reclaim deletes only interfaces with our marker and a pcr* name.
#[test]
#[ignore = "privileged: run via scripts/netns-test.sh inside an ostest-* netns"]
fn reclaim_refuses_foreign_interfaces() {
    setup();
    // Foreign: right prefix, no marker.
    sh(&["ip", "link", "add", "pcr_foreign", "type", "bridge"]);
    // Foreign: our marker, but not our name (spoofed / someone else's).
    sh(&["ip", "link", "add", "br-spoof", "type", "bridge"]);
    sh(&[
        "ip",
        "link",
        "set",
        "dev",
        "br-spoof",
        "alias",
        "outstation:9",
    ]);
    // Ours: a marked bridge and port, then "crash" (leak).
    let mut t = Topology::new("pcr9_br", 9).unwrap();
    t.create_bridge().unwrap();
    t.add_port("pcr9_t0", None).unwrap();
    t.leak();
    assert!(exists("pcr9_br") && exists("pcr9_t0") && exists("pcr9_t0i"));

    assert!(reclaim_stale("").is_err());
    assert!(reclaim_stale("br").is_err());
    let n = reclaim_stale("pcr").unwrap();
    assert!(n >= 2, "deleted {n}");
    assert!(!exists("pcr9_br") && !exists("pcr9_t0") && !exists("pcr9_t0i"));
    assert!(exists("pcr_foreign"), "unmarked pcr_foreign was deleted");
    assert!(exists("br-spoof"), "non-pcr interface was deleted");

    // A topology never adopts or deletes a foreign interface.
    let mut t = Topology::new("pcr_foreign", 1).unwrap();
    assert!(t.create_bridge().is_err());
    drop(t);
    assert!(exists("pcr_foreign"));

    sh(&["ip", "link", "del", "pcr_foreign"]);
    sh(&["ip", "link", "del", "br-spoof"]);
}

/// An address that was already there is never removed; one we added
/// is refcounted and removed with the last lease.
#[test]
#[ignore = "privileged: run via scripts/netns-test.sh inside an ostest-* netns"]
fn already_present_alias_survives_teardown() {
    setup();
    let dir = state_dir("alias");
    sh(&["ip", "addr", "add", "10.99.3.50/32", "dev", "nsfree0"]);
    let pre = AliasLease::acquire("nsfree0", Ipv4Addr::new(10, 99, 3, 50), &dir).unwrap();
    assert_eq!(pre.outcome(), AliasOutcome::AlreadyPresent);
    pre.release().unwrap();
    assert!(
        has_addr("nsfree0", "10.99.3.50"),
        "pre-existing address was deleted"
    );

    let ip = Ipv4Addr::new(10, 20, 30, 40);
    let a = AliasLease::acquire("nsfree0", ip, &dir).unwrap();
    assert_eq!(a.outcome(), AliasOutcome::Added);
    let b = AliasLease::acquire("nsfree0", ip, &dir).unwrap();
    assert!(has_addr("nsfree0", "10.20.30.40"));
    // /32 noprefixroute: no connected route for 10.20.30.0/24 appeared.
    assert!(!sh(&["ip", "route", "show"]).contains("10.20.30."));
    let journal = std::fs::read_to_string(netctl::aliases_path(&dir)).unwrap();
    assert!(journal.contains("nsfree0 10.20.30.40 32"));
    drop(a);
    assert!(
        has_addr("nsfree0", "10.20.30.40"),
        "removed while still referenced"
    );
    drop(b);
    assert!(!has_addr("nsfree0", "10.20.30.40"));
    assert!(std::fs::read_to_string(netctl::aliases_path(&dir))
        .unwrap()
        .trim()
        .is_empty());

    sh(&["ip", "addr", "del", "10.99.3.50/32", "dev", "nsfree0"]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// After a crash (guards leaked), cleanup_all restores sysctls,
/// offloads, iptables rules, aliases and interfaces; a second call
/// finds nothing to do.
#[test]
#[ignore = "privileged: run via scripts/netns-test.sh inside an ostest-* netns"]
fn cleanup_all_restores_sysctls_and_iptables() {
    setup();
    let dir = state_dir("cleanup");
    write_sysctl("net.ipv4.ip_forward", "0").unwrap();
    let tx_before = read_tx_checksum("nsfree0").unwrap();

    let gw = GatewayGuard::install(
        "nsfree0",
        Ipv4Addr::new(10, 99, 4, 1),
        Some("nsup0"),
        77,
        &dir,
        &Protection::default(),
    )
    .unwrap();
    let mut topo = Topology::new("pcr77_br", 77).unwrap();
    topo.create_bridge().unwrap();
    // nsfree1 is a plain veth end without addresses: allowed.
    topo.enslave_existing("nsfree1", &Protection::default())
        .unwrap();
    let eg = EgressGuard::install("pcr77_br", "nsfree1", 77, &dir).unwrap();

    assert_eq!(
        read_sysctl("net.ipv4.ip_forward").unwrap().as_deref(),
        Some("1")
    );
    assert_eq!(rule_count("nat", "outstation-run-77"), 1);
    assert_eq!(rule_count("raw", "outstation-run-77"), 1);
    assert!(has_addr("nsfree0", "10.99.4.1"));

    // Simulated SIGKILL: nothing restores.
    std::mem::forget(gw);
    std::mem::forget(eg);
    topo.leak();

    let r = cleanup_all(&dir).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(
        read_sysctl("net.ipv4.ip_forward").unwrap().as_deref(),
        Some("0")
    );
    assert_eq!(rule_count("nat", "outstation-run-"), 0);
    assert_eq!(rule_count("raw", "outstation-run-"), 0);
    assert!(!has_addr("nsfree0", "10.99.4.1"));
    assert!(!exists("pcr77_br"));
    assert_eq!(read_tx_checksum("nsfree1").unwrap(), tx_before);
    assert!(r.sysctls_restored >= 1 && r.iptables_rules_removed >= 2);

    let again = cleanup_all(&dir).unwrap();
    assert!(again.is_clean(), "{again:?}");
    assert_eq!(again.total_actions(), 0, "{again:?}");

    // A rule tagged by an unjournaled crash is found by the scan alone.
    sh(&[
        "iptables",
        "-t",
        "raw",
        "-A",
        "PREROUTING",
        "-i",
        "pcr5_br",
        "-m",
        "comment",
        "--comment",
        "outstation-run-5",
        "-j",
        "DROP",
    ]);
    let r = cleanup_all(&dir).unwrap();
    assert_eq!(r.iptables_rules_removed, 1);
    assert_eq!(rule_count("raw", "outstation-run-"), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The raw DROP rule is checked with -C and never duplicated, and the
/// tx-checksum offload is restored on release.
#[test]
#[ignore = "privileged: run via scripts/netns-test.sh inside an ostest-* netns"]
fn drop_rule_is_not_duplicated() {
    setup();
    let dir = state_dir("drop");
    let tx_before = read_tx_checksum("nsfree1").unwrap();
    let mut topo = Topology::new("pcr6_br", 6).unwrap();
    topo.create_bridge().unwrap();
    let g1 = EgressGuard::install("pcr6_br", "nsfree1", 6, &dir).unwrap();
    if tx_before.is_some_and(|(on, fixed)| on && !fixed) {
        assert_eq!(
            read_tx_checksum("nsfree1").unwrap().map(|t| t.0),
            Some(false)
        );
    }
    let g2 = EgressGuard::install("pcr6_br", "nsfree1", 6, &dir).unwrap();
    assert_eq!(
        rule_count("raw", "outstation-run-6"),
        1,
        "DROP rule duplicated"
    );
    g2.release().unwrap();
    assert_eq!(rule_count("raw", "outstation-run-6"), 0);
    drop(g1);
    topo.teardown().unwrap();
    assert_eq!(read_tx_checksum("nsfree1").unwrap(), tx_before);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The default-route NIC, protected-address NICs, bridges and bridge
/// ports are refused unless forced; loopback always.
#[test]
#[ignore = "privileged: run via scripts/netns-test.sh inside an ostest-* netns"]
fn protected_nics_are_refused() {
    setup();
    let none = Protection::default();
    let e = check_nic_allowed("nsup0", "enslave", &none).unwrap_err();
    assert!(format!("{e}").contains("default route"), "{e}");
    let mut topo = Topology::new("pcr8_br", 8).unwrap();
    topo.create_bridge().unwrap();
    assert!(topo.enslave_existing("nsup0", &none).is_err());
    assert!(topo
        .enslave_existing("lo", &Protection::new(vec![], true))
        .is_err());

    // The NIC carrying the web UI's own address.
    let web = Protection::new(vec![IpAddr::V4(Ipv4Addr::new(10, 99, 3, 1))], false);
    assert!(check_nic_allowed("nsfree0", "enslave", &web).is_err());
    assert!(check_nic_allowed("nsfree0", "enslave", &none).is_ok());

    // Real bridges and existing bridge ports.
    assert!(check_nic_allowed("pcr8_br", "enslave", &Protection::new(vec![], true)).is_err());
    sh(&["ip", "link", "add", "hostbr0", "type", "bridge"]);
    assert!(check_nic_allowed("hostbr0", "enslave", &none).is_err());
    topo.enslave_existing("nsfree1", &none).unwrap();
    let e = check_nic_allowed("nsfree1", "enslave", &none).unwrap_err();
    assert!(format!("{e}").contains("port"), "{e}");

    // force overrides the default-route protection (inside the netns).
    assert!(check_nic_allowed("nsup0", "enslave", &Protection::new(vec![], true)).is_ok());

    // Gateway mode refuses to alias onto the default-route NIC.
    let dir = state_dir("prot");
    assert!(
        GatewayGuard::install("nsup0", Ipv4Addr::new(10, 99, 5, 1), None, 8, &dir, &none).is_err()
    );
    // ... and refuses to alias the LAN's gateway address anywhere.
    assert!(GatewayGuard::install(
        "nsfree0",
        Ipv4Addr::new(10, 99, 0, 254),
        None,
        8,
        &dir,
        &none
    )
    .is_err());

    topo.teardown().unwrap();
    assert!(!sh(&["ip", "-o", "link", "show", "dev", "nsfree1"]).contains("master"));
    sh(&["ip", "link", "del", "hostbr0"]);
    std::fs::remove_dir_all(&dir).unwrap();
}
