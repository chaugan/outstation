//! Interface names and ownership markers.
//!
//! Every interface outstation creates:
//!
//! * has a name that starts with [`IFNAME_PREFIX`] (`pcr`) and matches
//!   `^pcr[a-z0-9_]*$` within `IFNAMSIZ` (15 usable bytes), **including**
//!   the one-byte `i` suffix of a veth's inject-side peer;
//! * carries an ifalias of the form `outstation:<run_id>`
//!   (`ip link set dev X alias outstation:<run_id>`).
//!
//! Reclaim code deletes an interface only when both hold. A name prefix
//! alone (let alone one supplied by an HTTP request) is never enough.

use anyhow::{bail, Result};

/// Prefix of every interface name outstation creates.
pub const IFNAME_PREFIX: &str = "pcr";

/// Longest interface name the kernel accepts (`IFNAMSIZ - 1`).
pub const IFNAME_MAX: usize = 15;

/// Longest accepted bridge name or tap prefix: `pcr` plus up to 8 of
/// `[a-z0-9_]`, so a prefix leaves room for a port index and the veth
/// `i` suffix.
pub const PREFIX_MAX: usize = IFNAME_PREFIX.len() + 8;

/// ifalias marker prefix. The full marker is `outstation:<run_id>`.
pub const OWNER_MARKER: &str = "outstation:";

/// Base36 digits of the run id used in derived names. 36^4 = 1.68M
/// distinct tags before they wrap, which only matters if two runs whose
/// ids differ by a multiple of that are alive at the same time.
const RUN_TAG_DIGITS: u32 = 4;

fn is_name_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
}

/// Validate a bridge name or tap prefix supplied by a caller:
/// `^pcr[a-z0-9_]{0,8}$`. An empty or foreign prefix is an error.
pub fn validate_prefix(p: &str) -> Result<()> {
    if p.is_empty() {
        bail!("interface prefix must not be empty");
    }
    if !p.starts_with(IFNAME_PREFIX) {
        bail!("interface name/prefix {p:?} must start with {IFNAME_PREFIX:?}");
    }
    if p.len() > PREFIX_MAX {
        bail!("interface name/prefix {p:?} is longer than {PREFIX_MAX} characters");
    }
    if let Some(c) = p.chars().find(|c| !is_name_char(*c)) {
        bail!("interface name/prefix {p:?} contains {c:?}; only [a-z0-9_] are allowed");
    }
    Ok(())
}

/// Validate the full name of an interface outstation creates or
/// deletes: `^pcr[a-z0-9_]*$`, at most [`IFNAME_MAX`] bytes.
pub fn validate_owned_ifname(n: &str) -> Result<()> {
    if !n.starts_with(IFNAME_PREFIX) {
        bail!("interface name {n:?} must start with {IFNAME_PREFIX:?}");
    }
    if n.len() > IFNAME_MAX {
        bail!("interface name {n:?} exceeds IFNAMSIZ ({IFNAME_MAX} characters)");
    }
    if let Some(c) = n.chars().find(|c| !is_name_char(*c)) {
        bail!("interface name {n:?} contains {c:?}; only [a-z0-9_] are allowed");
    }
    Ok(())
}

/// Validate the name of a pre-existing host interface (egress NIC,
/// alias NIC, NAT NIC) before it is passed to `ip`, `ethtool` or
/// `iptables` or used in a `/sys` path. Accepts the characters real
/// interface names use (`[A-Za-z0-9_.-]`), at most [`IFNAME_MAX`].
pub fn validate_host_ifname(n: &str) -> Result<()> {
    if n.is_empty() || n.len() > IFNAME_MAX {
        bail!("interface name {n:?} must be 1..={IFNAME_MAX} characters");
    }
    if n == "." || n == ".." || n.starts_with('-') {
        bail!("invalid interface name {n:?}");
    }
    if let Some(c) = n
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')))
    {
        bail!("interface name {n:?} contains {c:?}");
    }
    Ok(())
}

/// The ifalias value that marks an interface as created by `run_id`.
pub fn owner_marker(run_id: u64) -> String {
    format!("{OWNER_MARKER}{run_id}")
}

/// Parse an ifalias value. `Some(run_id)` only for an exact
/// `outstation:<decimal>` marker.
pub fn parse_owner_marker(alias: &str) -> Option<u64> {
    let rest = alias.trim().strip_prefix(OWNER_MARKER)?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

fn base36(mut n: u64) -> String {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if n == 0 {
        return "0".into();
    }
    let mut out = Vec::new();
    while n > 0 {
        out.push(DIGITS[(n % 36) as usize]);
        n /= 36;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// Kinds of bridge port a run creates. Each has its own one-letter tag
/// so the names of different kinds never collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortKind {
    /// Raw replay, one per IPv4 source.
    RawIp,
    /// Raw replay, one per non-IP (L2) source MAC.
    RawL2,
    /// Benchmark session (master mode).
    Session,
    /// Passive mirror capture port.
    Capture,
}

impl PortKind {
    fn tag(self) -> &'static str {
        match self {
            PortKind::RawIp => "t",
            PortKind::RawL2 => "l",
            PortKind::Session => "b",
            PortKind::Capture => "cap",
        }
    }
}

/// The bridge and port names of one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceNames {
    pub run_id: u64,
    pub bridge: String,
    pub tap_prefix: String,
}

impl IfaceNames {
    /// Names derived from the run id: bridge `pcr<tag>_br`, ports
    /// `pcr<tag>_<kind><n>`, where `<tag>` is the run id in base36
    /// (mod 36^4).
    pub fn for_run(run_id: u64) -> Self {
        let tag = base36(run_id % 36u64.pow(RUN_TAG_DIGITS));
        Self {
            run_id,
            bridge: format!("{IFNAME_PREFIX}{tag}_br"),
            tap_prefix: format!("{IFNAME_PREFIX}{tag}_"),
        }
    }

    /// Caller-chosen names, validated with [`validate_prefix`]. `None`
    /// falls back to the derived name for that field.
    pub fn custom(run_id: u64, bridge: Option<&str>, tap_prefix: Option<&str>) -> Result<Self> {
        let mut n = Self::for_run(run_id);
        if let Some(b) = bridge {
            validate_prefix(b).map_err(|e| anyhow::anyhow!("bridge name: {e}"))?;
            n.bridge = b.to_string();
        }
        if let Some(t) = tap_prefix {
            validate_prefix(t).map_err(|e| anyhow::anyhow!("tap prefix: {e}"))?;
            n.tap_prefix = t.to_string();
        }
        if n.bridge.starts_with(&n.tap_prefix) && n.bridge != n.tap_prefix {
            // e.g. bridge "pcr_t" with tap prefix "pcr_": still fine as
            // long as no port name can equal the bridge name.
            let rest = &n.bridge[n.tap_prefix.len()..];
            for kind in [PortKind::RawIp, PortKind::RawL2, PortKind::Session] {
                if let Some(idx) = rest.strip_prefix(kind.tag()) {
                    if !idx.is_empty() && idx.bytes().all(|b| b.is_ascii_digit()) {
                        bail!(
                            "bridge name {:?} collides with port names of tap prefix {:?}",
                            n.bridge,
                            n.tap_prefix
                        );
                    }
                }
            }
            if rest == PortKind::Capture.tag() {
                bail!("bridge name {:?} collides with the capture port", n.bridge);
            }
        }
        Ok(n)
    }

    /// Bridge-side name of port `idx` of `kind`. Errors if the name
    /// plus the veth `i` suffix would not fit in IFNAMSIZ.
    pub fn port(&self, kind: PortKind, idx: usize) -> Result<String> {
        let name = match kind {
            PortKind::Capture => format!("{}{}", self.tap_prefix, kind.tag()),
            _ => format!("{}{}{}", self.tap_prefix, kind.tag(), idx),
        };
        if name.len() + 1 > IFNAME_MAX {
            bail!(
                "port name {name:?} plus veth suffix exceeds IFNAMSIZ; \
                 use a shorter tap prefix or fewer ports"
            );
        }
        validate_owned_ifname(&name)?;
        Ok(name)
    }

    /// Name of the passive capture mirror port.
    pub fn capture_port(&self) -> Result<String> {
        self.port(PortKind::Capture, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_validation() {
        assert!(validate_prefix("pcr").is_ok());
        assert!(validate_prefix("pcr_br0").is_ok());
        assert!(validate_prefix("pcr_t").is_ok());
        assert!(validate_prefix("pcr12345678").is_ok());
        assert!(validate_prefix("").is_err());
        assert!(validate_prefix("br0").is_err());
        assert!(validate_prefix("docker0").is_err());
        assert!(validate_prefix("pcr123456789").is_err(), "too long");
        assert!(validate_prefix("pcr-x").is_err());
        assert!(validate_prefix("pcr_BR").is_err());
        assert!(validate_prefix("pcr x").is_err());
        assert!(validate_prefix("pcr/../x").is_err());
    }

    #[test]
    fn owned_ifname_validation() {
        assert!(validate_owned_ifname("pcr1_t12i").is_ok());
        assert!(validate_owned_ifname("pcr_0123456789a").is_ok()); // 15
        assert!(validate_owned_ifname("pcr_0123456789ab").is_err()); // 16
        assert!(validate_owned_ifname("eth0").is_err());
    }

    #[test]
    fn host_ifname_validation() {
        assert!(validate_host_ifname("enp41s0").is_ok());
        assert!(validate_host_ifname("eth0.100").is_ok());
        assert!(validate_host_ifname("br-1a2b3c").is_ok());
        assert!(validate_host_ifname("").is_err());
        assert!(validate_host_ifname("..").is_err());
        assert!(validate_host_ifname("../../etc").is_err());
        assert!(validate_host_ifname("eth0 up").is_err());
        assert!(validate_host_ifname("-j").is_err());
        assert!(validate_host_ifname("abcdefghijklmnop").is_err());
    }

    #[test]
    fn marker_roundtrip() {
        assert_eq!(parse_owner_marker(&owner_marker(42)), Some(42));
        assert_eq!(parse_owner_marker("outstation:42\n"), Some(42));
        assert_eq!(parse_owner_marker("outstation:"), None);
        assert_eq!(parse_owner_marker("outstation:4x"), None);
        assert_eq!(parse_owner_marker("other:1"), None);
        assert_eq!(parse_owner_marker(""), None);
    }

    #[test]
    fn derived_names_fit_ifnamsiz() {
        for run_id in [0u64, 1, 35, 36, 1_679_615, 1_679_616, u64::MAX] {
            let n = IfaceNames::for_run(run_id);
            validate_prefix(&n.bridge).unwrap();
            validate_prefix(&n.tap_prefix).unwrap();
            // Up to 99_999 ports per kind still fit with the 'i' suffix.
            for kind in [PortKind::RawIp, PortKind::RawL2, PortKind::Session] {
                let p = n.port(kind, 99_999).unwrap();
                assert!(p.len() < IFNAME_MAX, "{p}");
                assert_ne!(p, n.bridge);
            }
            let c = n.capture_port().unwrap();
            assert!(c.len() < IFNAME_MAX);
            assert_ne!(c, n.bridge);
        }
        assert_eq!(IfaceNames::for_run(1).bridge, "pcr1_br");
        assert_eq!(
            IfaceNames::for_run(1).port(PortKind::Session, 3).unwrap(),
            "pcr1_b3"
        );
        assert_eq!(IfaceNames::for_run(36).tap_prefix, "pcr10_");
    }

    #[test]
    fn custom_names_are_validated() {
        let n = IfaceNames::custom(7, Some("pcr_br0"), Some("pcr_t")).unwrap();
        assert_eq!(n.bridge, "pcr_br0");
        assert_eq!(n.port(PortKind::RawIp, 0).unwrap(), "pcr_tt0");
        assert!(IfaceNames::custom(7, Some("br0"), None).is_err());
        assert!(IfaceNames::custom(7, None, Some("")).is_err());
        assert!(IfaceNames::custom(7, Some("virbr0"), None).is_err());
        // Port would be "pcr12345678t100000" + 'i': too long.
        let long = IfaceNames::custom(7, None, Some("pcr12345678")).unwrap();
        assert!(long.port(PortKind::RawIp, 100).is_err());
        // Bridge equal to a port name is refused.
        assert!(IfaceNames::custom(7, Some("pcr_t0"), Some("pcr_")).is_err());
        assert!(IfaceNames::custom(7, Some("pcr_cap"), Some("pcr_")).is_err());
    }
}
