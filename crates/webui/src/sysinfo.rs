//! Host facts for `/api/status` and disk quotas: free space and
//! effective capabilities.

use std::path::Path;

use serde::Serialize;

/// Free bytes available to unprivileged users on the filesystem holding
/// `path`, via `statvfs`.
pub(crate) fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs writes into a zeroed struct we own.
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut st) != 0 {
            return None;
        }
        Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
    }
}

/// Where the disk checks (upload limits, health, the run guard) read
/// free space from. The default reads
/// [`free_bytes`] (statvfs); tests substitute a fixed figure so their
/// result does not depend on what else is writing to the disk.
#[derive(Clone)]
pub struct FreeSpace(std::sync::Arc<FreeBytesFn>);

/// Free bytes on the filesystem holding a path.
type FreeBytesFn = dyn Fn(&Path) -> Option<u64> + Send + Sync;

impl FreeSpace {
    /// A provider backed by `f`.
    pub fn from_fn(f: impl Fn(&Path) -> Option<u64> + Send + Sync + 'static) -> Self {
        Self(std::sync::Arc::new(f))
    }

    /// Free bytes on the filesystem holding `path`, if known.
    pub fn free_bytes(&self, path: &Path) -> Option<u64> {
        (self.0)(path)
    }
}

impl Default for FreeSpace {
    fn default() -> Self {
        Self::from_fn(free_bytes)
    }
}

impl std::fmt::Debug for FreeSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FreeSpace(..)")
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Capabilities {
    /// Raw `CapEff` mask from /proc/self/status, hex.
    pub cap_eff: String,
    pub net_admin: bool,
    pub net_raw: bool,
    pub net_bind_service: bool,
    pub sys_nice: bool,
}

const CAP_NET_BIND_SERVICE: u32 = 10;
const CAP_NET_ADMIN: u32 = 12;
const CAP_NET_RAW: u32 = 13;
const CAP_SYS_NICE: u32 = 23;

pub(crate) fn parse_cap_eff(status: &str) -> Option<Capabilities> {
    let hex = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))?
        .trim();
    let mask = u64::from_str_radix(hex, 16).ok()?;
    let has = |bit: u32| mask & (1u64 << bit) != 0;
    Some(Capabilities {
        cap_eff: hex.to_string(),
        net_admin: has(CAP_NET_ADMIN),
        net_raw: has(CAP_NET_RAW),
        net_bind_service: has(CAP_NET_BIND_SERVICE),
        sys_nice: has(CAP_SYS_NICE),
    })
}

pub(crate) fn capabilities() -> Option<Capabilities> {
    parse_cap_eff(&std::fs::read_to_string("/proc/self/status").ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_parse() {
        let c = parse_cap_eff("Name:\tx\nCapEff:\t0000000000803400\n").unwrap();
        assert!(c.net_admin && c.net_raw && c.net_bind_service && c.sys_nice);
        let c = parse_cap_eff("CapEff:\t0000000000000000\n").unwrap();
        assert!(!c.net_admin);
        assert!(parse_cap_eff("nothing").is_none());
    }

    #[test]
    fn free_space_of_tmp() {
        assert!(free_bytes(Path::new("/")).is_some());
        assert!(free_bytes(Path::new("/definitely/not/here")).is_none());
    }
}
