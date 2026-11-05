//! Host-state cleanup shared by server startup, graceful shutdown and
//! the `outstation cleanup` subcommand (systemd `ExecStopPost=`).

use std::path::Path;

use anyhow::Result;
use tracing::{info, warn};

use crate::state::alias_state_path_in;

/// Undo host network changes left behind by runs of this or a previous
/// process.
///
/// ORCHESTRATOR (T03 merge): replace the body of this function with a
/// call to `netctl::cleanup_all(state_dir)` once lane T03 has landed
/// it. Until then it reclaims what netctl can already undo: recorded IP
/// aliases and stale `pcr_*` bridge/veth interfaces. Everything else
/// (iptables rules, sysctls, NIC offloads) needs `cleanup_all`.
pub fn host_cleanup(state_dir: &Path) -> Result<()> {
    let state_path = alias_state_path_in(state_dir);
    match netctl::reclaim_recorded_aliases(&state_path) {
        Ok(n) if n > 0 => warn!(
            count = n,
            path = %state_path.display(),
            "reclaimed {n} orphaned ip alias(es) left by an earlier run"
        ),
        Ok(_) => {}
        Err(e) => warn!(error = %e, "reclaim_recorded_aliases failed"),
    }
    match netctl::reclaim_stale("pcr_br0", "pcr_") {
        Ok(n) if n > 0 => warn!(count = n, "reclaimed {n} stale pcr_* interface(s)"),
        Ok(_) => {}
        Err(e) => warn!(error = %e, "reclaim_stale failed"),
    }
    info!(state_dir = %state_dir.display(), "host cleanup done");
    Ok(())
}
