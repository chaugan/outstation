//! Host-state cleanup shared by server startup, graceful shutdown and
//! the `outstation cleanup` subcommand (systemd `ExecStopPost=`).

use std::path::Path;

use anyhow::Result;
use tracing::{info, warn};

/// Undo host network changes left behind by runs of this or a previous
/// process: everything recorded in netctl's guard journal under
/// `state_dir` (sysctls, NIC offloads, iptables rules tagged
/// `outstation-run-<id>`, IP aliases) plus our marked `pcr*`
/// interfaces. Idempotent; called at startup, after graceful shutdown,
/// and by `outstation cleanup` (systemd `ExecStopPost=`).
pub fn host_cleanup(state_dir: &Path) -> Result<()> {
    let report = netctl::cleanup_all(state_dir)?;
    let undone = report.interfaces_removed
        + report.iptables_rules_removed
        + report.sysctls_restored
        + report.offloads_restored
        + report.aliases_removed;
    if undone > 0 {
        warn!(
            interfaces = report.interfaces_removed,
            iptables_rules = report.iptables_rules_removed,
            sysctls = report.sysctls_restored,
            offloads = report.offloads_restored,
            aliases = report.aliases_removed,
            "undid host changes left behind by earlier runs"
        );
    }
    for e in &report.errors {
        warn!(error = %e, "host cleanup could not undo an entry (kept for retry)");
    }
    info!(state_dir = %state_dir.display(), "host cleanup done");
    Ok(())
}
