//! AF_PACKET-based raw frame replayer with microsecond-accurate scheduling.
//!
//! Open an [`RawReplayer`] bound to one outbound interface, feed it a
//! [`Plan`] (a timestamped list of full Ethernet frames), and call
//! [`run_plan`] to inject them. Scheduling uses `CLOCK_MONOTONIC` via
//! `clock_nanosleep(TIMER_ABSTIME)` plus a short busy-spin tail for
//! sub-hundred-microsecond jitter.
//!
//! This crate owns no network topology — the caller is expected to have
//! created the target interface already (typically a TAP managed by the
//! `netctl` crate).

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::{anyhow, Context, Result};
use tracing::{debug, warn};

pub mod capture;
pub use capture::Capture;

/// A single frame plus its target send time relative to the start of the
/// replay window (nanoseconds).
#[derive(Debug, Clone)]
pub struct ScheduledFrame {
    pub rel_ts_ns: u64,
    pub frame: Vec<u8>,
}

/// An ordered list of frames to replay on one interface.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub frames: Vec<ScheduledFrame>,
}

impl Plan {
    pub fn push(&mut self, rel_ts_ns: u64, frame: Vec<u8>) {
        self.frames.push(ScheduledFrame { rel_ts_ns, frame });
    }
    pub fn len(&self) -> usize {
        self.frames.len()
    }
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

/// Pacing strategy for a replay run.
#[derive(Debug, Clone, Copy)]
pub enum Pace {
    /// Honor the pcap's inter-packet gaps, scaled by `speed` (2.0 = twice
    /// as fast, 0.5 = half speed).
    Original { speed: f64 },
    /// Send back-to-back, ignoring original timestamps.
    TopSpeed,
}

/// Optional cooperative controls for a live run. Callers that need
/// live progress reporting or cancellation pass borrowed references;
/// callers that don't care pass [`RunControls::default`] and the hot
/// loop short-circuits every branch on the `None` side.
#[derive(Default)]
pub struct RunControls<'a> {
    /// If set to true, the send loop exits at the next frame boundary.
    pub cancel: Option<&'a AtomicBool>,
    /// Incremented by 1 on each successful send.
    pub sent: Option<&'a AtomicU64>,
    /// Incremented by the number of wire bytes on each successful send.
    pub bytes: Option<&'a AtomicU64>,
    /// Incremented by 1 on each send error.
    pub send_errors: Option<&'a AtomicU64>,
}

/// Statistics from a completed run.
#[derive(Debug, Clone, Copy, Default)]
pub struct RunStats {
    pub sent: u64,
    pub bytes: u64,
    pub send_errors: u64,
    pub elapsed_ns: u64,
    /// Mean absolute jitter between target and actual send time, in ns.
    pub mean_abs_jitter_ns: u64,
    /// Worst-case signed jitter (positive = late, negative = early).
    pub max_jitter_ns: i64,
    /// 99th percentile absolute jitter, in ns.
    pub p99_abs_jitter_ns: u64,
}

/// A bound AF_PACKET SOCK_RAW socket pointing at one interface.
pub struct RawReplayer {
    fd: OwnedFd,
    iface: String,
    ifindex: i32,
}

impl RawReplayer {
    /// Bind to `iface`. Requires CAP_NET_RAW. The interface must exist
    /// and be up; frames smaller than 14 bytes will be rejected by the
    /// kernel as malformed Ethernet.
    pub fn bind(iface: &str) -> Result<Self> {
        let ifindex = if_nametoindex(iface)?;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error())
                .context("socket(AF_PACKET, SOCK_RAW)");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = ifindex;

        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("bind to {iface}"));
        }
        debug!(iface, ifindex, "AF_PACKET bound");
        Ok(Self {
            fd,
            iface: iface.to_string(),
            ifindex,
        })
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }
    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }

    /// Send a single frame. The frame must contain a full Ethernet header.
    pub fn send(&self, frame: &[u8]) -> io::Result<usize> {
        let n = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

impl AsRawFd for RawReplayer {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

fn if_nametoindex(iface: &str) -> Result<i32> {
    let c = CString::new(iface).context("iface name contains nul byte")?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(anyhow!(io::Error::last_os_error())
            .context(format!("if_nametoindex({iface})")));
    }
    Ok(idx as i32)
}

/// Monotonic clock read in nanoseconds.
#[inline]
pub fn now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

/// Absolute-deadline sleep on CLOCK_MONOTONIC. Returns early if the
/// deadline is already past or if the call is interrupted; the caller
/// is expected to follow up with a busy-spin.
fn clock_nanosleep_abs(target_ns: u64) {
    let ts = libc::timespec {
        tv_sec: (target_ns / 1_000_000_000) as libc::time_t,
        tv_nsec: (target_ns % 1_000_000_000) as i64,
    };
    unsafe {
        libc::clock_nanosleep(
            libc::CLOCK_MONOTONIC,
            libc::TIMER_ABSTIME,
            &ts,
            std::ptr::null_mut(),
        );
    }
}

/// Hybrid precise sleep: coarse `clock_nanosleep` to within ~100 µs of
/// the target, then busy-spin on `clock_gettime` to the exact mark.
#[inline]
fn sleep_until_precise(target_ns: u64) {
    let now = now_ns();
    if target_ns <= now {
        return;
    }
    let gap = target_ns - now;
    if gap > 150_000 {
        clock_nanosleep_abs(target_ns - 100_000);
    }
    while now_ns() < target_ns {
        std::hint::spin_loop();
    }
}

/// Drive a replay to completion.
///
/// Equivalent to [`run_plan_ctl`] with [`RunControls::default()`]. Kept
/// so existing callers that don't need live progress / cancellation
/// don't have to thread the optional struct through.
pub fn run_plan(replayer: &RawReplayer, plan: &Plan, pace: Pace) -> RunStats {
    run_plan_ctl(replayer, plan, pace, RunControls::default())
}

/// Drive a replay to completion with optional cooperative controls.
/// Sends stop at the next frame boundary if `controls.cancel` flips to
/// true. Publishes running totals into the optional counters so an
/// HTTP handler in another thread can read progress without locking.
pub fn run_plan_ctl(
    replayer: &RawReplayer,
    plan: &Plan,
    pace: Pace,
    controls: RunControls<'_>,
) -> RunStats {
    let start = now_ns();
    let mut sent = 0u64;
    let mut bytes = 0u64;
    let mut send_errors = 0u64;
    // Store absolute jitter samples so we can compute a p99 later.
    let mut abs_jitter: Vec<u64> = Vec::with_capacity(plan.frames.len());
    let mut max_signed: i64 = 0;

    for f in &plan.frames {
        if let Some(c) = controls.cancel {
            if c.load(Ordering::Relaxed) {
                debug!("run_plan_ctl cancelled at {sent} frames");
                break;
            }
        }
        if let Pace::Original { speed } = pace {
            let target = start + ((f.rel_ts_ns as f64) / speed) as u64;
            sleep_until_precise(target);
            let actual = now_ns();
            let delta = actual as i64 - target as i64;
            let abs = delta.unsigned_abs();
            abs_jitter.push(abs);
            if delta.abs() > max_signed.abs() {
                max_signed = delta;
            }
        }
        match replayer.send(&f.frame) {
            Ok(_) => {
                sent += 1;
                bytes += f.frame.len() as u64;
                if let Some(c) = controls.sent {
                    c.fetch_add(1, Ordering::Relaxed);
                }
                if let Some(c) = controls.bytes {
                    c.fetch_add(f.frame.len() as u64, Ordering::Relaxed);
                }
            }
            Err(e) => {
                warn!(error = %e, "send failed");
                send_errors += 1;
                if let Some(c) = controls.send_errors {
                    c.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    let elapsed_ns = now_ns() - start;
    let (mean_abs, p99_abs) = summarize_jitter(&mut abs_jitter);
    RunStats {
        sent,
        bytes,
        send_errors,
        elapsed_ns,
        mean_abs_jitter_ns: mean_abs,
        max_jitter_ns: max_signed,
        p99_abs_jitter_ns: p99_abs,
    }
}

fn summarize_jitter(samples: &mut [u64]) -> (u64, u64) {
    if samples.is_empty() {
        return (0, 0);
    }
    let sum: u128 = samples.iter().map(|v| *v as u128).sum();
    let mean = (sum / samples.len() as u128) as u64;
    samples.sort_unstable();
    let idx = ((samples.len() as f64) * 0.99) as usize;
    let idx = idx.min(samples.len() - 1);
    (mean, samples[idx])
}

/// Raise the current thread's priority to `SCHED_FIFO` with the given
/// priority. Silently no-ops if the process lacks `CAP_SYS_NICE`.
pub fn try_set_realtime(priority: i32) {
    let param = libc::sched_param {
        sched_priority: priority,
    };
    let rc = unsafe { libc::sched_setscheduler(0, libc::SCHED_FIFO, &param) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        debug!(error = %err, "SCHED_FIFO not available; continuing with default policy");
    } else {
        debug!(priority, "thread promoted to SCHED_FIFO");
    }
}

/// Build a [`Plan`] from a loaded pcap filtered to one source IP.
/// Returns the plan plus the number of frames it contains.
pub fn plan_for_source(
    pcap: &pcapload::LoadedPcap,
    src_ip: std::net::Ipv4Addr,
) -> Result<Plan> {
    let src = pcap
        .sources
        .get(&src_ip)
        .ok_or_else(|| anyhow!("source {src_ip} not found in pcap"))?;
    let mut plan = Plan::default();
    for &idx in &src.packet_indices {
        let pkt = &pcap.packets[idx];
        plan.push(pkt.rel_ts_ns, pkt.data.clone());
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_summary_basic() {
        let mut v: Vec<u64> = (1..=100).collect();
        let (mean, p99) = summarize_jitter(&mut v);
        assert_eq!(mean, 50);
        assert_eq!(p99, 100);
    }

    #[test]
    fn jitter_summary_empty() {
        let mut v: Vec<u64> = vec![];
        assert_eq!(summarize_jitter(&mut v), (0, 0));
    }

    #[test]
    fn sleep_until_precise_respects_deadline() {
        let start = now_ns();
        let target = start + 2_000_000; // 2 ms
        sleep_until_precise(target);
        let actual = now_ns();
        assert!(actual >= target, "woke early: {} < {}", actual, target);
        // Accept up to 5 ms of scheduling slack on a VM.
        assert!(
            actual - target < 5_000_000,
            "jitter too high: {} ns",
            actual - target
        );
    }
}
