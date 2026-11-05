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

pub mod bpf;
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
    /// If set to true, the send loop exits at the next frame boundary,
    /// and any pacing sleep in progress returns within
    /// [`CANCEL_SLICE_NS`].
    pub cancel: Option<&'a AtomicBool>,
    /// Incremented by 1 on each successful send.
    pub sent: Option<&'a AtomicU64>,
    /// Incremented by the number of wire bytes on each successful send.
    pub bytes: Option<&'a AtomicU64>,
    /// Incremented by 1 on each send error.
    pub send_errors: Option<&'a AtomicU64>,
    /// Second set of counters, bumped alongside the ones above. Lets a
    /// caller feed a per-source counter and a run-wide counter live
    /// from the same hot loop.
    pub global_sent: Option<&'a AtomicU64>,
    pub global_bytes: Option<&'a AtomicU64>,
    pub global_send_errors: Option<&'a AtomicU64>,
}

/// Anything that can put one Ethernet frame on the wire. Implemented by
/// [`RawReplayer`]; tests use an in-memory sink.
pub trait FrameSink {
    fn send_frame(&self, frame: &[u8]) -> io::Result<usize>;
}

impl FrameSink for RawReplayer {
    fn send_frame(&self, frame: &[u8]) -> io::Result<usize> {
        self.send(frame)
    }
}

/// Longest single sleep a pacing wait performs before re-checking the
/// cancel flag (100 ms). Bounds how long STOP can take in raw mode.
pub const CANCEL_SLICE_NS: u64 = 100_000_000;

/// Gaps longer than this are slept with `clock_nanosleep` alone, with
/// no busy-spin tail. Spinning only pays off for sub-millisecond gaps;
/// above that it burns a CPU (at SCHED_FIFO, possibly starving others)
/// for no measurable accuracy gain.
pub const SPIN_TAIL_MAX_GAP_NS: u64 = 1_000_000;

/// Upper bound on how far into the future a single frame may be
/// scheduled relative to the replay epoch (31 days). A corrupt or
/// wrapped pcap timestamp (or a speed close to 0) would otherwise ask
/// for a sleep of centuries; such frames are clamped to this offset.
pub const MAX_SCHEDULE_OFFSET_NS: u64 = 31 * 24 * 3600 * 1_000_000_000;

/// Slowest and fastest accepted replay speeds. Values outside the range
/// (including NaN, 0, negative and infinity) are clamped into it.
pub const MIN_SPEED: f64 = 1e-3;
pub const MAX_SPEED: f64 = 1e6;

/// SCHED_FIFO priority used for replay workers. Deliberately low: it is
/// enough to beat SCHED_OTHER tasks but leaves room for kernel threads
/// and for the capture thread above it.
pub const REPLAY_RT_PRIORITY: i32 = 10;

/// SCHED_FIFO priority for the mirror-capture thread when a run uses
/// realtime replay. One above [`REPLAY_RT_PRIORITY`] so the capture
/// reader, which only ever blocks in `recv`, is never starved by the
/// replay workers it is recording.
pub const CAPTURE_RT_PRIORITY: i32 = REPLAY_RT_PRIORITY + 1;

/// Clamp a user-supplied speed into `[MIN_SPEED, MAX_SPEED]`. Non-finite
/// or non-positive values become 1.0.
pub fn sanitize_speed(speed: f64) -> f64 {
    if !speed.is_finite() || speed <= 0.0 {
        return 1.0;
    }
    speed.clamp(MIN_SPEED, MAX_SPEED)
}

/// Offset from the replay epoch at which a frame with pcap-relative
/// timestamp `rel_ts_ns` goes out at `speed`, clamped to
/// [`MAX_SCHEDULE_OFFSET_NS`].
#[inline]
pub fn schedule_offset_ns(rel_ts_ns: u64, speed: f64) -> u64 {
    let off = (rel_ts_ns as f64) / sanitize_speed(speed);
    if off.is_nan() || off <= 0.0 {
        0
    } else if off >= MAX_SCHEDULE_OFFSET_NS as f64 {
        MAX_SCHEDULE_OFFSET_NS
    } else {
        off as u64
    }
}

/// How many replay threads may be promoted to SCHED_FIFO: one fewer
/// than the number of CPUs, so at least one CPU always stays available
/// to SCHED_OTHER work (web UI, SSH, teardown commands).
pub fn realtime_thread_budget() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .saturating_sub(1)
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
            return Err(io::Error::last_os_error()).context("socket(AF_PACKET, SOCK_RAW)");
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
            return Err(io::Error::last_os_error()).with_context(|| format!("bind to {iface}"));
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
        return Err(anyhow!(io::Error::last_os_error()).context(format!("if_nametoindex({iface})")));
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
/// deadline is already past or if the call is interrupted; callers
/// loop on the clock.
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

/// Cancellable precise sleep until `target_ns` (CLOCK_MONOTONIC).
///
/// * The wait is cut into absolute `clock_nanosleep` slices of at most
///   [`CANCEL_SLICE_NS`], and `cancel` is checked between slices, so a
///   STOP lands within ~100 ms however far away the deadline is.
/// * Gaps above [`SPIN_TAIL_MAX_GAP_NS`] end with a plain absolute
///   sleep (no spin).
/// * Shorter gaps sleep to ~100 µs before the target and busy-spin the
///   rest for sub-100 µs accuracy.
///
/// Returns `false` if cancelled before the deadline, `true` otherwise.
pub fn sleep_until_precise(target_ns: u64, cancel: Option<&AtomicBool>) -> bool {
    let cancelled = || cancel.is_some_and(|c| c.load(Ordering::Relaxed));
    let mut now = now_ns();
    if target_ns <= now {
        return !cancelled();
    }
    let spin_tail = target_ns - now <= SPIN_TAIL_MAX_GAP_NS;
    let coarse_target = if spin_tail {
        target_ns.saturating_sub(100_000)
    } else {
        target_ns
    };
    while now < coarse_target {
        if cancelled() {
            return false;
        }
        let slice_end = coarse_target.min(now.saturating_add(CANCEL_SLICE_NS));
        clock_nanosleep_abs(slice_end);
        now = now_ns();
    }
    if spin_tail {
        while now_ns() < target_ns {
            std::hint::spin_loop();
        }
    }
    !cancelled()
}

/// Drive a replay to completion.
///
/// Equivalent to [`run_plan_ctl`] with [`RunControls::default()`]. Kept
/// so existing callers that don't need live progress / cancellation
/// don't have to thread the optional struct through.
pub fn run_plan(replayer: &RawReplayer, plan: &Plan, pace: Pace) -> RunStats {
    run_plan_ctl(replayer, plan, pace, RunControls::default())
}

/// Drive a replay to completion with optional cooperative controls,
/// using "now" as the epoch. See [`run_plan_at`].
pub fn run_plan_ctl(
    replayer: &RawReplayer,
    plan: &Plan,
    pace: Pace,
    controls: RunControls<'_>,
) -> RunStats {
    run_plan_at(replayer, plan, pace, now_ns(), controls)
}

/// Drive a replay with an explicit epoch: frame `f` is sent at
/// `epoch_ns + schedule_offset_ns(f.rel_ts_ns, speed)`. Several workers
/// given the same `epoch_ns` keep their relative schedules aligned.
///
/// Stops at the next frame boundary (or within [`CANCEL_SLICE_NS`] of a
/// pacing sleep) once `controls.cancel` flips. Publishes running totals
/// into the optional counters so another thread can read progress
/// without locking.
pub fn run_plan_at<S: FrameSink + ?Sized>(
    sink: &S,
    plan: &Plan,
    pace: Pace,
    epoch_ns: u64,
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
            let target = epoch_ns.saturating_add(schedule_offset_ns(f.rel_ts_ns, speed));
            if !sleep_until_precise(target, controls.cancel) {
                debug!("run_plan_at cancelled while pacing at {sent} frames");
                break;
            }
            let actual = now_ns();
            let delta = actual as i64 - target as i64;
            let abs = delta.unsigned_abs();
            abs_jitter.push(abs);
            if delta.abs() > max_signed.abs() {
                max_signed = delta;
            }
        }
        match sink.send_frame(&f.frame) {
            Ok(_) => {
                let len = f.frame.len() as u64;
                sent += 1;
                bytes += len;
                for c in [controls.sent, controls.global_sent].into_iter().flatten() {
                    c.fetch_add(1, Ordering::Relaxed);
                }
                for c in [controls.bytes, controls.global_bytes]
                    .into_iter()
                    .flatten()
                {
                    c.fetch_add(len, Ordering::Relaxed);
                }
            }
            Err(e) => {
                warn!(error = %e, "send failed");
                send_errors += 1;
                for c in [controls.send_errors, controls.global_send_errors]
                    .into_iter()
                    .flatten()
                {
                    c.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    let elapsed_ns = now_ns().saturating_sub(start);
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
/// priority. Returns whether the promotion took effect; without
/// `CAP_SYS_NICE` it fails and the thread keeps its default policy.
///
/// Callers should respect [`realtime_thread_budget`] and never promote
/// a thread that busy-loops without sleeping (top-speed replay): with
/// the kernel default `sched_rt_runtime_us=950000`, FIFO threads may
/// take 95% of every CPU they run on before RT throttling kicks in.
pub fn try_set_realtime(priority: i32) -> bool {
    let param = libc::sched_param {
        sched_priority: priority,
    };
    let rc = unsafe { libc::sched_setscheduler(0, libc::SCHED_FIFO, &param) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        debug!(error = %err, "SCHED_FIFO not available; continuing with default policy");
        false
    } else {
        debug!(priority, "thread promoted to SCHED_FIFO");
        true
    }
}

/// Build a [`Plan`] from a loaded pcap filtered to one source IP.
/// Returns the plan plus the number of frames it contains.
pub fn plan_for_source(pcap: &pcapload::LoadedPcap, src_ip: std::net::Ipv4Addr) -> Result<Plan> {
    let src = pcap
        .sources
        .get(&src_ip)
        .ok_or_else(|| anyhow!("source {src_ip} not found in pcap"))?;
    let mut plan = Plan::default();
    for &idx in &src.packet_indices {
        let pkt = &pcap.packets[idx];
        plan.push(pkt.rel_ts_ns, pkt.ether_frame().into_owned());
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
        assert!(sleep_until_precise(target, None));
        let actual = now_ns();
        assert!(actual >= target, "woke early: {} < {}", actual, target);
        // Accept up to 5 ms of scheduling slack on a VM.
        assert!(
            actual - target < 5_000_000,
            "jitter too high: {} ns",
            actual - target
        );
    }

    #[test]
    fn sleep_until_precise_short_gap_spins_to_deadline() {
        let target = now_ns() + 300_000; // 300 us: sleep + spin tail
        assert!(sleep_until_precise(target, None));
        assert!(now_ns() >= target);
    }

    #[test]
    fn sleep_until_precise_is_cancellable() {
        let cancel = AtomicBool::new(false);
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(50));
                cancel.store(true, Ordering::Relaxed);
            });
            let t0 = now_ns();
            // One hour away: must return within one slice of the cancel.
            let ok = sleep_until_precise(t0 + 3_600_000_000_000, Some(&cancel));
            assert!(!ok);
            let waited = now_ns() - t0;
            assert!(waited < 50_000_000 + 2 * CANCEL_SLICE_NS, "{waited}");
        });
    }

    #[test]
    fn schedule_offset_is_clamped() {
        assert_eq!(schedule_offset_ns(1_000, 1.0), 1_000);
        assert_eq!(schedule_offset_ns(1_000, 2.0), 500);
        // Wrapped "584 years" timestamp from a backwards pcap.
        assert_eq!(schedule_offset_ns(u64::MAX, 1.0), MAX_SCHEDULE_OFFSET_NS);
        // Speed 0 / NaN / negative fall back to 1.0 instead of dividing by 0.
        assert_eq!(schedule_offset_ns(1_000, 0.0), 1_000);
        assert_eq!(schedule_offset_ns(1_000, f64::NAN), 1_000);
        assert_eq!(schedule_offset_ns(1_000, -3.0), 1_000);
        // Tiny speed is clamped to MIN_SPEED and the result to the cap.
        assert_eq!(
            schedule_offset_ns(u64::MAX / 2, 1e-12),
            MAX_SCHEDULE_OFFSET_NS
        );
    }

    struct VecSink(std::sync::Mutex<Vec<(u64, usize)>>);
    impl FrameSink for VecSink {
        fn send_frame(&self, frame: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().push((now_ns(), frame.len()));
            Ok(frame.len())
        }
    }

    #[test]
    fn run_plan_at_absurd_timestamp_is_cancellable() {
        // P04: a frame scheduled "centuries" out must not pin the worker.
        let mut plan = Plan::default();
        plan.push(0, vec![0u8; 60]);
        plan.push(u64::MAX - 5, vec![0u8; 60]);
        let sink = VecSink(Default::default());
        let cancel = AtomicBool::new(false);
        let sent = AtomicU64::new(0);
        let global = AtomicU64::new(0);
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(30));
                cancel.store(true, Ordering::Relaxed);
            });
            let t0 = now_ns();
            let stats = run_plan_at(
                &sink,
                &plan,
                Pace::Original { speed: 1.0 },
                t0,
                RunControls {
                    cancel: Some(&cancel),
                    sent: Some(&sent),
                    global_sent: Some(&global),
                    ..Default::default()
                },
            );
            assert_eq!(stats.sent, 1);
            assert!(now_ns() - t0 < 1_000_000_000);
        });
        assert_eq!(sent.load(Ordering::Relaxed), 1);
        assert_eq!(global.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn run_plan_at_backwards_timestamps_send_immediately() {
        // pcapload rel times are non-negative but may go backwards; a
        // frame whose slot is already past goes out at once, no underflow.
        let mut plan = Plan::default();
        plan.push(20_000_000, vec![0u8; 20]);
        plan.push(0, vec![1u8; 20]);
        plan.push(10_000_000, vec![2u8; 20]);
        let sink = VecSink(Default::default());
        let epoch = now_ns();
        let stats = run_plan_at(
            &sink,
            &plan,
            Pace::Original { speed: 1.0 },
            epoch,
            Default::default(),
        );
        assert_eq!(stats.sent, 3);
        let sent = sink.0.lock().unwrap();
        // The two late frames follow the first one without waiting.
        assert!(sent[2].0 - sent[0].0 < 5_000_000);
        assert!(stats.elapsed_ns < 100_000_000);
    }

    #[test]
    fn run_plan_at_uses_shared_epoch() {
        // Two plans run against the same epoch land relative to it,
        // regardless of when each call starts.
        let epoch = now_ns() + 20_000_000;
        let mut plan = Plan::default();
        plan.push(5_000_000, vec![1u8; 20]);
        let sink = VecSink(Default::default());
        std::thread::sleep(std::time::Duration::from_millis(5));
        run_plan_at(
            &sink,
            &plan,
            Pace::Original { speed: 1.0 },
            epoch,
            Default::default(),
        );
        let (t, _) = sink.0.lock().unwrap()[0];
        assert!(t >= epoch + 5_000_000, "sent before its slot");
        assert!(t < epoch + 5_000_000 + 5_000_000, "sent >5ms late");
    }

    #[test]
    fn realtime_budget_leaves_a_cpu() {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        assert_eq!(realtime_thread_budget(), cpus - 1);
    }
}
