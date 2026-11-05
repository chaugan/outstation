//! Passive capture: bind AF_PACKET to an interface, write received
//! frames to a classic pcap file. Used by the orchestrator to record
//! the frames it just replayed, so the web UI can offer them as a
//! downloadable pcap without the user running Wireshark/tcpdump.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use tracing::{debug, info, warn};

use crate::bpf;

/// One AF_PACKET socket of a capture.
struct CapSock {
    fd: OwnedFd,
    iface: String,
    /// On `lo` every frame is seen twice, once outgoing and once
    /// incoming; the outgoing copy is skipped (as libpcap does).
    loopback: bool,
    /// The socket's TPACKET_V3 receive ring, when the kernel gave one
    /// (else frames are read with `recvmsg`).
    ring: Option<Ring>,
}

/// Size of one block of a capture's receive ring, and their number:
/// 32 MiB per socket, like the receive buffer of the `recvmsg` path,
/// but a block packs frames back to back (about 100 bytes for a small
/// IEC 104 frame instead of a socket buffer's ~1 KiB per frame), so the
/// ring holds several times as many frames, and the reader takes a
/// whole block per wakeup without a system call per frame (T17c).
const RING_BLOCK_SIZE: u32 = 1 << 20;
const RING_BLOCKS: u32 = 32;
/// A block the kernel has started filling is handed to the reader at
/// the latest this many ms later, even when not full.
const RING_BLOCK_TIMEOUT_MS: u32 = 2;
/// TPACKET_V3 (`enum tpacket_versions`).
const TPACKET_V3: libc::c_int = 2;

/// A TPACKET_V3 receive ring mapped from an AF_PACKET socket.
struct Ring {
    base: *mut u8,
    len: usize,
}

// SAFETY: the mapping is plain shared memory; only the reader thread
// touches its contents, and the handle only drops it (after the reader
// removed the socket or exited).
unsafe impl Send for Ring {}

impl Drop for Ring {
    fn drop(&mut self) {
        // SAFETY: `base`/`len` are the mapping made in `setup_ring`.
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, self.len);
        }
    }
}

/// What the reader needs of a socket, copied out of the lock.
#[derive(Clone)]
struct SockView {
    fd: RawFd,
    loopback: bool,
    iface: String,
    /// Ring base address (the mapping outlives the view: only the
    /// reader removes sockets).
    ring: Option<usize>,
}

/// Switch `fd` to TPACKET_V3 and map a receive ring. Fails (and the
/// socket stays as it was) when the kernel refuses, e.g. for lack of
/// memory.
fn setup_ring(fd: RawFd) -> Result<Ring> {
    let set = |opt: libc::c_int, val: *const libc::c_void, len: usize, what: &str| -> Result<()> {
        // SAFETY: `val` points at `len` valid bytes.
        let rc =
            unsafe { libc::setsockopt(fd, libc::SOL_PACKET, opt, val, len as libc::socklen_t) };
        if rc < 0 {
            return Err(io::Error::last_os_error()).with_context(|| format!("set {what}"));
        }
        Ok(())
    };
    let v = TPACKET_V3;
    set(
        libc::PACKET_VERSION,
        &v as *const libc::c_int as *const libc::c_void,
        mem::size_of::<libc::c_int>(),
        "PACKET_VERSION",
    )?;
    let frame_size: u32 = 2048;
    let req = libc::tpacket_req3 {
        tp_block_size: RING_BLOCK_SIZE,
        tp_block_nr: RING_BLOCKS,
        tp_frame_size: frame_size,
        tp_frame_nr: RING_BLOCK_SIZE / frame_size * RING_BLOCKS,
        tp_retire_blk_tov: RING_BLOCK_TIMEOUT_MS,
        tp_sizeof_priv: 0,
        tp_feature_req_word: 0,
    };
    set(
        libc::PACKET_RX_RING,
        &req as *const libc::tpacket_req3 as *const libc::c_void,
        mem::size_of::<libc::tpacket_req3>(),
        "PACKET_RX_RING",
    )?;
    let len = (RING_BLOCK_SIZE as usize) * (RING_BLOCKS as usize);
    // SAFETY: maps the ring the kernel just allocated for `fd`.
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return Err(io::Error::last_os_error()).context("mmap the capture ring");
    }
    Ok(Ring {
        base: base as *mut u8,
        len,
    })
}

/// Sockets and filter shared between the handle and the reader thread.
/// Only the reader removes sockets, so the raw fds it snapshots stay
/// open while it uses them.
#[derive(Default)]
struct Inner {
    socks: Vec<CapSock>,
    /// Kernel filter every socket carries; `None` = unfiltered.
    filter: Option<Vec<bpf::Insn>>,
    /// The byte cap was reached: the sockets are closed and no
    /// interface is added any more.
    closed: bool,
}

/// Handle to a running capture thread.
pub struct Capture {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    inner: Arc<Mutex<Inner>>,
    pub path: PathBuf,
    pub packets: Arc<AtomicU64>,
    pub bytes: Arc<AtomicU64>,
    /// Frames the kernel dropped because a socket's receive queue was
    /// full (PACKET_STATISTICS): the capture file is missing them.
    /// Updated about once a second and when the capture stops.
    pub dropped: Arc<AtomicU64>,
    /// Largest capture file in bytes (headers included); `u64::MAX` =
    /// no cap. See [`Capture::set_max_bytes`].
    max_bytes: Arc<AtomicU64>,
    /// The cap was reached and the capture stopped recording.
    truncated: Arc<AtomicBool>,
}

/// Final counters of a capture, see [`Capture::finish`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureStats {
    pub path: PathBuf,
    pub packets: u64,
    pub bytes: u64,
    /// Frames the kernel dropped (receive queue full).
    pub dropped: u64,
    /// The capture reached its byte cap and stopped recording: the file
    /// holds only the start of the run.
    pub truncated: bool,
}

/// Receive buffer requested for every capture socket. The default
/// (`net.core.rmem_default`, ~200 KiB) holds only a few hundred
/// loopback frames, which a briefly descheduled reader overflows.
pub const CAPTURE_RCVBUF: i32 = 32 << 20;

impl Capture {
    /// Start a capture on `iface`, writing frames to `path`. The
    /// writer uses classic pcap format with microsecond timestamps,
    /// LINKTYPE_ETHERNET, and a 65535-byte snaplen.
    pub fn start(iface: &str, path: impl Into<PathBuf>) -> Result<Self> {
        Self::start_with_priority(iface, path, None)
    }

    /// Like [`Capture::start`], optionally promoting the reader thread
    /// to `SCHED_FIFO` at `rt_priority`. Runs that put replay workers on
    /// SCHED_FIFO pass [`crate::CAPTURE_RT_PRIORITY`] here so the reader
    /// (which only blocks in `poll`, never spins) outranks the workers
    /// and keeps draining the socket instead of dropping frames.
    pub fn start_with_priority(
        iface: &str,
        path: impl Into<PathBuf>,
        rt_priority: Option<i32>,
    ) -> Result<Self> {
        let sock = open_socket(iface, None)?;
        Self::spawn(
            path.into(),
            Inner {
                socks: vec![sock],
                filter: None,
                closed: false,
            },
            rt_priority,
        )
    }

    /// Start a capture that records only what `filter` (see
    /// [`crate::bpf`]) accepts, initially on no interface: add them with
    /// [`Capture::add_iface`] and narrow or widen the filter with
    /// [`Capture::set_filter`]. Every socket gets the filter before it
    /// is bound, so not one frame outside the filter is ever read.
    /// `rt_priority` as for [`Capture::start_with_priority`].
    pub fn start_filtered(
        path: impl Into<PathBuf>,
        filter: Vec<bpf::Insn>,
        rt_priority: Option<i32>,
    ) -> Result<Self> {
        Self::spawn(
            path.into(),
            Inner {
                socks: Vec::new(),
                filter: Some(filter),
                closed: false,
            },
            rt_priority,
        )
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Cap the capture file at `max` bytes (pcap headers included;
    /// `None` = no cap). A frame that would cross the cap is not
    /// written: the capture stops recording, closes its sockets and
    /// reports [`CaptureStats::truncated`] (F055/F072).
    pub fn set_max_bytes(&self, max: Option<u64>) {
        self.max_bytes
            .store(max.unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Whether the byte cap stopped the capture.
    pub fn truncated(&self) -> bool {
        self.truncated.load(Ordering::Relaxed)
    }

    /// Also capture on `iface` (an Ethernet or loopback interface).
    /// Returns `false` if it is already captured.
    pub fn add_iface(&self, iface: &str) -> Result<bool> {
        let mut inner = self.lock();
        if inner.closed || inner.socks.iter().any(|s| s.iface == iface) {
            return Ok(false);
        }
        let sock = open_socket(iface, inner.filter.as_deref())?;
        info!(iface, path = %self.path.display(), "capture: added interface");
        inner.socks.push(sock);
        Ok(true)
    }

    /// Also capture on `iface`, through its own kernel `filter`, on a
    /// capture started unfiltered (an unfiltered capture has no
    /// capture-wide filter that could replace it). The run capture uses
    /// this for the enslaved NIC: incoming frames to the run's MACs
    /// only ([`bpf::incoming_to_macs_filter`]). Returns `false` if
    /// `iface` is already captured.
    pub fn add_iface_with_filter(&self, iface: &str, filter: &[bpf::Insn]) -> Result<bool> {
        let mut inner = self.lock();
        if inner.filter.is_some() {
            bail!("add_iface_with_filter on a filtered capture; use add_iface");
        }
        if inner.closed || inner.socks.iter().any(|s| s.iface == iface) {
            return Ok(false);
        }
        let sock = open_socket(iface, Some(filter))?;
        info!(iface, path = %self.path.display(), "capture: added filtered interface");
        inner.socks.push(sock);
        Ok(true)
    }

    /// Replace the kernel filter on every socket of a filtered capture
    /// (atomically per socket). A socket that rejects the new filter
    /// keeps its old one and is reported as an error.
    pub fn set_filter(&self, filter: Vec<bpf::Insn>) -> Result<()> {
        let mut inner = self.lock();
        if inner.filter.is_none() {
            bail!("set_filter on an unfiltered capture");
        }
        let mut first_err = None;
        for s in &inner.socks {
            if let Err(e) = attach_filter(s.fd.as_raw_fd(), &effective_filter(s.loopback, &filter))
            {
                warn!(iface = %s.iface, error = %format!("{e:#}"), "capture filter update failed");
                first_err.get_or_insert(e);
            }
        }
        inner.filter = Some(filter);
        first_err.map_or(Ok(()), Err)
    }

    /// Interfaces currently captured.
    pub fn ifaces(&self) -> Vec<String> {
        self.lock().socks.iter().map(|s| s.iface.clone()).collect()
    }

    fn spawn(path: PathBuf, inner: Inner, rt_priority: Option<i32>) -> Result<Self> {
        Self::spawn_with_burst(path, inner, rt_priority, BURST)
    }

    /// [`Capture::spawn`] reading at most `burst` frames per socket and
    /// wakeup (tests use a small one).
    fn spawn_with_burst(
        path: PathBuf,
        inner: Inner,
        rt_priority: Option<i32>,
        burst: usize,
    ) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let file = File::create(&path).with_context(|| format!("create capture file {path:?}"))?;
        let mut writer = BufWriter::with_capacity(64 * 1024, file);
        write_global_header(&mut writer)?;
        writer.flush().ok();

        let inner = Arc::new(Mutex::new(inner));
        let stop = Arc::new(AtomicBool::new(false));
        let packets = Arc::new(AtomicU64::new(0));
        let bytes = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let max_bytes = Arc::new(AtomicU64::new(u64::MAX));
        let truncated = Arc::new(AtomicBool::new(false));
        let stop_c = Arc::clone(&stop);
        let counters = Counters {
            packets: Arc::clone(&packets),
            bytes: Arc::clone(&bytes),
            dropped: Arc::clone(&dropped),
            max_bytes: Arc::clone(&max_bytes),
            truncated: Arc::clone(&truncated),
        };
        let inner_c = Arc::clone(&inner);
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();

        let span = tracing::Span::current();
        let thread = thread::Builder::new()
            .name(format!("capture-{name}"))
            .spawn(move || {
                let _span = span.enter();
                if let Some(prio) = rt_priority {
                    crate::try_set_realtime(prio);
                }
                read_loop(&inner_c, &stop_c, &mut writer, &counters, burst);
                if let Err(e) = writer.flush() {
                    warn!(error = %e, "capture flush failed");
                }
                debug!("capture thread exiting");
            })
            .context("spawn capture thread")?;

        Ok(Self {
            stop,
            thread: Some(thread),
            inner,
            path,
            packets,
            bytes,
            dropped,
            max_bytes,
            truncated,
        })
    }

    /// Stop (draining what the sockets still hold), flush, and return
    /// the final counters.
    pub fn finish(mut self) -> CaptureStats {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
        CaptureStats {
            path: self.path.clone(),
            packets: self.packets.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            truncated: self.truncated.load(Ordering::Relaxed),
        }
    }

    /// Signal the capture thread to stop and wait for it to finish
    /// flushing the file.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

/// Frames read from one socket per wakeup before the next is served.
const BURST: usize = 256;
/// Frames drained in total when the capture stops (bounded, so a
/// socket that keeps receiving cannot hold the stop up).
const DRAIN_MAX: usize = 1 << 16;

/// Counters shared with the handle.
struct Counters {
    packets: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    max_bytes: Arc<AtomicU64>,
    truncated: Arc<AtomicBool>,
}

/// Size of the classic pcap global header and of a record header.
const PCAP_GLOBAL_HEADER: u64 = 24;
const PCAP_RECORD_HEADER: u64 = 16;

/// How often the kernel's per-socket drop counters are collected.
const STATS_EVERY: Duration = Duration::from_secs(1);

/// Add the kernel drop counts of `fds` (reset by reading) to `dropped`.
fn collect_drops(socks: &[SockView], dropped: &AtomicU64) {
    for SockView { fd, iface, .. } in socks {
        let mut st: libc::tpacket_stats = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::tpacket_stats>() as libc::socklen_t;
        // SAFETY: `st` is a valid tpacket_stats of `len` bytes.
        let rc = unsafe {
            libc::getsockopt(
                *fd,
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                &mut st as *mut libc::tpacket_stats as *mut libc::c_void,
                &mut len,
            )
        };
        if rc == 0 && st.tp_drops > 0 {
            warn!(iface = %iface, drops = st.tp_drops, "capture: kernel dropped frames");
            dropped.fetch_add(u64::from(st.tp_drops), Ordering::Relaxed);
        }
    }
}

/// How long a frame is held back so that a frame with an earlier kernel
/// timestamp, still on its way through another socket of the capture,
/// can be written before it (T17c). The capture reads several sockets
/// (the ports' ingress mirror and the enslaved NIC) in turns; written
/// in arrival order, a reply could land in the file before its request
/// (a SYN-ACK before its SYN), and pcapload would split the flow.
///
/// It also covers a receive ring's block timeout: a frame can wait in
/// the block the kernel is filling for [`RING_BLOCK_TIMEOUT_MS`]
/// (rounded up to the timer tick, 10 ms at HZ=100) before the reader
/// sees it.
const REORDER_HOLD_US: u64 = 20_000;
/// Upper bounds on what the reorder buffer holds. Beyond them the
/// oldest frames are written even if a socket might still hold an
/// earlier one (a reader that cannot keep up must not grow without
/// bound).
const REORDER_MAX_FRAMES: usize = 1 << 17;
const REORDER_MAX_BYTES: usize = 64 << 20;
/// A frame is never held longer than this in wall time, whatever its
/// timestamp says (a clock step must not hold the capture back).
const REORDER_MAX_WAIT: Duration = Duration::from_millis(500);
/// Spare frame buffers kept for reuse.
const REORDER_POOL: usize = 4096;

/// One frame waiting in the reorder buffer.
struct Held {
    /// Kernel receive time in microseconds since the epoch.
    ts_us: u64,
    /// Read order, to keep frames with equal timestamps in arrival order.
    seq: u64,
    held_at: Instant,
    data: Vec<u8>,
}

impl PartialEq for Held {
    fn eq(&self, o: &Self) -> bool {
        (self.ts_us, self.seq) == (o.ts_us, o.seq)
    }
}
impl Eq for Held {}
impl PartialOrd for Held {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Held {
    /// Reversed, so the max-heap pops the earliest frame first.
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (o.ts_us, o.seq).cmp(&(self.ts_us, self.seq))
    }
}

/// k-way merge of the capture's sockets by kernel timestamp: frames are
/// held until no socket can still deliver an earlier one (the
/// watermark, see [`read_loop`]), then written earliest first.
#[derive(Default)]
struct Reorder {
    heap: std::collections::BinaryHeap<Held>,
    bytes: usize,
    seq: u64,
    pool: Vec<Vec<u8>>,
}

impl Reorder {
    fn push(&mut self, ts_us: u64, frame: &[u8], now: Instant) {
        let mut data = self.pool.pop().unwrap_or_default();
        data.clear();
        data.extend_from_slice(frame);
        self.bytes += data.len();
        self.seq += 1;
        self.heap.push(Held {
            ts_us,
            seq: self.seq,
            held_at: now,
            data,
        });
    }

    fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// The earliest frame if it may be written: its timestamp is at or
    /// below `watermark_us` (`None` = flush everything), or a bound is
    /// exceeded.
    fn pop_ready(&mut self, watermark_us: Option<u64>, now: Instant) -> Option<Held> {
        let top = self.heap.peek()?;
        let ready = watermark_us.is_none_or(|w| top.ts_us <= w)
            || self.heap.len() > REORDER_MAX_FRAMES
            || self.bytes > REORDER_MAX_BYTES
            || now.duration_since(top.held_at) >= REORDER_MAX_WAIT;
        if !ready {
            return None;
        }
        let h = self.heap.pop()?;
        self.bytes -= h.data.len();
        Some(h)
    }

    /// Give a written frame's buffer back for reuse.
    fn recycle(&mut self, data: Vec<u8>) {
        if self.pool.len() < REORDER_POOL {
            self.pool.push(data);
        }
    }
}

/// Wall-clock time in microseconds since the epoch, the clock
/// `SO_TIMESTAMP` uses.
fn realtime_us() -> u64 {
    let mut tv: libc::timeval = unsafe { mem::zeroed() };
    // SAFETY: plain gettimeofday into a local.
    unsafe {
        libc::gettimeofday(&mut tv, std::ptr::null_mut());
    }
    tv_us(&tv)
}

fn tv_us(tv: &libc::timeval) -> u64 {
    (tv.tv_sec.max(0) as u64) * 1_000_000 + tv.tv_usec.max(0) as u64
}

/// Outcome of reading one socket.
enum SockRead {
    /// Read frames; the socket may hold more (the burst ran out).
    /// Carries the latest timestamp read.
    More(usize, Option<u64>),
    /// Read `n` frames and the socket is empty.
    Empty(usize),
    /// The socket failed; drop it.
    Dead,
}

/// Read up to `burst` frames from `fd` into `out`, stamping each with
/// its kernel receive time (`SO_TIMESTAMP`; the read time if the kernel
/// gave none).
fn read_socket(
    fd: RawFd,
    loopback: bool,
    iface: &str,
    burst: usize,
    buf: &mut [u8],
    out: &mut Reorder,
) -> SockRead {
    // u64 storage keeps the control buffer aligned for cmsghdr.
    let mut cbuf = [0u64; 16];
    let mut n_read = 0usize;
    let mut last_ts = None;
    let now = Instant::now();
    for _ in 0..burst {
        let mut from: libc::sockaddr_ll = unsafe { mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = &mut from as *mut libc::sockaddr_ll as *mut libc::c_void;
        msg.msg_namelen = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = mem::size_of_val(&cbuf) as _;
        // SAFETY: `msg` points at live, correctly sized buffers.
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
        if n < 0 {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => SockRead::Empty(n_read),
                _ => {
                    warn!(iface, error = %err, "capture recv failed; dropping interface");
                    SockRead::Dead
                }
            };
        }
        if n == 0 {
            return SockRead::Empty(n_read);
        }
        n_read += 1;
        // The kernel filter already drops these on lo; this also
        // covers an unfiltered or older socket.
        if loopback && from.sll_pkttype == libc::PACKET_OUTGOING {
            continue;
        }
        let ts = cmsg_timestamp(&msg).map_or_else(realtime_us, |tv| tv_us(&tv));
        last_ts = Some(last_ts.map_or(ts, |l: u64| l.max(ts)));
        out.push(ts, &buf[..n as usize], now);
    }
    SockRead::More(n_read, last_ts)
}

/// The kernel's `TPACKET_ALIGN(x)`: `x` rounded up to
/// `TPACKET_ALIGNMENT` (16).
const fn tpacket_align(x: usize) -> usize {
    (x + libc::TPACKET_ALIGNMENT - 1) & !(libc::TPACKET_ALIGNMENT - 1)
}

/// Offset of the `sockaddr_ll` after a frame's `tpacket3_hdr`
/// (`TPACKET_ALIGN(sizeof(struct tpacket3_hdr))`). Not
/// `TPACKET3_HDRLEN`, which is the end of that `sockaddr_ll`.
const RING_SLL_OFF: usize = tpacket_align(mem::size_of::<libc::tpacket3_hdr>());
/// Where a frame's link-layer data may start at the earliest.
const RING_DATA_MIN: usize = RING_SLL_OFF + mem::size_of::<libc::sockaddr_ll>();

/// Outcome of parsing one ring block.
#[derive(Debug, Default, PartialEq, Eq)]
struct BlockParse {
    /// Frames walked (including skipped loopback copies).
    frames: usize,
    /// Frame headers that were out of bounds or inconsistent: skipped
    /// without reading their data. A bad chain stops the walk.
    malformed: usize,
    /// Latest timestamp handed to the sink, in microseconds.
    last_ts: Option<u64>,
}

/// Walk the frames of one TPACKET_V3 block (`block` = the whole block,
/// descriptor included) and hand each frame's kernel time (µs) and
/// link-layer bytes to `sink`, skipping the outgoing copies on
/// loopback. Every header field is bounds-checked against the block
/// before anything it points at is read; a frame that fails a check is
/// counted as malformed and not read, and a chain that would leave the
/// block or not advance stops the walk.
fn parse_block(block: &[u8], loopback: bool, mut sink: impl FnMut(u64, &[u8])) -> BlockParse {
    let mut res = BlockParse::default();
    let u32_at = |o: usize| -> Option<u32> {
        block
            .get(o..o + 4)
            .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
    };
    // tpacket_block_desc: version, offset_to_priv, then
    // tpacket_hdr_v1 at 8: block_status, num_pkts, offset_to_first_pkt.
    let (Some(num_pkts), Some(first)) = (u32_at(12), u32_at(16)) else {
        res.malformed += 1;
        return res;
    };
    let hdr_len = mem::size_of::<libc::tpacket3_hdr>();
    // No more frames than could fit at the smallest possible stride.
    let max_frames = block.len() / tpacket_align(RING_DATA_MIN);
    let mut off = first as usize;
    for i in 0..(num_pkts as usize).min(max_frames.max(1)) {
        if off < mem::size_of::<libc::tpacket_block_desc>()
            || off
                .checked_add(RING_DATA_MIN)
                .is_none_or(|e| e > block.len())
        {
            res.malformed += num_pkts as usize - i;
            return res;
        }
        // SAFETY: `off + hdr_len <= off + RING_DATA_MIN <= block.len()`.
        let h = unsafe { (block.as_ptr().add(off) as *const libc::tpacket3_hdr).read_unaligned() };
        let start = off + h.tp_mac as usize;
        let len = h.tp_snaplen as usize;
        let data_ok = (h.tp_mac as usize) >= RING_DATA_MIN
            && start.checked_add(len).is_some_and(|e| e <= block.len());
        if data_ok {
            res.frames += 1;
            // SAFETY: `off + RING_SLL_OFF + sizeof(sockaddr_ll) <= block.len()`.
            let sll = unsafe {
                (block.as_ptr().add(off + RING_SLL_OFF) as *const libc::sockaddr_ll)
                    .read_unaligned()
            };
            if !(loopback && sll.sll_pkttype == libc::PACKET_OUTGOING) {
                let ts = u64::from(h.tp_sec) * 1_000_000 + u64::from(h.tp_nsec) / 1000;
                res.last_ts = Some(res.last_ts.map_or(ts, |l| l.max(ts)));
                sink(ts, &block[start..start + len]);
            }
        } else {
            res.malformed += 1;
        }
        if i + 1 == num_pkts as usize {
            break;
        }
        let next = h.tp_next_offset as usize;
        if next < hdr_len || off.checked_add(next).is_none_or(|o| o >= block.len()) {
            // The chain does not advance or leaves the block.
            res.malformed += num_pkts as usize - i - 1;
            return res;
        }
        off += next;
    }
    res
}

/// Read whole blocks of a TPACKET_V3 ring into `out`, starting at
/// block `*next`, until a block is still the kernel's or at least
/// `burst` frames were read. Each frame keeps its kernel receive time
/// (nanoseconds in the ring, written with microseconds). Malformed
/// frame headers are counted in `malformed` and skipped.
fn read_ring(
    base: usize,
    loopback: bool,
    burst: usize,
    next: &mut usize,
    out: &mut Reorder,
    malformed: &mut u64,
) -> SockRead {
    use std::sync::atomic::{fence, AtomicU32};
    let now = Instant::now();
    let mut n_read = 0usize;
    let mut last_ts: Option<u64> = None;
    loop {
        if n_read >= burst {
            return SockRead::More(n_read, last_ts);
        }
        let block = (base + *next * RING_BLOCK_SIZE as usize) as *mut u8;
        let desc = block as *mut libc::tpacket_block_desc;
        // SAFETY: the block lies inside the mapping (next < RING_BLOCKS);
        // block_status is the u32 the kernel hands over with release
        // semantics, read here with acquire.
        let status_ptr = unsafe { std::ptr::addr_of_mut!((*desc).hdr.bh1.block_status) };
        let status = unsafe { (*(status_ptr as *const AtomicU32)).load(Ordering::Acquire) };
        if status & libc::TP_STATUS_USER == 0 {
            return SockRead::Empty(n_read);
        }
        // SAFETY: a user-owned block is ours to read until handed back;
        // it is RING_BLOCK_SIZE bytes inside the mapping.
        let bytes =
            unsafe { std::slice::from_raw_parts(block as *const u8, RING_BLOCK_SIZE as usize) };
        let r = parse_block(bytes, loopback, |ts, frame| out.push(ts, frame, now));
        n_read += r.frames;
        if let Some(t) = r.last_ts {
            last_ts = Some(last_ts.map_or(t, |l| l.max(t)));
        }
        *malformed += r.malformed as u64;
        // Hand the block back to the kernel.
        fence(Ordering::Release);
        // SAFETY: as for the load above.
        unsafe {
            (*(status_ptr as *const AtomicU32)).store(libc::TP_STATUS_KERNEL, Ordering::Release)
        };
        *next = (*next + 1) % RING_BLOCKS as usize;
    }
}

/// The pending error of a socket (cleared by reading it).
fn sock_error(fd: RawFd) -> io::Error {
    let mut err: libc::c_int = 0;
    let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `err` is a valid c_int of `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut err as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        io::Error::last_os_error()
    } else {
        io::Error::from_raw_os_error(err)
    }
}

/// The `SCM_TIMESTAMP` of a received message, if present.
fn cmsg_timestamp(msg: &libc::msghdr) -> Option<libc::timeval> {
    // SAFETY: `msg` was filled by recvmsg; the CMSG_* walk stays
    // within `msg_control`/`msg_controllen`.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_TIMESTAMP {
                return Some(std::ptr::read_unaligned(
                    libc::CMSG_DATA(c) as *const libc::timeval
                ));
            }
            c = libc::CMSG_NXTHDR(msg, c);
        }
    }
    None
}

fn read_loop(
    inner: &Mutex<Inner>,
    stop: &AtomicBool,
    writer: &mut impl Write,
    c: &Counters,
    burst: usize,
) {
    let mut buf = vec![0u8; 65536];
    let mut held = Reorder::default();
    // Next block to read per ring (keyed by its mapping address).
    let mut ring_next: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    // Ring frame headers that failed their bounds checks (skipped).
    let mut malformed = 0u64;
    let mut malformed_warned = 0u64;
    let mut last_stats = Instant::now();
    let mut drained = 0usize;
    loop {
        // Once stopping, drain what is queued, collect the drop counts
        // and exit.
        let stopping = stop.load(Ordering::Relaxed);
        let socks: Vec<SockView> = inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .socks
            .iter()
            .map(|s| SockView {
                fd: s.fd.as_raw_fd(),
                loopback: s.loopback,
                iface: s.iface.clone(),
                ring: s.ring.as_ref().map(|r| r.base as usize),
            })
            .collect();
        let mut pfds: Vec<libc::pollfd> = socks
            .iter()
            .map(|v| libc::pollfd {
                fd: v.fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: `pfds` is a valid array of `pfds.len()` pollfds; with
        // no sockets yet this just sleeps for the timeout. Held frames
        // are written within about a hold time even when nothing new
        // arrives.
        let timeout = if stopping {
            0
        } else if held.is_empty() {
            200
        } else {
            (REORDER_HOLD_US / 1000).max(1) as libc::c_int
        };
        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, timeout) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            warn!(error = %err, "capture poll failed");
            return;
        }
        // Every socket was empty or readable at this instant: a frame
        // a socket delivers later was stamped after it (less a small
        // in-flight delay the hold covers).
        let polled_us = realtime_us();
        let mut watermark = polled_us.saturating_sub(REORDER_HOLD_US);
        let mut dead: Vec<RawFd> = Vec::new();
        let mut more = false;
        for (p, v) in pfds.iter().zip(&socks) {
            if p.revents == 0 {
                continue;
            }
            let got = match v.ring {
                Some(base) => {
                    let next = ring_next.entry(base).or_insert(0);
                    let r = read_ring(base, v.loopback, burst, next, &mut held, &mut malformed);
                    if p.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                        // The recvmsg path sees this as a failed read
                        // (e.g. the interface went away): drop the
                        // socket after taking what its ring holds.
                        warn!(iface = %v.iface, error = %sock_error(v.fd),
                            "capture socket failed; dropping interface");
                        ring_next.remove(&base);
                        SockRead::Dead
                    } else {
                        r
                    }
                }
                None => read_socket(v.fd, v.loopback, &v.iface, burst, &mut buf, &mut held),
            };
            match got {
                SockRead::More(n, last) => {
                    more = true;
                    drained += n;
                    // Frames still queued on this socket are no earlier
                    // than the last one read from it.
                    if let Some(t) = last {
                        watermark = watermark.min(t.saturating_sub(1));
                    }
                }
                SockRead::Empty(n) => drained += n,
                SockRead::Dead => dead.push(v.fd),
            }
        }
        // Write in kernel time order across sockets (T17c). When the
        // stop has drained every socket, everything goes.
        let finishing = stopping && !(more && drained < DRAIN_MAX);
        let mark = (!finishing).then_some(watermark);
        let now = Instant::now();
        while let Some(h) = held.pop_ready(mark, now) {
            let frame = &h.data;
            let file_bytes = PCAP_GLOBAL_HEADER
                + c.packets.load(Ordering::Relaxed) * PCAP_RECORD_HEADER
                + c.bytes.load(Ordering::Relaxed);
            let cap = c.max_bytes.load(Ordering::Relaxed);
            if file_bytes + PCAP_RECORD_HEADER + frame.len() as u64 > cap {
                warn!(
                    cap,
                    packets = c.packets.load(Ordering::Relaxed),
                    "capture reached its byte cap; recording stopped"
                );
                c.truncated.store(true, Ordering::Relaxed);
                collect_drops(&socks, &c.dropped);
                let mut inner = inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.closed = true;
                inner.socks.clear();
                return;
            }
            let (sec, us) = ((h.ts_us / 1_000_000) as u32, (h.ts_us % 1_000_000) as u32);
            if let Err(e) = write_record(writer, sec, us, frame) {
                warn!(error = %e, "capture write failed");
                return;
            }
            c.packets.fetch_add(1, Ordering::Relaxed);
            c.bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
            held.recycle(h.data);
        }
        if stopping || last_stats.elapsed() >= STATS_EVERY {
            if malformed > malformed_warned {
                warn!(
                    malformed,
                    "capture: skipped ring frames with inconsistent headers"
                );
                malformed_warned = malformed;
            }
            collect_drops(&socks, &c.dropped);
            last_stats = Instant::now();
        }
        if !dead.is_empty() {
            inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .socks
                .retain(|s| !dead.contains(&s.fd.as_raw_fd()));
        }
        if stopping {
            // Keep draining while a socket still holds frames, bounded
            // so a socket that keeps receiving cannot hold the stop up.
            if !finishing {
                continue;
            }
            return;
        }
        drained = 0;
    }
}

/// The filter a socket actually carries: on loopback, outgoing copies
/// are dropped in the kernel first.
fn effective_filter(loopback: bool, filter: &[bpf::Insn]) -> Vec<bpf::Insn> {
    if loopback {
        bpf::skip_outgoing(filter)
    } else {
        filter.to_vec()
    }
}

/// Ask for [`CAPTURE_RCVBUF`] bytes of receive buffer: SO_RCVBUFFORCE
/// (needs CAP_NET_ADMIN) and else SO_RCVBUF, which the kernel caps at
/// `net.core.rmem_max`. Best effort.
fn grow_rcvbuf(fd: RawFd, iface: &str) {
    let size: libc::c_int = CAPTURE_RCVBUF;
    for opt in [libc::SO_RCVBUFFORCE, libc::SO_RCVBUF] {
        // SAFETY: `size` is a valid c_int.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &size as *const libc::c_int as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            return;
        }
    }
    debug!(iface, "capture: could not grow the receive buffer");
}

/// Ask for each frame's kernel receive time (`SO_TIMESTAMP`), so
/// frames read from several sockets can be written in the order they
/// were seen and the pcap's gaps reflect the wire, not the reader's
/// wakeups. Best effort: without it the read time is used.
fn enable_timestamps(fd: RawFd, iface: &str) {
    let on: libc::c_int = 1;
    // SAFETY: `on` is a valid c_int.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMP,
            &on as *const libc::c_int as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        debug!(iface, "capture: no kernel timestamps");
    }
}

/// Link types a capture can record as LINKTYPE_ETHERNET.
const ARPHRD_ETHER: u32 = 1;
const ARPHRD_LOOPBACK: u32 = 772;

fn validate_ifname(iface: &str) -> Result<()> {
    if iface.is_empty()
        || iface.len() > 15
        || iface == "."
        || iface == ".."
        || iface
            .bytes()
            .any(|b| b == b'/' || b.is_ascii_whitespace() || b == 0)
    {
        bail!("invalid interface name {iface:?}");
    }
    Ok(())
}

/// The interface's ARPHRD type, from sysfs.
fn link_type(iface: &str) -> Result<u32> {
    let p = Path::new("/sys/class/net").join(iface).join("type");
    let t = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
    t.trim()
        .parse()
        .with_context(|| format!("parse {}", p.display()))
}

fn attach_filter(fd: RawFd, filter: &[bpf::Insn]) -> Result<()> {
    let prog = libc::sock_fprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_ptr() as *mut bpf::Insn,
    };
    // SAFETY: `prog` points at `filter`, which outlives the call; the
    // kernel copies the program.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog as *const libc::sock_fprog as *const libc::c_void,
            mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("attach capture filter");
    }
    Ok(())
}

/// An AF_PACKET socket on `iface`. It is created with protocol 0 (it
/// receives nothing), gets `filter` attached, and only then is bound
/// with ETH_P_ALL, so no frame outside the filter is ever queued.
fn open_socket(iface: &str, filter: Option<&[bpf::Insn]>) -> Result<CapSock> {
    validate_ifname(iface)?;
    let ltype = link_type(iface)?;
    if ltype != ARPHRD_ETHER && ltype != ARPHRD_LOOPBACK {
        bail!("cannot capture on {iface}: link type {ltype} is neither Ethernet nor loopback");
    }
    let ifindex = if_nametoindex(iface)?;
    // SAFETY: plain socket(2).
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("socket(AF_PACKET, SOCK_RAW)");
    }
    // SAFETY: `fd` is a fresh descriptor we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let loopback = ltype == ARPHRD_LOOPBACK;
    grow_rcvbuf(fd.as_raw_fd(), iface);
    enable_timestamps(fd.as_raw_fd(), iface);
    match (filter, loopback) {
        (Some(f), _) => attach_filter(fd.as_raw_fd(), &effective_filter(loopback, f))?,
        (None, true) => attach_filter(fd.as_raw_fd(), &bpf::skip_outgoing(&bpf::accept_all()))?,
        (None, false) => {}
    }
    let ring = match setup_ring(fd.as_raw_fd()) {
        Ok(r) => Some(r),
        Err(e) => {
            debug!(iface, error = %format!("{e:#}"), "capture: no receive ring; reading frame by frame");
            None
        }
    };
    let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = ifindex;
    // SAFETY: `addr` is a valid sockaddr_ll.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("bind capture socket to {iface}"));
    }
    Ok(CapSock {
        fd,
        iface: iface.to_string(),
        loopback,
        ring,
    })
}

fn if_nametoindex(iface: &str) -> Result<i32> {
    let c = CString::new(iface).context("iface name contains nul byte")?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(anyhow!(io::Error::last_os_error()).context(format!("if_nametoindex({iface})")));
    }
    Ok(idx as i32)
}

fn write_global_header<W: Write>(w: &mut W) -> io::Result<()> {
    // Classic pcap, little-endian microsecond magic.
    w.write_all(&[0xd4, 0xc3, 0xb2, 0xa1])?;
    w.write_all(&2u16.to_le_bytes())?; // version major
    w.write_all(&4u16.to_le_bytes())?; // version minor
    w.write_all(&0u32.to_le_bytes())?; // thiszone
    w.write_all(&0u32.to_le_bytes())?; // sigfigs
    w.write_all(&65535u32.to_le_bytes())?; // snaplen
    w.write_all(&1u32.to_le_bytes())?; // network = LINKTYPE_ETHERNET
    Ok(())
}

fn write_record<W: Write>(w: &mut W, ts_sec: u32, ts_us: u32, frame: &[u8]) -> io::Result<()> {
    w.write_all(&ts_sec.to_le_bytes())?;
    w.write_all(&ts_us.to_le_bytes())?;
    w.write_all(&(frame.len() as u32).to_le_bytes())?;
    w.write_all(&(frame.len() as u32).to_le_bytes())?;
    w.write_all(frame)?;
    Ok(())
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

/// Attempt to delete `path` if it exists.
pub fn delete_capture(path: &Path) {
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A datagram socketpair stands in for an AF_PACKET socket: the
    /// reader only polls and receives, and SO_TIMESTAMP works on it.
    fn pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `fds` has room for the two descriptors.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        // SAFETY: both are fresh descriptors we own.
        let (a, b) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        grow_rcvbuf(a.as_raw_fd(), "test");
        enable_timestamps(a.as_raw_fd(), "test");
        (a, b)
    }

    fn send(fd: &OwnedFd, frame: &[u8]) {
        // SAFETY: `frame` is valid for its length.
        let n = unsafe {
            libc::send(
                fd.as_raw_fd(),
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
            )
        };
        assert_eq!(n, frame.len() as isize, "{}", io::Error::last_os_error());
    }

    fn capture_on(path: &Path, socks: Vec<OwnedFd>) -> Capture {
        capture_with_burst(path, socks, BURST)
    }

    fn capture_with_burst(path: &Path, socks: Vec<OwnedFd>, burst: usize) -> Capture {
        let socks = socks
            .into_iter()
            .enumerate()
            .map(|(i, fd)| CapSock {
                fd,
                iface: format!("test{i}"),
                loopback: false,
                ring: None,
            })
            .collect();
        Capture::spawn_with_burst(
            path.to_path_buf(),
            Inner {
                socks,
                filter: None,
                closed: false,
            },
            None,
            burst,
        )
        .unwrap()
    }

    /// F055/F072: at the byte cap the capture stops recording, the file
    /// stays within the cap and holds whole records only, and the stats
    /// say it was truncated; no interface can be added afterwards.
    #[test]
    fn byte_cap_stops_the_capture() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capped.pcap");
        let (rx, tx) = pair();
        let cap = capture_on(&path, vec![rx]);
        // Room for exactly 10 records of 60-byte frames.
        let max = 24 + 10 * (16 + 60);
        cap.set_max_bytes(Some(max));
        for i in 0..25 {
            send(&tx, &frame(i));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cap.truncated() {
            assert!(Instant::now() < deadline, "cap never reached");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !cap.add_iface("lo").unwrap(),
            "closed capture took an iface"
        );
        let st = cap.finish();
        assert!(st.truncated);
        assert_eq!(st.packets, 10);
        assert_eq!(records(&path).len(), 10);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), max);

        // No cap: nothing is truncated.
        let path = dir.path().join("free.pcap");
        let (rx, tx) = pair();
        let cap = capture_on(&path, vec![rx]);
        cap.set_max_bytes(None);
        for i in 0..25 {
            send(&tx, &frame(i));
        }
        let st = cap.finish();
        assert!(!st.truncated);
        assert_eq!(st.packets, 25);
    }

    /// The records of a classic pcap: (sec, usec, frame).
    fn records(path: &Path) -> Vec<(u32, u32, Vec<u8>)> {
        let b = std::fs::read(path).unwrap();
        let mut out = Vec::new();
        let mut off = 24;
        while off + 16 <= b.len() {
            let u = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
            let incl = u(off + 8) as usize;
            out.push((u(off), u(off + 4), b[off + 16..off + 16 + incl].to_vec()));
            off += 16 + incl;
        }
        assert_eq!(off, b.len(), "trailing bytes in {}", path.display());
        out
    }

    fn frame(tag: u16) -> Vec<u8> {
        let mut f = vec![0u8; 60];
        f[..2].copy_from_slice(&tag.to_be_bytes());
        f
    }

    /// B2: the counters `finish` returns are read after the reader has
    /// stopped and drained, so they match the file exactly, even for
    /// frames that were still queued when the stop was requested.
    #[test]
    fn finish_counts_every_frame_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        for round in 0..20u16 {
            let path = dir.path().join(format!("c{round}.pcap"));
            let (rx, tx) = pair();
            let cap = capture_on(&path, vec![rx]);
            let n = 300 + round * 37;
            for i in 0..n {
                send(&tx, &frame(i));
            }
            // Stop right away: most frames are still in the queue.
            let st = cap.finish();
            let recs = records(&path);
            assert_eq!(st.packets, recs.len() as u64, "round {round}");
            assert_eq!(st.packets, u64::from(n), "round {round}: drained on stop");
            assert_eq!(
                st.bytes,
                recs.iter().map(|r| r.2.len() as u64).sum::<u64>(),
                "round {round}"
            );
            assert_eq!(st.dropped, 0);
        }
    }

    /// T17c: when one socket holds more than a read burst of older
    /// frames and another has newer ones, the newer frames wait until
    /// the older socket is drained: the file is in timestamp order
    /// across wakeups, not only within one (a SYN-ACK read from the NIC
    /// used to land before its SYN still queued on the port mirror).
    #[test]
    fn frames_are_merged_by_timestamp_across_wakeups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("merge.pcap");
        let (rx_a, tx_a) = pair();
        let (rx_b, tx_b) = pair();
        // Several read bursts (a small burst keeps the queue within
        // what an AF_UNIX socket buffers before the reader starts).
        let burst = 8;
        let n_a = (burst * 4 + 3) as u16;
        for i in 0..n_a {
            send(&tx_a, &frame(i));
        }
        std::thread::sleep(Duration::from_millis(3));
        for i in 0..10 {
            send(&tx_b, &frame(10_000 + i));
        }
        // b is read first in each wakeup: the old code wrote b's ten
        // frames after a's first burst.
        let cap = capture_with_burst(&path, vec![rx_b, rx_a], burst);
        std::thread::sleep(Duration::from_millis(300));
        let st = cap.finish();
        assert_eq!(st.packets, u64::from(n_a) + 10);
        let recs = records(&path);
        let tags: Vec<u16> = recs
            .iter()
            .map(|r| u16::from_be_bytes([r.2[0], r.2[1]]))
            .collect();
        let want: Vec<u16> = (0..n_a).chain(10_000..10_010).collect();
        assert_eq!(tags, want);
        let ts: Vec<(u32, u32)> = recs.iter().map(|r| (r.0, r.1)).collect();
        assert!(ts.windows(2).all(|w| w[0] <= w[1]), "{ts:?}");
    }

    /// A synthetic TPACKET_V3 block: descriptor, then `frames` as
    /// (tp_next_offset or None for "computed", pkttype, payload).
    fn v3_block(frames: &[(Option<u32>, u8, &[u8])]) -> Vec<u8> {
        let mut b = vec![0u8; 4096];
        let first = tpacket_align(mem::size_of::<libc::tpacket_block_desc>());
        b[12..16].copy_from_slice(&(frames.len() as u32).to_ne_bytes());
        b[16..20].copy_from_slice(&(first as u32).to_ne_bytes());
        let mut off = first;
        for (i, (next, pkttype, data)) in frames.iter().enumerate() {
            let mac = tpacket_align(RING_DATA_MIN);
            let stride = tpacket_align(mac + data.len());
            let mut h: libc::tpacket3_hdr = unsafe { mem::zeroed() };
            h.tp_next_offset = if i + 1 == frames.len() {
                0
            } else {
                next.unwrap_or(stride as u32)
            };
            h.tp_sec = 1_700_000_000;
            h.tp_nsec = 1_000 * (i as u32 + 1);
            h.tp_snaplen = data.len() as u32;
            h.tp_len = data.len() as u32;
            h.tp_mac = mac as u16;
            // SAFETY: within `b` (4096 bytes, small frames).
            unsafe {
                (b.as_mut_ptr().add(off) as *mut libc::tpacket3_hdr).write_unaligned(h);
                let mut sll: libc::sockaddr_ll = mem::zeroed();
                sll.sll_pkttype = *pkttype;
                (b.as_mut_ptr().add(off + RING_SLL_OFF) as *mut libc::sockaddr_ll)
                    .write_unaligned(sll);
            }
            b[off + mac..off + mac + data.len()].copy_from_slice(data);
            off += stride;
        }
        b
    }

    /// The sockaddr_ll sits at TPACKET_ALIGN(sizeof(tpacket3_hdr)); the
    /// kernel's TPACKET3_HDRLEN is that plus sizeof(sockaddr_ll).
    #[test]
    fn ring_header_offsets_match_the_kernel() {
        assert_eq!(tpacket_align(0), 0);
        assert_eq!(tpacket_align(1), 16);
        assert_eq!(tpacket_align(16), 16);
        assert_eq!(tpacket_align(17), 32);
        assert_eq!(mem::size_of::<libc::tpacket3_hdr>(), 48);
        assert_eq!(RING_SLL_OFF, 48);
        assert_eq!(
            libc::TPACKET3_HDRLEN,
            RING_SLL_OFF + mem::size_of::<libc::sockaddr_ll>()
        );
        assert_eq!(RING_DATA_MIN, libc::TPACKET3_HDRLEN);
    }

    /// The block parser yields only the incoming frame on loopback, with
    /// its bytes and time; both frames when not loopback.
    #[test]
    fn ring_block_parser_skips_outgoing_loopback_copies() {
        let out_f: &[u8] = b"outgoing-copy-frame";
        let in_f: &[u8] = b"incoming-frame-bytes-1234";
        let b = v3_block(&[
            (None, libc::PACKET_OUTGOING, out_f),
            (None, libc::PACKET_HOST, in_f),
        ]);
        let mut got: Vec<(u64, Vec<u8>)> = Vec::new();
        let r = parse_block(&b, true, |ts, f| got.push((ts, f.to_vec())));
        assert_eq!(got, vec![(1_700_000_000_000_002, in_f.to_vec())]);
        assert_eq!((r.frames, r.malformed), (2, 0));
        assert_eq!(r.last_ts, Some(1_700_000_000_000_002));
        got.clear();
        parse_block(&b, false, |ts, f| got.push((ts, f.to_vec())));
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].1, out_f);
    }

    /// A corrupt chain stops safely: a tp_next_offset that does not
    /// advance, one that leaves the block, a huge num_pkts, data that
    /// runs past the block, and tp_mac pointing into the header.
    #[test]
    fn ring_block_parser_stops_on_corrupt_headers() {
        let f: &[u8] = b"frame";
        for bad_next in [0u32, 8, 1 << 30] {
            let b = v3_block(&[
                (Some(bad_next), libc::PACKET_HOST, f),
                (None, libc::PACKET_HOST, f),
            ]);
            let mut n = 0;
            let r = parse_block(&b, false, |_, d| {
                assert_eq!(d, f);
                n += 1;
            });
            assert_eq!(n, 1, "next {bad_next}");
            assert_eq!(r.malformed, 1, "next {bad_next}");
        }
        // num_pkts far beyond what fits: bounded, no panic.
        let mut b = v3_block(&[(None, libc::PACKET_HOST, f)]);
        b[12..16].copy_from_slice(&u32::MAX.to_ne_bytes());
        let r = parse_block(&b, false, |_, _| {});
        assert_eq!(r.frames, 1);
        // Snaplen past the end of the block: skipped, not read.
        let mut b = v3_block(&[(None, libc::PACKET_HOST, f)]);
        let first = tpacket_align(mem::size_of::<libc::tpacket_block_desc>());
        let snap = first + 12; // tp_snaplen
        b[snap..snap + 4].copy_from_slice(&100_000u32.to_ne_bytes());
        let r = parse_block(&b, false, |_, _| panic!("read past the block"));
        assert_eq!((r.frames, r.malformed), (0, 1));
        // tp_mac inside the header area.
        let mut b = v3_block(&[(None, libc::PACKET_HOST, f)]);
        let mac = first + 24; // tp_mac
        b[mac..mac + 2].copy_from_slice(&8u16.to_ne_bytes());
        let r = parse_block(&b, false, |_, _| panic!("read the header as data"));
        assert_eq!(r.malformed, 1);
        // First frame offset past the block, or a truncated block.
        let mut b = v3_block(&[(None, libc::PACKET_HOST, f)]);
        b[16..20].copy_from_slice(&5000u32.to_ne_bytes());
        assert_eq!(parse_block(&b, false, |_, _| panic!()).malformed, 1);
        assert_eq!(parse_block(&b[..10], false, |_, _| panic!()).malformed, 1);
    }

    /// T17c: the reorder buffer releases frames up to the watermark,
    /// earliest first (equal timestamps in read order), everything on
    /// a final flush, and the oldest frames when a bound is hit.
    #[test]
    fn reorder_buffer_releases_by_watermark_and_bounds() {
        let now = Instant::now();
        let mut r = Reorder::default();
        for (ts, tag) in [(50u64, 1u8), (10, 2), (30, 3), (10, 4), (70, 5)] {
            r.push(ts, &[tag], now);
        }
        let mut out = Vec::new();
        while let Some(h) = r.pop_ready(Some(30), now) {
            out.push(h.data[0]);
            r.recycle(h.data);
        }
        assert_eq!(out, [2, 4, 3], "up to the watermark, earliest first");
        assert!(r.pop_ready(Some(49), now).is_none());
        out.clear();
        while let Some(h) = r.pop_ready(None, now) {
            out.push(h.data[0]);
        }
        assert_eq!(out, [1, 5], "a final flush releases everything");
        assert!(r.is_empty() && r.bytes == 0);

        // A frame held too long goes whatever the watermark says.
        r.push(1_000, &[9], now);
        assert!(r.pop_ready(Some(0), now).is_none());
        let late = now + REORDER_MAX_WAIT;
        assert_eq!(r.pop_ready(Some(0), late).unwrap().data, [9]);

        // Past the frame bound the oldest goes first.
        for i in 0..=REORDER_MAX_FRAMES as u64 {
            r.push(1_000 + i, &[0], now);
        }
        assert_eq!(r.pop_ready(Some(0), now).unwrap().ts_us, 1_000);
        assert!(r.pop_ready(Some(0), now).is_none());
    }

    /// Frames read from several sockets in one wakeup are written in
    /// kernel-timestamp order, not in socket order.
    #[test]
    fn frames_from_several_sockets_are_written_in_time_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("order.pcap");
        let (rx_a, tx_a) = pair();
        let (rx_b, tx_b) = pair();
        // Queue before the reader starts, so one wakeup sees both
        // sockets: b's frames are older than a's, a is read first.
        for i in 0..5 {
            send(&tx_b, &frame(100 + i));
            std::thread::sleep(Duration::from_millis(2));
        }
        for i in 0..5 {
            send(&tx_a, &frame(i));
            std::thread::sleep(Duration::from_millis(2));
        }
        let cap = capture_on(&path, vec![rx_a, rx_b]);
        std::thread::sleep(Duration::from_millis(300));
        let st = cap.finish();
        assert_eq!(st.packets, 10);
        let recs = records(&path);
        let tags: Vec<u16> = recs
            .iter()
            .map(|r| u16::from_be_bytes([r.2[0], r.2[1]]))
            .collect();
        assert_eq!(tags, [100, 101, 102, 103, 104, 0, 1, 2, 3, 4]);
        let ts: Vec<(u32, u32)> = recs.iter().map(|r| (r.0, r.1)).collect();
        assert!(ts.windows(2).all(|w| w[0] <= w[1]), "{ts:?}");
        // Kernel receive times: the 2 ms spacing survives.
        let us = |t: (u32, u32)| u64::from(t.0) * 1_000_000 + u64::from(t.1);
        assert!(us(ts[9]) - us(ts[0]) >= 15_000, "{ts:?}");
    }
}
