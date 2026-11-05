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
                read_loop(&inner_c, &stop_c, &mut writer, &counters);
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
fn collect_drops(fds: &[(RawFd, bool, String)], dropped: &AtomicU64) {
    for (fd, _, iface) in fds {
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
            warn!(iface, drops = st.tp_drops, "capture: kernel dropped frames");
            dropped.fetch_add(u64::from(st.tp_drops), Ordering::Relaxed);
        }
    }
}

/// One frame read in a wakeup, waiting to be written in time order.
struct Pending {
    ts_sec: u32,
    ts_us: u32,
    /// Range of the frame in the batch arena.
    start: usize,
    len: usize,
}

/// Outcome of reading one socket.
enum SockRead {
    /// Read `n` frames; the socket may hold more (the burst ran out).
    More(usize),
    /// Read `n` frames and the socket is empty.
    Empty(usize),
    /// The socket failed; drop it.
    Dead,
}

/// Read up to `burst` frames from `fd` into `arena`/`batch`, stamping
/// each with its kernel receive time (`SO_TIMESTAMP`; the read time if
/// the kernel gave none).
fn read_socket(
    fd: RawFd,
    loopback: bool,
    iface: &str,
    burst: usize,
    buf: &mut [u8],
    arena: &mut Vec<u8>,
    batch: &mut Vec<Pending>,
) -> SockRead {
    // u64 storage keeps the control buffer aligned for cmsghdr.
    let mut cbuf = [0u64; 16];
    let mut n_read = 0usize;
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
        let tv = cmsg_timestamp(&msg).unwrap_or_else(|| {
            let mut tv: libc::timeval = unsafe { mem::zeroed() };
            // SAFETY: plain gettimeofday into a local.
            unsafe {
                libc::gettimeofday(&mut tv, std::ptr::null_mut());
            }
            tv
        });
        let frame = &buf[..n as usize];
        batch.push(Pending {
            ts_sec: tv.tv_sec as u32,
            ts_us: tv.tv_usec as u32,
            start: arena.len(),
            len: frame.len(),
        });
        arena.extend_from_slice(frame);
    }
    SockRead::More(n_read)
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

fn read_loop(inner: &Mutex<Inner>, stop: &AtomicBool, writer: &mut impl Write, c: &Counters) {
    let mut buf = vec![0u8; 65536];
    let mut arena: Vec<u8> = Vec::with_capacity(1 << 20);
    let mut batch: Vec<Pending> = Vec::with_capacity(BURST * 2);
    let mut last_stats = Instant::now();
    let mut drained = 0usize;
    loop {
        // Once stopping, drain what is queued, collect the drop counts
        // and exit.
        let stopping = stop.load(Ordering::Relaxed);
        let socks: Vec<(RawFd, bool, String)> = inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .socks
            .iter()
            .map(|s| (s.fd.as_raw_fd(), s.loopback, s.iface.clone()))
            .collect();
        let mut pfds: Vec<libc::pollfd> = socks
            .iter()
            .map(|(fd, _, _)| libc::pollfd {
                fd: *fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: `pfds` is a valid array of `pfds.len()` pollfds; with
        // no sockets yet this just sleeps for the timeout.
        let timeout = if stopping { 0 } else { 200 };
        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, timeout) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            warn!(error = %err, "capture poll failed");
            return;
        }
        let mut dead: Vec<RawFd> = Vec::new();
        let mut more = false;
        arena.clear();
        batch.clear();
        for (p, (fd, loopback, iface)) in pfds.iter().zip(&socks) {
            if p.revents == 0 {
                continue;
            }
            match read_socket(
                *fd, *loopback, iface, BURST, &mut buf, &mut arena, &mut batch,
            ) {
                SockRead::More(n) => {
                    more = true;
                    drained += n;
                }
                SockRead::Empty(n) => drained += n,
                SockRead::Dead => dead.push(*fd),
            }
        }
        // Several sockets (the port mirror and the enslaved NIC) are
        // read in turns: write this wakeup's frames in kernel time
        // order, so a reply never lands before its request.
        batch.sort_by_key(|p| (p.ts_sec, p.ts_us));
        for p in &batch {
            let frame = &arena[p.start..p.start + p.len];
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
            if let Err(e) = write_record(writer, p.ts_sec, p.ts_us, frame) {
                warn!(error = %e, "capture write failed");
                return;
            }
            c.packets.fetch_add(1, Ordering::Relaxed);
            c.bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
        }
        if stopping || last_stats.elapsed() >= STATS_EVERY {
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
            if more && drained < DRAIN_MAX {
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
        let socks = socks
            .into_iter()
            .enumerate()
            .map(|(i, fd)| CapSock {
                fd,
                iface: format!("test{i}"),
                loopback: false,
            })
            .collect();
        Capture::spawn(
            path.to_path_buf(),
            Inner {
                socks,
                filter: None,
                closed: false,
            },
            None,
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
