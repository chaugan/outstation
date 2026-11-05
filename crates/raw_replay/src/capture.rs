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
}

/// Final counters of a capture, see [`Capture::finish`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureStats {
    pub path: PathBuf,
    pub packets: u64,
    pub bytes: u64,
    /// Frames the kernel dropped (receive queue full).
    pub dropped: u64,
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
            },
            rt_priority,
        )
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Also capture on `iface` (an Ethernet or loopback interface).
    /// Returns `false` if it is already captured.
    pub fn add_iface(&self, iface: &str) -> Result<bool> {
        let mut inner = self.lock();
        if inner.socks.iter().any(|s| s.iface == iface) {
            return Ok(false);
        }
        let sock = open_socket(iface, inner.filter.as_deref())?;
        info!(iface, path = %self.path.display(), "capture: added interface");
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
        let stop_c = Arc::clone(&stop);
        let counters = Counters {
            packets: Arc::clone(&packets),
            bytes: Arc::clone(&bytes),
            dropped: Arc::clone(&dropped),
        };
        let inner_c = Arc::clone(&inner);
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();

        let thread = thread::Builder::new()
            .name(format!("capture-{name}"))
            .spawn(move || {
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
/// Frames drained from one socket when the capture stops (bounded, so
/// a socket that keeps receiving cannot hold the stop up).
const DRAIN_MAX: usize = 1 << 16;

/// Counters shared with the handle.
struct Counters {
    packets: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

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

fn read_loop(inner: &Mutex<Inner>, stop: &AtomicBool, writer: &mut impl Write, c: &Counters) {
    let mut buf = vec![0u8; 65536];
    let mut last_stats = Instant::now();
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
        for (p, (fd, loopback, iface)) in pfds.iter().zip(&socks) {
            if p.revents == 0 {
                continue;
            }
            let burst = if stopping { DRAIN_MAX } else { BURST };
            for _ in 0..burst {
                let mut from: libc::sockaddr_ll = unsafe { mem::zeroed() };
                let mut from_len = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
                // SAFETY: `buf` and `from` are valid for the given sizes.
                let n = unsafe {
                    libc::recvfrom(
                        *fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        libc::MSG_DONTWAIT,
                        &mut from as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                        &mut from_len,
                    )
                };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(libc::EAGAIN) | Some(libc::EINTR) => {}
                        _ => {
                            warn!(iface, error = %err, "capture recv failed; dropping interface");
                            dead.push(*fd);
                        }
                    }
                    break;
                }
                if n == 0 {
                    break;
                }
                // The kernel filter already drops these on lo; this
                // also covers an unfiltered or older socket.
                if *loopback && from.sll_pkttype == libc::PACKET_OUTGOING {
                    continue;
                }
                let frame = &buf[..n as usize];
                let mut tv: libc::timeval = unsafe { mem::zeroed() };
                // SAFETY: plain gettimeofday into a local.
                unsafe {
                    libc::gettimeofday(&mut tv, std::ptr::null_mut());
                }
                if let Err(e) = write_record(writer, tv.tv_sec as u32, tv.tv_usec as u32, frame) {
                    warn!(error = %e, "capture write failed");
                    return;
                }
                c.packets.fetch_add(1, Ordering::Relaxed);
                c.bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
            }
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
            return;
        }
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
