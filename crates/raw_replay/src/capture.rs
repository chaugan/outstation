//! Passive capture: bind AF_PACKET to an interface, write received
//! frames to a classic pcap file. Used by the orchestrator to record
//! the frames it just replayed, so the web UI can offer them as a
//! downloadable pcap without the user running Wireshark/tcpdump.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

use anyhow::{anyhow, Context, Result};
use tracing::{debug, warn};

/// Handle to a running capture thread.
pub struct Capture {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    pub path: PathBuf,
    pub packets: Arc<AtomicU64>,
    pub bytes: Arc<AtomicU64>,
}

impl Capture {
    /// Start a capture on `iface`, writing frames to `path`. The
    /// writer uses classic pcap format with microsecond timestamps,
    /// LINKTYPE_ETHERNET, and a 65535-byte snaplen.
    pub fn start(iface: &str, path: impl Into<PathBuf>) -> Result<Self> {
        let path: PathBuf = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
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
                .context("socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)");
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
                .with_context(|| format!("bind capture socket to {iface}"));
        }
        // Short receive timeout so the reader loop can check the stop
        // flag periodically.
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 200_000,
        };
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        let file = File::create(&path)
            .with_context(|| format!("create capture file {path:?}"))?;
        let mut writer = BufWriter::with_capacity(64 * 1024, file);
        write_global_header(&mut writer)?;
        writer.flush().ok();

        let stop = Arc::new(AtomicBool::new(false));
        let packets = Arc::new(AtomicU64::new(0));
        let bytes = Arc::new(AtomicU64::new(0));
        let stop_c = Arc::clone(&stop);
        let packets_c = Arc::clone(&packets);
        let bytes_c = Arc::clone(&bytes);
        let iface_c = iface.to_string();

        let thread = thread::Builder::new()
            .name(format!("capture-{iface_c}"))
            .spawn(move || {
                let mut buf = vec![0u8; 65536];
                loop {
                    if stop_c.load(Ordering::Relaxed) {
                        break;
                    }
                    let n = unsafe {
                        libc::recv(
                            fd.as_raw_fd(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                            0,
                        )
                    };
                    if n > 0 {
                        let n = n as usize;
                        let frame = &buf[..n];
                        let mut tv: libc::timeval = unsafe { mem::zeroed() };
                        unsafe {
                            libc::gettimeofday(&mut tv, std::ptr::null_mut());
                        }
                        if let Err(e) =
                            write_record(&mut writer, tv.tv_sec as u32, tv.tv_usec as u32, frame)
                        {
                            warn!(error = %e, "capture write failed");
                            break;
                        }
                        packets_c.fetch_add(1, Ordering::Relaxed);
                        bytes_c.fetch_add(n as u64, Ordering::Relaxed);
                    } else if n < 0 {
                        let err = io::Error::last_os_error();
                        match err.raw_os_error() {
                            Some(libc::EAGAIN) | Some(libc::EINTR) => continue,
                            _ => {
                                warn!(error = %err, "capture recv failed");
                                break;
                            }
                        }
                    }
                }
                if let Err(e) = writer.flush() {
                    warn!(error = %e, "capture flush failed");
                }
                debug!("capture thread exiting");
            })
            .context("spawn capture thread")?;

        Ok(Self {
            stop,
            thread: Some(thread),
            path,
            packets,
            bytes,
        })
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

fn if_nametoindex(iface: &str) -> Result<i32> {
    let c = CString::new(iface).context("iface name contains nul byte")?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(anyhow!(io::Error::last_os_error())
            .context(format!("if_nametoindex({iface})")));
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
