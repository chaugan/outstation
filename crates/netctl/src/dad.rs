//! Duplicate-address detection before a listen alias is added (F039):
//! an RFC 5227 ARP probe ("who has `ip`?", sender address 0.0.0.0) on
//! the alias NIC. Any answer from another station claiming `ip` means
//! the address is live on that LAN, and aliasing it would steal it.

use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tracing::{info, warn};

use crate::names::validate_host_ifname;
use crate::{format_mac, MacAddr, Protection};

/// How long [`probe_address_in_use`] listens for an answer by default
/// (two probes, half of it apart).
pub const DAD_TIMEOUT: Duration = Duration::from_millis(1000);

const ETH_P_ARP: u16 = 0x0806;
const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_NOARP: u32 = 0x80;

/// Refuse to alias `ip` onto `iface` while another station answers for
/// it, unless `prot.force`. A probe that cannot be carried out is an
/// error as well (fail closed), with the same override.
pub fn check_address_free(iface: &str, ip: Ipv4Addr, prot: &Protection) -> Result<()> {
    if prot.force {
        info!(%ip, iface, "force: duplicate-address check skipped");
        return Ok(());
    }
    match probe_address_in_use(iface, ip, DAD_TIMEOUT) {
        Ok(None) => Ok(()),
        Ok(Some(mac)) => bail!(
            "{ip} is already in use on the LAN of {iface} (ARP answer from {}); \
             pick a free listen address, or force",
            format_mac(mac)
        ),
        Err(e) => Err(e.context(format!(
            "could not check whether {ip} is free on {iface} (force skips the check)"
        ))),
    }
}

/// Send an ARP probe for `ip` on `iface` and wait up to `timeout` for a
/// station claiming it. Returns its MAC, or `None` if nobody answered.
/// Interfaces without ARP (loopback, NOARP, down) have nobody to
/// conflict with and return `None` at once.
pub fn probe_address_in_use(
    iface: &str,
    ip: Ipv4Addr,
    timeout: Duration,
) -> Result<Option<MacAddr>> {
    validate_host_ifname(iface)?;
    let flags = read_sys(iface, "flags")
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .with_context(|| format!("read flags of {iface}"))?;
    if flags & (IFF_LOOPBACK | IFF_NOARP) != 0 || flags & IFF_UP == 0 {
        return Ok(None);
    }
    let own_mac = read_sys(iface, "address")
        .and_then(|s| crate::parse_mac(s.trim()).ok())
        .with_context(|| format!("read MAC of {iface}"))?;
    let ifindex = ifindex(iface)?;
    let sock = arp_socket(ifindex).with_context(|| format!("ARP socket on {iface}"))?;
    let probe = arp_probe(own_mac, ip);

    let start = Instant::now();
    let deadline = start + timeout;
    let mut probes_sent = 0u32;
    loop {
        let now = Instant::now();
        // Two probes: at the start and half way through.
        if probes_sent < 2 && now >= start + timeout / 2 * probes_sent {
            send_broadcast(&sock, ifindex, &probe)
                .with_context(|| format!("send ARP probe on {iface}"))?;
            probes_sent += 1;
        }
        if now >= deadline {
            return Ok(None);
        }
        let next_probe = if probes_sent < 2 {
            start + timeout / 2
        } else {
            deadline
        };
        let wait = next_probe.min(deadline).saturating_duration_since(now);
        if let Some(mac) = recv_claim(&sock, own_mac, ip, wait)? {
            warn!(%ip, iface, mac = %format_mac(mac), "address already in use on the LAN");
            return Ok(Some(mac));
        }
    }
}

fn read_sys(iface: &str, attr: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/{attr}")).ok()
}

fn ifindex(iface: &str) -> Result<i32> {
    let c = std::ffi::CString::new(iface).context("interface name contains a nul byte")?;
    // SAFETY: valid C string.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("if_nametoindex({iface})"));
    }
    Ok(idx as i32)
}

fn sockaddr_ll(ifindex: i32) -> libc::sockaddr_ll {
    // SAFETY: plain C struct, all-zero is valid.
    let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = ETH_P_ARP.to_be();
    sll.sll_ifindex = ifindex;
    sll
}

/// An AF_PACKET datagram socket bound to ARP on `ifindex`.
fn arp_socket(ifindex: i32) -> Result<OwnedFd> {
    // SAFETY: plain socket(2) call.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            i32::from(ETH_P_ARP.to_be()),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("socket(AF_PACKET)");
    }
    // SAFETY: fresh descriptor we own.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    let sll = sockaddr_ll(ifindex);
    // SAFETY: `sll` is a valid sockaddr_ll of the given size.
    let rc = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("bind ARP socket");
    }
    Ok(sock)
}

/// RFC 5227 probe: request, sender MAC ours, sender IP 0.0.0.0, target
/// IP `ip`.
pub(crate) fn arp_probe(own_mac: MacAddr, ip: Ipv4Addr) -> [u8; 28] {
    let mut p = [0u8; 28];
    p[0..2].copy_from_slice(&1u16.to_be_bytes()); // Ethernet
    p[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    p[4] = 6;
    p[5] = 4;
    p[6..8].copy_from_slice(&1u16.to_be_bytes()); // request
    p[8..14].copy_from_slice(&own_mac);
    // p[14..18]: sender IP 0.0.0.0; p[18..24]: target MAC unknown.
    p[24..28].copy_from_slice(&ip.octets());
    p
}

/// If `arp` is a request or reply from another station whose sender
/// address is `ip`, that station's MAC.
pub(crate) fn claimant(arp: &[u8], own_mac: MacAddr, ip: Ipv4Addr) -> Option<MacAddr> {
    if arp.len() < 28 || arp[0..2] != [0, 1] || arp[2..4] != [8, 0] || arp[4] != 6 || arp[5] != 4 {
        return None;
    }
    let sha: MacAddr = arp[8..14].try_into().ok()?;
    let spa = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
    (spa == ip && sha != own_mac).then_some(sha)
}

fn send_broadcast(sock: &OwnedFd, ifindex: i32, payload: &[u8]) -> Result<()> {
    let mut sll = sockaddr_ll(ifindex);
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(&[0xff; 6]);
    // SAFETY: valid buffer and sockaddr_ll.
    let n = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            payload.as_ptr() as *const libc::c_void,
            payload.len(),
            0,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

/// Read ARP frames for up to `wait`; the first claim on `ip` wins.
fn recv_claim(
    sock: &OwnedFd,
    own_mac: MacAddr,
    ip: Ipv4Addr,
    wait: Duration,
) -> Result<Option<MacAddr>> {
    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 128];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let mut pfd = libc::pollfd {
            fd: sock.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = left.as_millis().min(i32::MAX as u128) as libc::c_int;
        // SAFETY: one valid pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e).context("poll ARP socket");
        }
        if rc == 0 {
            return Ok(None);
        }
        // SAFETY: `buf` is valid for its length.
        let n = unsafe {
            libc::recv(
                sock.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(e).context("recv ARP");
        }
        if let Some(mac) = claimant(&buf[..n as usize], own_mac, ip) {
            return Ok(Some(mac));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_and_claim_parsing() {
        let me = [2, 0, 0, 0, 0, 1];
        let ip = Ipv4Addr::new(192, 168, 10, 49);
        let p = arp_probe(me, ip);
        assert_eq!(&p[..8], &[0, 1, 8, 0, 6, 4, 0, 1]);
        assert_eq!(&p[8..14], &me);
        assert_eq!(&p[14..18], &[0, 0, 0, 0], "probe sender IP is 0.0.0.0");
        assert_eq!(&p[24..28], &ip.octets());
        // Our own probe (sender IP 0, our MAC) is no claim.
        assert_eq!(claimant(&p, me, ip), None);
        // A reply from another station for ip is.
        let other = [2, 0, 0, 0, 0, 9];
        let mut reply = p;
        reply[6..8].copy_from_slice(&2u16.to_be_bytes());
        reply[8..14].copy_from_slice(&other);
        reply[14..18].copy_from_slice(&ip.octets());
        assert_eq!(claimant(&reply, me, ip), Some(other));
        // ... but not for another address, nor a truncated frame.
        assert_eq!(claimant(&reply, me, Ipv4Addr::new(10, 0, 0, 1)), None);
        assert_eq!(claimant(&reply[..20], me, ip), None);
        // A station announcing ip (gratuitous request) is a claim too.
        let mut announce = reply;
        announce[6..8].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(claimant(&announce, me, ip), Some(other));
    }

    #[test]
    fn loopback_has_nobody_to_conflict_with() {
        assert_eq!(
            probe_address_in_use("lo", Ipv4Addr::new(127, 0, 0, 9), DAD_TIMEOUT).unwrap(),
            None
        );
        let force = Protection::new(Vec::new(), true);
        assert!(check_address_free("no-such-if0", Ipv4Addr::new(10, 0, 0, 1), &force).is_ok());
        let no_force = Protection::new(Vec::new(), false);
        assert!(check_address_free("no-such-if0", Ipv4Addr::new(10, 0, 0, 1), &no_force).is_err());
    }
}
