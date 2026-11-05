//! Classic BPF socket filters for [`crate::Capture`].
//!
//! [`tcp_endpoints_filter`] builds the kernel filter that restricts a
//! capture to TCP segments to or from a set of `(ip, port)` endpoints,
//! so nothing else on the interface ever reaches userspace (or the
//! capture file). The program is straight-line comparisons with
//! unconditional `ja` trampolines, so it stays valid however many
//! addresses it lists (conditional jumps only reach 255 instructions).

use std::net::Ipv4Addr;

use anyhow::{bail, Result};

/// One classic BPF instruction (`struct sock_filter`).
pub type Insn = libc::sock_filter;

// Instruction classes and fields (linux/filter.h, linux/bpf_common.h).
const LD: u16 = 0x00;
const LDX: u16 = 0x01;
const JMP: u16 = 0x05;
const RET: u16 = 0x06;
const W: u16 = 0x00;
const H: u16 = 0x08;
const B: u16 = 0x10;
const ABS: u16 = 0x20;
const IND: u16 = 0x40;
const MSH: u16 = 0xa0;
const JA: u16 = 0x00;
const JEQ: u16 = 0x10;
const JSET: u16 = 0x40;
const K: u16 = 0x00;

/// The kernel's limit on a classic BPF program (BPF_MAXINSNS).
pub const MAX_INSNS: usize = 4096;

/// Bytes kept of every accepted frame (the capture file's snaplen).
pub const SNAPLEN: u32 = 65535;

fn stmt(code: u16, k: u32) -> Insn {
    Insn {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Insn {
    Insn { code, jt, jf, k }
}

/// A program that accepts nothing.
pub fn reject_all() -> Vec<Insn> {
    vec![stmt(RET | K, 0)]
}

/// A program that accepts every frame (snapped to [`SNAPLEN`]).
pub fn accept_all() -> Vec<Insn> {
    vec![stmt(RET | K, SNAPLEN)]
}

/// Ancillary load of the packet type (`SKF_AD_OFF + SKF_AD_PKTTYPE`).
const AD_PKTTYPE: u32 = (libc::SKF_AD_OFF + libc::SKF_AD_PKTTYPE) as u32;

/// `prog`, but dropping outgoing frames first. On `lo` every frame is
/// seen twice (outgoing, then incoming); dropping one copy in the
/// kernel halves what the socket must queue. The rest of `prog` only
/// uses relative jumps, so prefixing it is safe.
pub fn skip_outgoing(prog: &[Insn]) -> Vec<Insn> {
    let mut v = vec![
        stmt(LD | W | ABS, AD_PKTTYPE),
        jump(JMP | JEQ | K, u32::from(libc::PACKET_OUTGOING), 0, 1),
        stmt(RET | K, 0),
    ];
    v.extend_from_slice(prog);
    v
}

/// Accept frames that are *not* outgoing and whose destination MAC is
/// a group address (broadcast or multicast) or one of `macs`: what a
/// run bridge delivers from its enslaved NIC to the run's own ports.
/// Used on the enslaved NIC, whose outgoing frames the port mirror
/// already holds, so a capture of both sees every wire frame of the run
/// exactly once (B1). Frames for other LAN hosts are dropped in the
/// kernel. With more MACs than fit in one program, the MAC test is
/// left out (every incoming frame is kept).
pub fn incoming_to_macs_filter(macs: &[[u8; 6]]) -> Vec<Insn> {
    // 5 instructions per MAC (all jumps short and forward), 7 fixed.
    if macs.len() * 5 + 7 > MAX_INSNS {
        return skip_outgoing(&accept_all());
    }
    let mut prog: Vec<Insn> = Vec::with_capacity(macs.len() * 5 + 4);
    // Group bit of the destination MAC.
    prog.push(stmt(LD | B | ABS, 0));
    prog.push(jump(JMP | JSET | K, 0x01, 0, 1));
    prog.push(stmt(RET | K, SNAPLEN));
    for m in macs {
        let hi = u32::from(u16::from_be_bytes([m[0], m[1]]));
        let lo = u32::from_be_bytes([m[2], m[3], m[4], m[5]]);
        prog.push(stmt(LD | W | ABS, 2));
        prog.push(jump(JMP | JEQ | K, lo, 0, 3));
        prog.push(stmt(LD | H | ABS, 0));
        prog.push(jump(JMP | JEQ | K, hi, 0, 1));
        prog.push(stmt(RET | K, SNAPLEN));
    }
    prog.push(stmt(RET | K, 0));
    skip_outgoing(&prog)
}

/// Labels of [`tcp_endpoints_filter`].
#[derive(Clone, Copy)]
enum Label {
    Drop,
    Accept,
    SrcMatch,
    CheckDst,
    DstMatch,
}

/// Accept IPv4 TCP segments (first fragments or unfragmented) whose
/// source is `(ip, port)` or whose destination is `(ip, port)` for any
/// `ip` in `ips`, on an Ethernet (or loopback) link. Everything else
/// (other hosts, other ports, UDP, ICMP, ARP, IPv6, VLAN-tagged frames)
/// is dropped in the kernel. An empty `ips` accepts nothing.
pub fn tcp_endpoints_filter(ips: &[Ipv4Addr], port: u16) -> Result<Vec<Insn>> {
    if ips.is_empty() {
        return Ok(reject_all());
    }
    // (instruction, label its `ja` targets)
    let mut prog: Vec<(Insn, Option<Label>)> = Vec::new();
    let mut labels: [usize; 5] = [0; 5];
    let ja =
        |prog: &mut Vec<(Insn, Option<Label>)>, l: Label| prog.push((stmt(JMP | JA, 0), Some(l)));

    // EtherType IPv4.
    prog.push((stmt(LD | H | ABS, 12), None));
    prog.push((jump(JMP | JEQ | K, 0x0800, 1, 0), None));
    ja(&mut prog, Label::Drop);
    // Protocol TCP.
    prog.push((stmt(LD | B | ABS, 23), None));
    prog.push((jump(JMP | JEQ | K, 6, 1, 0), None));
    ja(&mut prog, Label::Drop);
    // Not a non-first fragment (ports are only in the first).
    prog.push((stmt(LD | H | ABS, 20), None));
    prog.push((jump(JMP | JSET | K, 0x1fff, 0, 1), None));
    ja(&mut prog, Label::Drop);
    // X = IPv4 header length.
    prog.push((stmt(LDX | B | MSH, 14), None));

    // Source side: src ip in set and src port == port.
    prog.push((stmt(LD | W | ABS, 26), None));
    for ip in ips {
        prog.push((jump(JMP | JEQ | K, u32::from(*ip), 0, 1), None));
        ja(&mut prog, Label::SrcMatch);
    }
    ja(&mut prog, Label::CheckDst);
    labels[Label::SrcMatch as usize] = prog.len();
    prog.push((stmt(LD | H | IND, 14), None));
    prog.push((jump(JMP | JEQ | K, u32::from(port), 0, 1), None));
    ja(&mut prog, Label::Accept);

    // Destination side.
    labels[Label::CheckDst as usize] = prog.len();
    prog.push((stmt(LD | W | ABS, 30), None));
    for ip in ips {
        prog.push((jump(JMP | JEQ | K, u32::from(*ip), 0, 1), None));
        ja(&mut prog, Label::DstMatch);
    }
    ja(&mut prog, Label::Drop);
    labels[Label::DstMatch as usize] = prog.len();
    prog.push((stmt(LD | H | IND, 16), None));
    prog.push((jump(JMP | JEQ | K, u32::from(port), 0, 1), None));
    ja(&mut prog, Label::Accept);

    labels[Label::Drop as usize] = prog.len();
    prog.push((stmt(RET | K, 0), None));
    labels[Label::Accept as usize] = prog.len();
    prog.push((stmt(RET | K, SNAPLEN), None));

    if prog.len() > MAX_INSNS {
        bail!(
            "capture filter for {} addresses needs {} BPF instructions (limit {MAX_INSNS})",
            ips.len(),
            prog.len()
        );
    }
    Ok(prog
        .into_iter()
        .enumerate()
        .map(|(pc, (mut i, l))| {
            if let Some(l) = l {
                // `ja` jumps relative to the next instruction.
                i.k = (labels[l as usize] - (pc + 1)) as u32;
            }
            i
        })
        .collect())
}

/// Minimal classic-BPF interpreter covering what this module emits,
/// with the kernel's semantics (an out-of-bounds load drops the
/// packet). Test-only.
#[cfg(test)]
pub(crate) fn run(prog: &[Insn], pkt: &[u8]) -> u32 {
    run_typed(prog, pkt, 0)
}

/// [`run`] for a frame of the given packet type (`PACKET_HOST` = 0,
/// `PACKET_OUTGOING` = 4).
#[cfg(test)]
pub(crate) fn run_typed(prog: &[Insn], pkt: &[u8], pkttype: u8) -> u32 {
    let (mut a, mut x): (u32, u32) = (0, 0);
    let mut pc = 0usize;
    let load = |off: usize, size: usize| -> Option<u32> {
        let b = pkt.get(off..off + size)?;
        Some(b.iter().fold(0u32, |acc, &v| (acc << 8) | u32::from(v)))
    };
    loop {
        let i = prog[pc];
        pc += 1;
        let size = |c: u16| match c & 0x18 {
            W => 4,
            H => 2,
            _ => 1,
        };
        match i.code & 0x07 {
            c if c == LD && i.code & 0xe0 == ABS && i.k == AD_PKTTYPE => {
                a = u32::from(pkttype);
            }
            c if c == LD => {
                let off = match i.code & 0xe0 {
                    ABS => i.k as usize,
                    IND => x as usize + i.k as usize,
                    m => panic!("unsupported ld mode {m:#x}"),
                };
                match load(off, size(i.code)) {
                    Some(v) => a = v,
                    None => return 0,
                }
            }
            c if c == LDX => {
                assert_eq!(i.code & 0xe0, MSH);
                match load(i.k as usize, 1) {
                    Some(v) => x = (v & 0xf) * 4,
                    None => return 0,
                }
            }
            c if c == JMP => match i.code & 0xf0 {
                JA => pc += i.k as usize,
                JEQ => pc += usize::from(if a == i.k { i.jt } else { i.jf }),
                JSET => pc += usize::from(if a & i.k != 0 { i.jt } else { i.jf }),
                o => panic!("unsupported jmp {o:#x}"),
            },
            c if c == RET => return i.k,
            c => panic!("unsupported class {c:#x}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    /// Ethernet + IPv4 (+options) + L4 header bytes.
    #[allow(clippy::too_many_arguments)]
    fn frame(
        ethertype: u16,
        proto: u8,
        src: Ipv4Addr,
        sport: u16,
        dst: Ipv4Addr,
        dport: u16,
        frag: u16,
        opt_words: u8,
    ) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&ethertype.to_be_bytes());
        let ihl = 5 + opt_words;
        f.push(0x40 | ihl);
        f.push(0);
        f.extend_from_slice(&[0, 60, 0, 0]);
        f.extend_from_slice(&frag.to_be_bytes());
        f.extend_from_slice(&[64, proto, 0, 0]);
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&dst.octets());
        f.extend(std::iter::repeat_n(1u8, usize::from(opt_words) * 4));
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&[0; 16]);
        f
    }

    fn tcp(src: &str, sport: u16, dst: &str, dport: u16) -> Vec<u8> {
        frame(0x0800, 6, ip(src), sport, ip(dst), dport, 0, 0)
    }

    #[test]
    fn accepts_only_the_listed_endpoints() {
        let ips = [ip("192.168.10.49"), ip("192.168.10.67"), ip("127.0.10.16")];
        let p = tcp_endpoints_filter(&ips, 2404).unwrap();
        let yes = |f: &[u8]| run(&p, f) == SNAPLEN;
        // To and from every listed endpoint.
        assert!(yes(&tcp("10.79.0.2", 50000, "192.168.10.49", 2404)));
        assert!(yes(&tcp("192.168.10.49", 2404, "10.79.0.2", 50000)));
        assert!(yes(&tcp("192.168.10.67", 2404, "10.79.0.2", 50001)));
        assert!(yes(&tcp("127.0.0.1", 41000, "127.0.10.16", 2404)));
        // IP options shift the TCP header.
        assert!(yes(&frame(
            0x0800,
            6,
            ip("10.79.0.2"),
            1,
            ip("192.168.10.67"),
            2404,
            0,
            2
        )));
        assert!(yes(&frame(
            0x0800,
            6,
            ip("10.79.0.2"),
            1,
            ip("192.168.10.67"),
            2404,
            0x4000, // DF only
            0
        )));
        // Listed host, other port; other host, listed port.
        assert!(!yes(&tcp("10.79.0.2", 50000, "192.168.10.49", 22)));
        assert!(!yes(&tcp("192.168.10.49", 22, "10.79.0.2", 2404)));
        assert!(!yes(&tcp("10.79.0.2", 50000, "10.79.0.1", 2404)));
        assert!(!yes(&tcp("10.79.0.1", 2404, "10.79.0.2", 50000)));
        // The listed port as the *peer's* port does not count.
        assert!(!yes(&tcp("10.79.0.2", 2404, "192.168.10.49", 50000)));
        // Not TCP / not IPv4.
        let udp = frame(
            0x0800,
            17,
            ip("10.79.0.2"),
            1,
            ip("192.168.10.49"),
            2404,
            0,
            0,
        );
        assert!(!yes(&udp));
        let icmp = frame(0x0800, 1, ip("10.79.0.2"), 0, ip("192.168.10.49"), 0, 0, 0);
        assert!(!yes(&icmp));
        let arp = frame(
            0x0806,
            6,
            ip("10.79.0.2"),
            1,
            ip("192.168.10.49"),
            2404,
            0,
            0,
        );
        assert!(!yes(&arp));
        let vlan = frame(
            0x8100,
            6,
            ip("10.79.0.2"),
            1,
            ip("192.168.10.49"),
            2404,
            0,
            0,
        );
        assert!(!yes(&vlan));
        // A non-first fragment carries no ports.
        let frag = frame(
            0x0800,
            6,
            ip("10.79.0.2"),
            1,
            ip("192.168.10.49"),
            2404,
            0x0010,
            0,
        );
        assert!(!yes(&frag));
        // Truncated frames are dropped, not misread.
        assert_eq!(
            run(&p, &tcp("10.79.0.2", 1, "192.168.10.49", 2404)[..30]),
            0
        );
        assert_eq!(run(&p, &[]), 0);
    }

    #[test]
    fn outgoing_copies_are_skipped() {
        let ips = [ip("127.0.10.49")];
        let p = skip_outgoing(&tcp_endpoints_filter(&ips, 2404).unwrap());
        let f = tcp("127.0.0.1", 41000, "127.0.10.49", 2404);
        assert_eq!(run_typed(&p, &f, 0), SNAPLEN, "incoming copy kept");
        assert_eq!(run_typed(&p, &f, libc::PACKET_OUTGOING), 0);
        let other = tcp("127.0.0.1", 41000, "127.0.0.5", 2404);
        assert_eq!(run_typed(&p, &other, 0), 0, "the filter still applies");
        let all = skip_outgoing(&accept_all());
        assert_eq!(run_typed(&all, &other, 0), SNAPLEN);
        assert_eq!(run_typed(&all, &other, libc::PACKET_OUTGOING), 0);
    }

    #[test]
    fn incoming_frames_to_our_macs_and_groups_only() {
        let a = [0x02, 0x00, 0x5e, 0x00, 0x64, 0x6c];
        let b = [0x02, 0x13, 0x2c, 0xde, 0xd6, 0x23];
        let p = incoming_to_macs_filter(&[a, b]);
        let to = |dst: [u8; 6]| {
            let mut f = tcp("10.77.0.1", 2404, "192.168.10.3", 50000);
            f[..6].copy_from_slice(&dst);
            f
        };
        let keep = |f: &[u8], t: u8| run_typed(&p, f, t) == SNAPLEN;
        // Incoming (host, broadcast, multicast, other host).
        for t in [0u8, 1, 2, 3] {
            assert!(keep(&to(a), t));
            assert!(keep(&to(b), t));
            assert!(keep(&to([0xff; 6]), t), "broadcast");
            assert!(keep(&to([0x01, 0x00, 0x5e, 0, 0, 0x16]), t), "multicast");
            assert!(!keep(&to([0x02, 0x00, 0x5e, 0x00, 0x64, 0x6d]), t));
            assert!(
                !keep(&to([0x02, 0x01, 0x5e, 0x00, 0x64, 0x6c]), t),
                "same low 4 bytes"
            );
            assert!(
                !keep(&to([0x02, 0x00, 0x2c, 0xde, 0xd6, 0x23]), t),
                "mixed halves"
            );
        }
        // Outgoing copies are always dropped.
        assert!(!keep(&to(a), libc::PACKET_OUTGOING));
        assert!(!keep(&to([0xff; 6]), libc::PACKET_OUTGOING));
        // Truncated frames are dropped.
        assert_eq!(run(&p, &to(a)[..4]), 0);
        // No MACs: groups only.
        let g = incoming_to_macs_filter(&[]);
        assert_eq!(run(&g, &to([0xff; 6])), SNAPLEN);
        assert_eq!(run(&g, &to(a)), 0);
        // Too many MACs: everything incoming.
        let many: Vec<[u8; 6]> = (0..800u32)
            .map(|n| {
                let x = n.to_be_bytes();
                [2, 0, x[0], x[1], x[2], x[3]]
            })
            .collect();
        let m = incoming_to_macs_filter(&many);
        assert!(m.len() <= MAX_INSNS);
        assert_eq!(run(&m, &to(many[799])), SNAPLEN);
        assert_eq!(run(&m, &to(many[0])), SNAPLEN);
        assert_eq!(run(&m, &to([2, 9, 9, 9, 9, 9])), 0);
        let huge: Vec<[u8; 6]> = (0..1000u32)
            .map(|n| {
                let x = n.to_be_bytes();
                [2, 1, x[0], x[1], x[2], x[3]]
            })
            .chain(many.iter().copied())
            .collect();
        let h = incoming_to_macs_filter(&huge);
        assert_eq!(run(&h, &to([2, 9, 9, 9, 9, 9])), SNAPLEN);
        assert_eq!(run_typed(&h, &to(a), libc::PACKET_OUTGOING), 0);
    }

    #[test]
    fn empty_set_accepts_nothing() {
        let p = tcp_endpoints_filter(&[], 2404).unwrap();
        assert_eq!(run(&p, &tcp("10.0.0.1", 1, "10.0.0.2", 2404)), 0);
    }

    #[test]
    fn large_sets_stay_reachable_and_bounded() {
        // 1000 addresses: far more than a conditional jump can span.
        let ips: Vec<Ipv4Addr> = (0..1000u32)
            .map(|n| Ipv4Addr::from(0x0a00_0000 + n))
            .collect();
        let p = tcp_endpoints_filter(&ips, 2404).unwrap();
        assert!(p.len() <= MAX_INSNS);
        for probe in [0usize, 1, 499, 998, 999] {
            let host = ips[probe].to_string();
            assert_eq!(
                run(&p, &tcp("10.200.0.1", 7, &host, 2404)),
                SNAPLEN,
                "{host}"
            );
            assert_eq!(
                run(&p, &tcp(&host, 2404, "10.200.0.1", 7)),
                SNAPLEN,
                "{host}"
            );
            assert_eq!(run(&p, &tcp(&host, 2405, "10.200.0.1", 7)), 0, "{host}");
        }
        assert_eq!(run(&p, &tcp("10.200.0.1", 7, "10.0.3.232", 2404)), 0);
        let too_many: Vec<Ipv4Addr> = (0..1100u32).map(Ipv4Addr::from).collect();
        assert!(tcp_endpoints_filter(&too_many, 2404).is_err());
    }
}
