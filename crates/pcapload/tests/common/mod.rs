//! In-test capture builders. A Rust port of the audit's
//! `gen_variants.py` / `gen_more.py`, so every fixture is generated
//! from bytes at test time and no binary blobs live in the repo.

#![allow(dead_code)]

pub const CMAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
pub const SMAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
pub const CIP: [u8; 4] = [10, 0, 0, 1];
pub const SIP: [u8; 4] = [10, 0, 0, 2];
pub const CPORT: u16 = 40000;
pub const SPORT: u16 = 2404;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

pub const STARTDT_ACT: [u8; 6] = [0x68, 4, 0x07, 0, 0, 0];
pub const STARTDT_CON: [u8; 6] = [0x68, 4, 0x0B, 0, 0, 0];

/// `(timestamp_ns, frame)`.
pub type Pkt = (u64, Vec<u8>);

fn csum(b: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in b.chunks(2) {
        let w = if c.len() == 2 {
            u16::from_be_bytes([c[0], c[1]])
        } else {
            u16::from_be_bytes([c[0], 0])
        };
        s += u32::from(w);
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

pub fn ip4(
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    payload: &[u8],
    ident: u16,
    flags_frag: u16,
) -> Vec<u8> {
    let tl = (20 + payload.len()) as u16;
    let mut h = Vec::with_capacity(20 + payload.len());
    h.push(0x45);
    h.push(0);
    h.extend_from_slice(&tl.to_be_bytes());
    h.extend_from_slice(&ident.to_be_bytes());
    h.extend_from_slice(&flags_frag.to_be_bytes());
    h.push(64);
    h.push(proto);
    h.extend_from_slice(&[0, 0]);
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let c = csum(&h);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

pub fn tcp_hdr(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(20 + payload.len());
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    t.push(5 << 4);
    t.push(flags);
    t.extend_from_slice(&65535u16.to_be_bytes());
    t.extend_from_slice(&[0, 0, 0, 0]);
    t.extend_from_slice(payload);
    t
}

pub fn eth(src: [u8; 6], dst: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

pub fn frame(c2s: bool, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    if c2s {
        let t = tcp_hdr(CPORT, SPORT, seq, ack, flags, payload);
        eth(CMAC, SMAC, 0x0800, &ip4(CIP, SIP, 6, &t, 1, 0x4000))
    } else {
        let t = tcp_hdr(SPORT, CPORT, seq, ack, flags, payload);
        eth(SMAC, CMAC, 0x0800, &ip4(SIP, CIP, 6, &t, 1, 0x4000))
    }
}

pub fn iframe(ns: u16, nr: u16, asdu: &[u8]) -> Vec<u8> {
    let mut f = vec![0x68, (4 + asdu.len()) as u8];
    f.extend_from_slice(&(ns << 1).to_le_bytes());
    f.extend_from_slice(&(nr << 1).to_le_bytes());
    f.extend_from_slice(asdu);
    f
}

/// M_ME_NC_1, one object, COT spontaneous.
pub fn asdu_m_me_nc(ca: u16, ioa: u32, val: f32) -> Vec<u8> {
    let mut a = vec![13, 1, 3, 0];
    a.extend_from_slice(&ca.to_le_bytes());
    a.extend_from_slice(&ioa.to_le_bytes()[..3]);
    a.extend_from_slice(&val.to_le_bytes());
    a.push(0);
    a
}

/// C_IC_NA_1 activation.
pub fn asdu_c_ic(ca: u16) -> Vec<u8> {
    let mut a = vec![100, 1, 6, 0];
    a.extend_from_slice(&ca.to_le_bytes());
    a.extend_from_slice(&[0, 0, 0, 20]);
    a
}

pub struct Session {
    pub pkts: Vec<Pkt>,
    pub client: Vec<u8>,
    pub server: Vec<u8>,
}

/// One IEC 104 session: optional handshake, STARTDT, a GI, `n`
/// spontaneous measurements and `n` more GIs.
pub fn session(cisn: u32, sisn: u32, n: u16, t0_ns: u64, with_syn: bool) -> Session {
    let mut pkts = Vec::new();
    let mut t = t0_ns;
    let (mut c, mut s) = (cisn, sisn);
    let mut client = Vec::new();
    let mut server = Vec::new();
    if with_syn {
        pkts.push((t, frame(true, c, 0, SYN, &[])));
        c = c.wrapping_add(1);
        t += 1_000_000;
        pkts.push((t, frame(false, s, c, SYN | ACK, &[])));
        s = s.wrapping_add(1);
        t += 1_000_000;
        pkts.push((t, frame(true, c, s, ACK, &[])));
        t += 1_000_000;
    }
    let mut add = |c2s: bool, payload: Vec<u8>, pkts: &mut Vec<Pkt>| {
        if c2s {
            pkts.push((t, frame(true, c, s, PSH | ACK, &payload)));
            c = c.wrapping_add(payload.len() as u32);
            client.extend_from_slice(&payload);
        } else {
            pkts.push((t, frame(false, s, c, PSH | ACK, &payload)));
            s = s.wrapping_add(payload.len() as u32);
            server.extend_from_slice(&payload);
        }
        t += 10_000_000;
    };
    add(true, STARTDT_ACT.to_vec(), &mut pkts);
    add(false, STARTDT_CON.to_vec(), &mut pkts);
    add(true, iframe(0, 0, &asdu_c_ic(1)), &mut pkts);
    for i in 0..n {
        add(
            false,
            iframe(i, 1, &asdu_m_me_nc(1, 100 + u32::from(i), f32::from(i))),
            &mut pkts,
        );
    }
    for i in 0..n {
        add(true, iframe(1 + i, n, &asdu_c_ic(1)), &mut pkts);
    }
    Session {
        pkts,
        client,
        server,
    }
}

/// The audit's base session: ISNs 1000/5000, 6 measurements, with SYN.
pub fn base() -> Session {
    session(1000, 5000, 6, 1_700_000_000_000_000_000, true)
}

/// Classic pcap writer. `ns` selects the nanosecond magic.
pub fn write_pcap(pkts: &[Pkt], linktype: u32, big_endian: bool, ns: bool) -> Vec<u8> {
    let u32b = |v: u32| {
        if big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    let u16b = |v: u16| {
        if big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    let magic: u32 = if ns { 0xa1b2_3c4d } else { 0xa1b2_c3d4 };
    let mut out = Vec::new();
    out.extend_from_slice(&u32b(magic));
    out.extend_from_slice(&u16b(2));
    out.extend_from_slice(&u16b(4));
    out.extend_from_slice(&u32b(0));
    out.extend_from_slice(&u32b(0));
    out.extend_from_slice(&u32b(65535));
    out.extend_from_slice(&u32b(linktype));
    for (ts, d) in pkts {
        let sec = (ts / 1_000_000_000) as u32;
        let sub = if ns {
            (ts % 1_000_000_000) as u32
        } else {
            ((ts % 1_000_000_000) / 1_000) as u32
        };
        out.extend_from_slice(&u32b(sec));
        out.extend_from_slice(&u32b(sub));
        out.extend_from_slice(&u32b(d.len() as u32));
        out.extend_from_slice(&u32b(d.len() as u32));
        out.extend_from_slice(d);
    }
    out
}

/// Little-endian µs Ethernet pcap.
pub fn pcap(pkts: &[Pkt]) -> Vec<u8> {
    write_pcap(pkts, 1, false, false)
}

pub fn ng_block(btype: u32, body: &[u8]) -> Vec<u8> {
    let pad = (4 - body.len() % 4) % 4;
    let total = (12 + body.len() + pad) as u32;
    let mut b = Vec::new();
    b.extend_from_slice(&btype.to_le_bytes());
    b.extend_from_slice(&total.to_le_bytes());
    b.extend_from_slice(body);
    b.extend(std::iter::repeat_n(0u8, pad));
    b.extend_from_slice(&total.to_le_bytes());
    b
}

pub fn shb() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(-1i64).to_le_bytes());
    ng_block(0x0A0D_0D0A, &body)
}

pub fn idb(linktype: u16, tsresol: Option<u8>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&linktype.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    if let Some(r) = tsresol {
        body.extend_from_slice(&9u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&[r, 0, 0, 0]);
        body.extend_from_slice(&[0, 0, 0, 0]);
    }
    ng_block(1, &body)
}

pub fn epb(iface: u32, ticks: u64, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&iface.to_le_bytes());
    body.extend_from_slice(&((ticks >> 32) as u32).to_le_bytes());
    body.extend_from_slice(&(ticks as u32).to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(data);
    ng_block(6, &body)
}

pub fn spb(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(data);
    ng_block(3, &body)
}

/// Single-section pcapng, one Ethernet interface, µs (or `tsresol`).
pub fn pcapng(pkts: &[Pkt], tsresol: Option<u8>) -> Vec<u8> {
    let mut out = shb();
    out.extend(idb(1, tsresol));
    let div = match tsresol {
        Some(9) => 1,
        _ => 1_000,
    };
    for (ts, d) in pkts {
        out.extend(epb(0, ts / div, d));
    }
    out
}

/// Strip the 14-byte Ethernet header.
pub fn l3_of(d: &[u8]) -> &[u8] {
    &d[14..]
}

pub fn sll(d: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&0u16.to_be_bytes()); // pkttype
    f.extend_from_slice(&1u16.to_be_bytes()); // ARPHRD_ETHER
    f.extend_from_slice(&6u16.to_be_bytes()); // halen
    f.extend_from_slice(&d[6..12]);
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f.extend_from_slice(&d[14..]);
    f
}

pub fn sll2(d: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol
    f.extend_from_slice(&0u16.to_be_bytes()); // reserved
    f.extend_from_slice(&1u32.to_be_bytes()); // ifindex
    f.extend_from_slice(&1u16.to_be_bytes()); // ARPHRD_ETHER
    f.push(0); // pkttype
    f.push(6); // halen
    f.extend_from_slice(&d[6..12]);
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&d[14..]);
    f
}

/// Insert VLAN tags (outermost first) after the MAC addresses.
pub fn vlan(d: &[u8], tpids: &[u16]) -> Vec<u8> {
    let mut f = d[..12].to_vec();
    for (i, tpid) in tpids.iter().enumerate() {
        f.extend_from_slice(&tpid.to_be_bytes());
        f.extend_from_slice(&(100 + i as u16).to_be_bytes());
    }
    f.extend_from_slice(&d[12..]);
    f
}

/// Re-encode an Ethernet/IPv4/TCP frame as Ethernet/IPv6/TCP.
pub fn to_v6(d: &[u8]) -> Vec<u8> {
    let ipb = &d[14..];
    let ihl = usize::from(ipb[0] & 0xf) * 4;
    let l4 = &ipb[ihl..];
    let mut v6 = Vec::new();
    v6.extend_from_slice(&0x6000_0000u32.to_be_bytes());
    v6.extend_from_slice(&(l4.len() as u16).to_be_bytes());
    v6.push(6);
    v6.push(64);
    let mut src = [0u8; 16];
    src[0] = 0xfd;
    src[15] = ipb[15];
    let mut dst = [0u8; 16];
    dst[0] = 0xfd;
    dst[15] = ipb[19];
    v6.extend_from_slice(&src);
    v6.extend_from_slice(&dst);
    v6.extend_from_slice(l4);
    eth(
        d[6..12].try_into().unwrap(),
        d[0..6].try_into().unwrap(),
        0x86dd,
        &v6,
    )
}
