//! Re-audit fixes (T17): a master whose peer hangs up on unacknowledged
//! frames fails (N1), a flooding peer cannot overflow the receive
//! counter while acks are withheld (N3), a master connect and a stalled
//! write can be cancelled (F028), and a lost first segment is a counted
//! gap (N19).

use super::*;
use crate::apdu::{Apdu, U_STARTDT_ACT, U_STARTDT_CON};
use crate::mockpeer::{blob, cfg, free_port, is_i, is_u, sp_asdu, Peer, Running};
use protoplay::Role;
use std::net::{Ipv4Addr, TcpListener};
use std::time::{Duration, Instant};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn listener() -> (TcpListener, u16) {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

fn server_handshake(p: &mut Peer) {
    let a = p.recv(ms(3000)).expect("STARTDT act");
    assert!(is_u(&a, U_STARTDT_ACT), "{a:?}");
    p.send_u(U_STARTDT_CON);
}

/// N1: the server takes the script and hangs up without acknowledging
/// it. Before, the master reported success; staying open would have
/// been a t1 failure.
#[test]
fn master_fails_when_the_peer_closes_on_unacked_frames() {
    let (l, port) = listener();
    let payload: Vec<Vec<u8>> = (0..3).map(|i| sp_asdu(i, 1)).collect();
    let run = Running::spawn(cfg(Role::Master, port, blob(&payload)));
    let mut p = Peer::accept(&l);
    server_handshake(&mut p);
    for _ in 0..3 {
        assert!(is_i(&p.recv(ms(2000)).expect("I-frame")));
    }
    drop(p);
    let (rep, _, _) = run.join_within(ms(3000));
    let err = rep.error.expect("session error");
    assert!(
        err.contains("peer closed") && err.contains("3 I-frame(s) unacknowledged"),
        "{err}"
    );
    assert_eq!(rep.unacked_at_end, 3);
}

/// N1, the other half: everything acknowledged, then the server hangs
/// up instead of answering STOPDT. Nothing was lost: no error.
#[test]
fn master_succeeds_when_the_peer_closes_after_acking_everything() {
    let (l, port) = listener();
    let payload: Vec<Vec<u8>> = (0..3).map(|i| sp_asdu(i, 1)).collect();
    let run = Running::spawn(cfg(Role::Master, port, blob(&payload)));
    let mut p = Peer::accept(&l);
    server_handshake(&mut p);
    for _ in 0..3 {
        assert!(is_i(&p.recv(ms(2000)).expect("I-frame")));
    }
    p.ack();
    drop(p);
    let (rep, _, _) = run.join_within(ms(3000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.unacked_at_end, 0);
}

/// N3: with acks withheld, a master that ignores its own k sends more
/// than 65535 I-frames in a row. The receive counter saturates instead
/// of overflowing (a panic in debug builds), and the session ends
/// normally when the master hangs up.
#[test]
fn withheld_acks_survive_a_flood_beyond_u16() {
    let port = free_port();
    let mut c = cfg(Role::Slave, port, blob(&[sp_asdu(1, 1)]));
    c.proto_config = Some(
        r#"{"gi_ci_synthesis":false,"commands":{"enabled":false},
            "session":{"t1":30,"t2":20,"t3":60,"idle_serve_secs":60},
            "faults":[{"at":{"ms":0},"kind":"withhold_acks","duration_ms":600000}]}"#
            .into(),
    );
    let run = Running::spawn(c);
    let mut p = Peer::connect(port);
    p.send_u(U_STARTDT_ACT);
    p.recv_until(ms(3000), |a| is_u(a, U_STARTDT_CON))
        .expect("STARTDT con");
    p.recv_until(ms(3000), is_i).expect("script frame");
    // One write of 70 000 back-to-back I-frames.
    let mut flood = Vec::new();
    for i in 0..70_000u32 {
        flood.extend(
            Apdu::I {
                ns: (i & 0x7fff) as u16,
                nr: 1,
                asdu: sp_asdu((i & 0xffff) as u16, 1),
            }
            .serialize(),
        );
    }
    std::io::Write::write_all(&mut p.s, &flood).unwrap();
    // Wait until the slave has read all of them, then hang up.
    let deadline = Instant::now() + Duration::from_secs(60);
    while run
        .progress
        .received
        .load(std::sync::atomic::Ordering::Relaxed)
        < 70_000
    {
        assert!(Instant::now() < deadline, "flood not consumed");
        std::thread::sleep(ms(20));
    }
    drop(p);
    let (rep, _, _) = run.join_within(ms(5000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.messages_received, 70_000);
}

/// F028: a master connect that would wait out t0 (the target's accept
/// queue is full, so the SYN is never answered) stops within a slice of
/// the cancel.
#[test]
fn master_connect_is_cancellable() {
    use socket2::{Domain, Socket, Type};
    let srv = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    srv.bind(&std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
        .unwrap();
    srv.listen(0).unwrap();
    let addr = srv.local_addr().unwrap().as_socket().unwrap();
    // Fill the (never drained) accept queue; later SYNs are dropped.
    let mut fillers = Vec::new();
    for _ in 0..4 {
        let s = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        s.set_nonblocking(true).unwrap();
        let _ = s.connect(&addr.into());
        fillers.push(s);
    }
    std::thread::sleep(ms(200));

    let mut c = cfg(Role::Master, addr.port(), blob(&[sp_asdu(1, 1)]));
    c.proto_config = Some(r#"{"session":{"t0":120}}"#.into());
    let run = Running::spawn(c);
    std::thread::sleep(ms(500));
    assert!(!run.handle.is_finished(), "connect did not hang (premise)");
    run.cancel();
    let t = Instant::now();
    let (rep, _, _) = run.join_within(ms(2000));
    assert!(t.elapsed() < ms(1000), "cancel took {:?}", t.elapsed());
    let err = rep.error.unwrap_or_default();
    assert!(err.contains("cancelled while connecting"), "{err}");
    assert!(!rep.connected);
}

/// F028: a peer that completes STARTDT and then stops reading cannot
/// hang a STOP: the blocked write is retried in slices, each after a
/// cancel check.
#[test]
fn stalled_write_is_cancellable() {
    use socket2::{Domain, Socket, Type};
    let srv = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    srv.set_recv_buffer_size(4096).unwrap();
    srv.bind(&std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
        .unwrap();
    srv.listen(4).unwrap();
    let l: TcpListener = srv.into();
    let port = l.local_addr().unwrap().port();
    // 30 000 frames of ~255 bytes with k = 32767: far more than the
    // socket buffers hold (the receive buffer is shrunk before the
    // connection exists), so the writer blocks.
    let big: Vec<u8> = (0..240u8).collect();
    let asdu = [vec![1, 1, 3, 0, 1, 0, 1, 0, 0], big].concat();
    let payload: Vec<Vec<u8>> = (0..30_000).map(|_| asdu.clone()).collect();
    let mut c = cfg(Role::Master, port, blob(&payload));
    c.proto_config = Some(r#"{"session":{"k":32767,"w":8,"t1":120,"t2":10}}"#.into());
    let run = Running::spawn(c);
    let (s, _) = l.accept().unwrap();
    let mut p = Peer::from_stream(s);
    server_handshake(&mut p);
    // Stop reading; wait until the session is stuck in a write.
    let mut last = 0;
    loop {
        std::thread::sleep(ms(300));
        let now = run
            .progress
            .bytes_written
            .load(std::sync::atomic::Ordering::Relaxed);
        if now == last {
            break;
        }
        last = now;
    }
    assert!(last < 30_000 * 255, "writer never blocked (premise)");
    run.cancel();
    let t = Instant::now();
    let (rep, _, _) = run.join_within(ms(3000));
    assert!(t.elapsed() < ms(1500), "stop took {:?}", t.elapsed());
    assert!(rep.error.unwrap_or_default().contains("cancelled"));
    drop(p);
}

/// F028: t0 above the IEC maximum of 255 s is refused.
#[test]
fn t0_is_capped_at_255_seconds() {
    let ok = crate::asdu::Iec104ProtoConfig::parse(Some(r#"{"session":{"t0":255}}"#));
    assert!(ok.is_ok(), "{ok:?}");
    let e = crate::asdu::Iec104ProtoConfig::parse(Some(r#"{"session":{"t0":256}}"#))
        .unwrap_err()
        .to_string();
    assert!(e.contains("t0 must be <= 255"), "{e}");
}

/// N19: a SYN-anchored stream whose first segment was lost has its gap
/// at offset 0. It splits no frame but is still counted.
#[test]
fn a_lost_first_segment_is_a_counted_gap() {
    let stream = blob(&[sp_asdu(1, 1), sp_asdu(2, 1)]);
    let mut c = cfg(Role::Master, 0, stream);
    c.capture_gaps = vec![0];
    let s = extract_script(&c, "test");
    assert_eq!(s.gaps, 1);
    assert_eq!(s.frames.len(), 2);
    c.capture_gaps = vec![0, 0, 16];
    assert_eq!(extract_script(&c, "test").gaps, 2);
    c.capture_gaps = vec![];
    assert_eq!(extract_script(&c, "test").gaps, 0);
}
