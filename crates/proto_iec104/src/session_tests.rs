//! Session tests against an in-process mock peer (see
//! [`crate::mockpeer`]). Timers are configured short so the suite stays
//! fast; bounds are generous because tests run in parallel.

use super::*;
use crate::apdu::{
    Apdu, U_STARTDT_ACT, U_STARTDT_CON, U_STOPDT_ACT, U_STOPDT_CON, U_TESTFR_ACT, U_TESTFR_CON,
};
use crate::mockpeer::{asdu_of, blob, cfg, free_port, gi_act, is_i, is_u, sp_asdu, Peer, Running};
use protoplay::{Pacing, Role};
use std::net::{Ipv4Addr, TcpListener};
use std::time::{Duration, Instant};

const MS: Duration = Duration::from_millis(1);

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn listener() -> (TcpListener, u16) {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

/// Master side of a peer: answer STARTDT act.
fn server_handshake(p: &mut Peer) {
    let a = p.recv(ms(3000)).expect("STARTDT act");
    assert!(is_u(&a, U_STARTDT_ACT), "{a:?}");
    p.send_u(U_STARTDT_CON);
}

/// Slave side: send STARTDT act, expect con.
fn master_handshake(p: &mut Peer) {
    p.send_u(U_STARTDT_ACT);
    let a = p
        .recv_until(ms(3000), |a| is_u(a, U_STARTDT_CON))
        .expect("STARTDT con");
    assert!(is_u(&a, U_STARTDT_CON));
}

fn kinds(rep: &ProtoReport) -> Vec<String> {
    rep.protocol
        .protocol_errors
        .iter()
        .map(|e| e.kind.clone())
        .collect()
}

fn cot(asdu: &[u8]) -> u8 {
    asdu[2] & 0x3f
}

// ---------------------------------------------------------------------
// Master
// ---------------------------------------------------------------------

/// F000/F024/F141/F005/F001: during a pacing gap the master answers
/// TESTFR at once, acknowledges the server's I-frame after t2, and the
/// ack latency of an immediately acknowledged frame excludes the gap.
/// The session ends with STOPDT and a FIN.
#[test]
fn master_pacing_services_peer_during_gap() {
    let (l, port) = listener();
    let mut c = cfg(Role::Master, port, blob(&[sp_asdu(1, 1), sp_asdu(2, 1)]));
    c.pacing = Pacing::OriginalTiming { speed: 1.0 };
    c.frame_times_ns = vec![0, 1_500_000_000];
    c.proto_config = Some(r#"{"session":{"t1":3,"t2":0.5,"t3":10}}"#.into());
    let run = Running::spawn(c);
    let mut p = Peer::accept(&l);
    server_handshake(&mut p);

    let f0 = p.recv(ms(2000)).expect("I-frame 0");
    assert!(is_i(&f0));
    let t_f0 = Instant::now();
    // Acknowledge frame 0 at once (piggybacked) and probe the link.
    p.send_i(sp_asdu(7, 0));
    p.send_u(U_TESTFR_ACT);
    let t = Instant::now();
    p.recv_until(ms(1000), |a| is_u(a, U_TESTFR_CON))
        .expect("TESTFR con during the gap");
    assert!(t.elapsed() < ms(400), "TESTFR con after {:?}", t.elapsed());
    // Our single I-frame (< w) is acknowledged by t2, mid-gap.
    let s = p
        .recv_until(ms(1200), |a| matches!(a, Apdu::S { .. }))
        .expect("S-frame from t2");
    let waited = t.elapsed();
    assert!(matches!(s, Apdu::S { nr: 1 }), "{s:?}");
    assert!(
        waited >= ms(350) && waited < ms(1000),
        "t2 S-frame after {waited:?}"
    );
    // Frame 1 keeps its original 1.5 s offset.
    let f1 = p.recv_until(ms(2500), is_i).expect("I-frame 1");
    assert!(
        t_f0.elapsed() >= ms(1300),
        "frame 1 early: {:?}",
        t_f0.elapsed()
    );
    let _ = f1;
    p.ack();
    p.recv_until(ms(3000), |a| is_u(a, U_STOPDT_ACT))
        .expect("STOPDT act");
    p.send_u(U_STOPDT_CON);
    assert!(p.sees_fin(ms(1500)), "no FIN after the session ended");

    let (rep, _, _) = run.join_within(ms(5000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.messages_sent, 2);
    assert_eq!(rep.messages_received, 1);
    assert_eq!(rep.latency_samples_us.len(), 2);
    assert!(
        rep.latency_samples_us[0] < 300_000,
        "ack latency of frame 0 includes the gap: {:?}",
        rep.latency_samples_us
    );
    assert_eq!(rep.protocol.protocol_violations, 0, "{:?}", kinds(&rep));
    assert!(rep.protocol.acks_sent >= 1);
}

/// F004/F023/F145: cancel during a long pacing wait returns promptly
/// and closes the connection (FIN).
#[test]
fn master_cancel_during_pace_sends_fin() {
    let (l, port) = listener();
    let mut c = cfg(Role::Master, port, blob(&[sp_asdu(1, 1), sp_asdu(2, 1)]));
    c.pacing = Pacing::OriginalTiming { speed: 1.0 };
    c.frame_times_ns = vec![0, 30_000_000_000];
    let run = Running::spawn(c);
    let mut p = Peer::accept(&l);
    server_handshake(&mut p);
    p.recv(ms(2000)).expect("I-frame 0");
    p.ack();
    std::thread::sleep(ms(200));
    run.cancel();
    let t = Instant::now();
    assert!(p.sees_fin(ms(1500)), "no FIN after cancel");
    assert!(t.elapsed() < ms(1000));
    let (rep, _, _) = run.join_within(ms(2000));
    let err = rep.error.unwrap_or_default();
    assert!(err.contains("cancelled") && err.contains("idx 1"), "{err}");
}

/// F001/F006: before STOPDT the master acknowledges the server's
/// outstanding I-frames; a missing STOPDT con is a recorded t1 expiry
/// that closes the link without failing a complete run.
#[test]
fn master_flushes_ack_before_stopdt_and_times_out_con() {
    let (l, port) = listener();
    let mut c = cfg(Role::Master, port, blob(&[sp_asdu(1, 1)]));
    c.proto_config = Some(r#"{"session":{"t1":0.8,"t2":0.7,"t3":10}}"#.into());
    let run = Running::spawn(c);
    let mut p = Peer::accept(&l);
    server_handshake(&mut p);
    p.recv(ms(2000)).expect("I-frame 0");
    // Two server I-frames; the second acknowledges frame 0.
    p.send(&Apdu::I {
        ns: 0,
        nr: 0,
        asdu: sp_asdu(5, 1),
    });
    p.send(&Apdu::I {
        ns: 1,
        nr: 1,
        asdu: sp_asdu(6, 1),
    });
    let a = p.recv(ms(500)).expect("S-frame flush");
    assert!(
        matches!(a, Apdu::S { nr: 2 }),
        "expected S(2) first, got {a:?}"
    );
    let a = p.recv(ms(500)).expect("STOPDT act");
    assert!(is_u(&a, U_STOPDT_ACT), "{a:?}");
    // No con: t1 (0.8 s) expires and the master closes.
    assert!(p.sees_fin(ms(2000)));
    let (rep, _, _) = run.join_within(ms(2000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(kinds(&rep), vec!["t1_timeout".to_string()]);
}

/// The k-window stalls the sender until the server acknowledges.
#[test]
fn windowed_send_blocks_until_server_acks() {
    let (l, port) = listener();
    let payload: Vec<Vec<u8>> = (0..15).map(|i| sp_asdu(i, 1)).collect();
    let run = Running::spawn(cfg(Role::Master, port, blob(&payload)));
    let mut p = Peer::accept(&l);
    server_handshake(&mut p);
    for _ in 0..12 {
        assert!(is_i(&p.recv(ms(2000)).expect("I-frame")));
    }
    // Window full: nothing more may arrive.
    assert!(p.recv(ms(150)).is_none(), "13th frame sent with k=12");
    p.ack();
    for _ in 0..3 {
        assert!(is_i(&p.recv(ms(2000)).expect("I-frame")));
    }
    p.ack();
    p.recv_until(ms(2000), |a| is_u(a, U_STOPDT_ACT))
        .expect("STOPDT");
    p.send_u(U_STOPDT_CON);
    let live = run.progress.ack_latency.clone();
    let (rep, _, _) = run.join_within(ms(3000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.messages_sent, 15);
    assert!(rep.window_stalls >= 1);
    // The live histogram saw every retired frame as it was acked.
    let h = live.snapshot();
    assert_eq!(h.total(), 15);
    let reservoir = protoplay::LiveLatencyHist::default();
    for &us in &rep.latency_samples_us {
        reservoir.record_us(us);
    }
    assert_eq!(h, reservoir.snapshot(), "live and final samples bin alike");
    assert!(h.quantile_us(0.99).unwrap() >= 100_000);
    assert_eq!(rep.latency_samples_us.len(), 15);
    let slow = rep
        .latency_samples_us
        .iter()
        .filter(|&&us| us >= 100_000)
        .count();
    assert!(slow >= 12, "{:?}", rep.latency_samples_us);
    assert_eq!(rep.unacked_at_end, 0);
    assert!(rep.latency_p99_us >= rep.latency_p50_us);
}

/// F009: the report says how the peer acknowledged: a full window w,
/// its t2 timer (fewer than w, after t2), or N(R) on its own data.
#[test]
fn peer_ack_cadence_is_classified() {
    let (l, port) = listener();
    let payload: Vec<Vec<u8>> = (0..9).map(|i| sp_asdu(i, 1)).collect();
    let mut c = cfg(Role::Master, port, blob(&payload));
    c.proto_config = Some(r#"{"session":{"k":12,"w":4,"t1":5,"t2":0.3,"t3":30}}"#.into());
    let run = Running::spawn(c);
    let mut p = Peer::accept(&l);
    server_handshake(&mut p);
    let mut got = 0;
    let mut recv_i = |p: &mut Peer, n: usize| {
        while got < n {
            if is_i(&p.recv(ms(3000)).expect("I-frame")) {
                got += 1;
            }
        }
    };
    recv_i(&mut p, 4);
    p.ack(); // 4 frames: a full window
    recv_i(&mut p, 8);
    p.send_i(sp_asdu(100, 1)); // N(R) on our own data: 4 frames
    recv_i(&mut p, 9);
    std::thread::sleep(ms(320));
    p.ack(); // 1 frame after t2: the timer
    p.recv_until(ms(3000), |a| is_u(a, U_STOPDT_ACT))
        .expect("STOPDT");
    p.send_u(U_STOPDT_CON);
    let (rep, _, _) = run.join_within(ms(3000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    let a = rep.protocol.ack_cadence;
    assert_eq!(a.messages_acked, 9, "{a:?}");
    assert_eq!(a.standalone_acks, 2, "{a:?}");
    assert_eq!(a.window_acks, 1, "{a:?}");
    assert_eq!(a.below_window_acks, 1, "{a:?}");
    assert_eq!(a.timer_acks, 1, "{a:?}");
    assert_eq!(a.piggybacked_acks, 1, "{a:?}");
    assert_eq!(a.max_messages_per_ack, 4, "{a:?}");
}

/// F008/F147/F010: 15-bit wraparound of V(S) and of the peer's N(R),
/// over 32768+ frames in fast mode.
#[test]
fn master_sequence_wraps_past_32767() {
    const N: u16 = 32_800;
    let (l, port) = listener();
    let payload: Vec<Vec<u8>> = (0..N).map(|i| sp_asdu(i, 1)).collect();
    let run = Running::spawn(cfg(Role::Master, port, blob(&payload)));
    let mut p = Peer::accept(&l);
    server_handshake(&mut p);
    let mut got = 0u32;
    while got < u32::from(N) {
        // recv() asserts the N(S) sequence, including 32767 -> 0.
        let a = p.recv(ms(3000)).expect("I-frame");
        if is_i(&a) {
            got += 1;
            if p.unacked >= 8 {
                p.ack();
            }
        }
    }
    p.ack();
    p.recv_until(ms(3000), |a| is_u(a, U_STOPDT_ACT))
        .expect("STOPDT");
    p.send_u(U_STOPDT_CON);
    let (rep, _, _) = run.join_within(ms(5000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.messages_sent, u64::from(N));
    assert_eq!(rep.protocol.protocol_violations, 0, "{:?}", kinds(&rep));
    assert_eq!(rep.unacked_at_end, 0);
    assert_eq!(p.vr, N & 0x7fff);
}

// ---------------------------------------------------------------------
// Slave
// ---------------------------------------------------------------------

fn slave(payload: Vec<u8>, proto_config: &str) -> (Running, u16) {
    let port = free_port();
    let mut c = cfg(Role::Slave, port, payload);
    c.proto_config = Some(proto_config.into());
    (Running::spawn(c), port)
}

/// T07b: a slave stopped while still listening (no master ever
/// connected) is cancelled, not failed.
#[test]
fn slave_stopped_while_listening_is_cancelled() {
    let (run, _port) = slave(blob(&[sp_asdu(1, 1)]), "{}");
    let deadline = Instant::now() + ms(3000);
    while run.progress.state.load(Ordering::Relaxed) != session_state::LISTENING {
        assert!(Instant::now() < deadline, "never listened");
        std::thread::sleep(ms(5));
    }
    let state = run.progress.state.clone();
    run.progress.cancel.store(true, Ordering::Relaxed);
    let (rep, _, _) = run.join_within(ms(2000));
    assert_eq!(rep.error.as_deref(), Some("cancelled while listening"));
    assert!(!rep.connected);
    assert_eq!(
        state.load(Ordering::Relaxed),
        session_state::CANCELLED,
        "a never-connected listener must not count as failed"
    );
}

/// T17c: a master that closes (FIN), or resets (RST), its connection
/// before STARTDT leaves the slave listening again; the next master gets
/// the whole script and the session completes. A probe that sends
/// TESTFR first is no different. The dropped connections are counted.
#[test]
fn slave_listens_again_after_master_leaves_before_startdt() {
    let (run, port) = slave(
        blob(&[sp_asdu(1, 1), sp_asdu(2, 0), sp_asdu(3, 1)]),
        r#"{"session":{"t1":3,"t2":1,"idle_serve_secs":0.2}}"#,
    );
    let wait_state = |want: u8| {
        let deadline = Instant::now() + ms(3000);
        while run.progress.state.load(Ordering::Relaxed) != want {
            assert!(Instant::now() < deadline, "state never became {want}");
            std::thread::sleep(ms(5));
        }
    };
    // 1. Connect and close without a word.
    let p = Peer::connect(port);
    wait_state(session_state::CONNECTED);
    drop(p);
    wait_state(session_state::LISTENING);
    // 2. Probe with TESTFR, then reset.
    let mut p = Peer::connect(port);
    p.send_u(U_TESTFR_ACT);
    let a = p.recv(ms(2000)).expect("TESTFR con");
    assert!(is_u(&a, U_TESTFR_CON), "{a:?}");
    p.reset();
    wait_state(session_state::LISTENING);
    // 3. A real master: the full script.
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    for _ in 0..3 {
        assert!(is_i(&p.recv(ms(2000)).expect("I-frame")));
    }
    p.ack();
    assert!(p.sees_fin(ms(3000)), "no FIN after idle-serve");
    let (rep, _, _) = run.join_within(ms(3000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert!(rep.connected);
    assert_eq!(rep.messages_sent, 3);
    assert_eq!(
        rep.messages_received, 0,
        "the probe's TESTFR is not counted"
    );
    assert_eq!(rep.protocol.connections_before_startdt, 2);
    assert_eq!(rep.protocol.protocol_violations, 0, "{:?}", kinds(&rep));
}

/// T17c: a master that connects and stays silent still ends the
/// session at the STARTDT timeout (only a closed connection re-arms
/// the listener), and a stop while listening again is a cancel.
#[test]
fn slave_stopped_after_an_early_close_is_cancelled() {
    let (run, port) = slave(blob(&[sp_asdu(1, 1)]), "{}");
    let p = Peer::connect(port);
    let deadline = Instant::now() + ms(3000);
    while run.progress.state.load(Ordering::Relaxed) != session_state::CONNECTED {
        assert!(Instant::now() < deadline, "never connected");
        std::thread::sleep(ms(5));
    }
    drop(p);
    while run.progress.state.load(Ordering::Relaxed) != session_state::LISTENING {
        assert!(Instant::now() < deadline, "never listened again");
        std::thread::sleep(ms(5));
    }
    let state = run.progress.state.clone();
    run.cancel();
    let (rep, _, _) = run.join_within(ms(2000));
    assert_eq!(rep.error.as_deref(), Some("cancelled while listening"));
    assert_eq!(rep.protocol.connections_before_startdt, 1);
    assert_eq!(state.load(Ordering::Relaxed), session_state::CANCELLED);
}

/// F150: end-to-end slave session: handshake, replay, acks, live GI,
/// idle-serve for `idle_serve_secs`, then close with FIN.
#[test]
fn slave_end_to_end_with_idle_serve_deadline() {
    let (run, port) = slave(
        blob(&[sp_asdu(1, 1), sp_asdu(2, 0), sp_asdu(3, 1)]),
        r#"{"session":{"t1":3,"t2":1,"idle_serve_secs":0.5}}"#,
    );
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    for _ in 0..3 {
        assert!(is_i(&p.recv(ms(2000)).expect("I-frame")));
    }
    p.ack();
    p.send_i(gi_act());
    let mut resp = Vec::new();
    while resp.len() < 3 {
        let a = p.recv_until(ms(1000), is_i).expect("GI response");
        resp.push(asdu_of(&a).unwrap().to_vec());
    }
    p.ack();
    assert_eq!(cot(&resp[0]), 7);
    assert_eq!(cot(&resp[1]), 20);
    assert_eq!(cot(&resp[2]), 10);
    let t = Instant::now();
    assert!(p.sees_fin(ms(2000)), "no FIN after idle-serve");
    let (rep, _, _) = run.join_within(ms(2000));
    assert!(t.elapsed() < ms(1500));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.messages_sent, 6);
    assert_eq!(rep.messages_received, 1);
    assert_eq!(rep.protocol.synthesized_frames, 3);
    assert_eq!(rep.protocol.synthesized_send_indices, vec![3, 4, 5]);
    assert!(
        (300..1500).contains(&rep.protocol.idle_serve_ms),
        "idle {}",
        rep.protocol.idle_serve_ms
    );
    assert_eq!(rep.latency_samples_us.len(), 6);
    assert_eq!(rep.protocol.protocol_violations, 0, "{:?}", kinds(&rep));
}

/// F002/F013/F140/F018: a GI is answered promptly in the middle of a
/// pacing gap and after the script ends; the captured GI burst is not
/// replayed; synthesized frames are tagged.
#[test]
fn slave_gi_answered_mid_gap_and_after_script() {
    let captured = vec![
        sp_asdu(1, 1),
        vec![100, 1, 7, 0, 1, 0, 0, 0, 0, 20], // captured ActCon
        vec![1, 1, 20, 0, 1, 0, 2, 0, 0, 1],   // captured Inrogen
        vec![100, 1, 10, 0, 1, 0, 0, 0, 0, 20], // captured ActTerm
        sp_asdu(3, 0),
    ];
    let port = free_port();
    let mut c = cfg(Role::Slave, port, blob(&captured));
    c.pacing = Pacing::OriginalTiming { speed: 1.0 };
    c.frame_times_ns = vec![0, 100_000_000, 100_000_000, 100_000_000, 1_500_000_000];
    c.proto_config = Some(r#"{"session":{"t1":4,"t2":1}}"#.into());
    let run = Running::spawn(c);
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    let t_script = Instant::now();
    let a = p.recv(ms(1000)).expect("first captured frame");
    assert_eq!(asdu_of(&a).unwrap(), &sp_asdu(1, 1)[..]);

    let mut all = Vec::new();
    // GI in the gap before the frame due at 1.5 s.
    std::thread::sleep(ms(200));
    p.send_i(gi_act());
    let t = Instant::now();
    for _ in 0..3 {
        let a = p.recv_until(ms(1000), is_i).expect("GI response");
        all.push(asdu_of(&a).unwrap().to_vec());
    }
    assert!(t.elapsed() < ms(500), "GI response took {:?}", t.elapsed());
    assert!(t_script.elapsed() < ms(1200));
    p.ack();
    // Then the last captured frame, on time; nothing captured between.
    let a = p.recv_until(ms(2500), is_i).expect("last captured frame");
    assert_eq!(asdu_of(&a).unwrap(), &sp_asdu(3, 0)[..]);
    assert!(t_script.elapsed() >= ms(1300));
    p.ack();
    // Script over: a second GI is still answered.
    std::thread::sleep(ms(200));
    p.send_i(gi_act());
    let t = Instant::now();
    for _ in 0..3 {
        let a = p
            .recv_until(ms(1000), is_i)
            .expect("GI response after script");
        all.push(asdu_of(&a).unwrap().to_vec());
    }
    assert!(t.elapsed() < ms(500));
    p.ack();
    assert!(p.recv(ms(200)).is_none(), "unexpected extra frame");
    drop(p); // master closes: the normal end of idle-serve

    let (rep, _, _) = run.join_within(ms(2000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    let actcon = all.iter().filter(|a| a[0] == 100 && cot(a) == 7).count();
    let actterm = all.iter().filter(|a| a[0] == 100 && cot(a) == 10).count();
    assert_eq!((actcon, actterm), (2, 2));
    // The synthesized data frame carries all three points.
    assert_eq!(all[1][1] & 0x7f, 3);
    assert_eq!(rep.protocol.stripped_capture_frames, 3);
    assert_eq!(rep.protocol.synthesized_frames, 6);
    assert_eq!(
        rep.protocol.synthesized_send_indices,
        vec![1, 2, 3, 5, 6, 7]
    );
    assert_eq!(rep.protocol.command_response_us.len(), 2);
    assert!(rep
        .protocol
        .command_response_us
        .iter()
        .all(|&us| us < 300_000));
    assert_eq!(rep.messages_sent, 8);
}

/// F143: the k-window holds with synthesized frames in the mix.
#[test]
fn slave_never_exceeds_k_with_synthesized_frames() {
    let script: Vec<Vec<u8>> = (0..8).map(|i| sp_asdu(i, 1)).collect();
    let (run, port) = slave(
        blob(&script),
        r#"{"session":{"k":3,"w":2,"t1":5,"t2":1,"idle_serve_secs":0.2}}"#,
    );
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    p.send_i(gi_act());
    let mut got = 0;
    while got < 11 {
        let a = p.recv(ms(2000)).expect("I-frame");
        if !is_i(&a) {
            continue;
        }
        got += 1;
        assert!(p.unacked <= 3, "more than k=3 unacknowledged");
        if p.unacked == 3 {
            // Window full: anything else now would overrun k.
            if let Some(extra) = p.recv(ms(150)) {
                assert!(!is_i(&extra), "I-frame beyond k: {extra:?}");
            }
            p.ack();
        }
    }
    p.ack();
    assert!(p.sees_fin(ms(2000)));
    let (rep, _, _) = run.join_within(ms(2000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.messages_sent, 11);
    assert_eq!(rep.protocol.synthesized_frames, 3);
    assert!(rep.window_stalls >= 1);
}

/// F006/F142: STOPDT mid-session: no con until our I-frames are
/// acknowledged, no I-frames while stopped, resume on STARTDT.
#[test]
fn slave_stopdt_mid_session_then_restart() {
    let script: Vec<Vec<u8>> = (0..6).map(|i| sp_asdu(i, 1)).collect();
    let port = free_port();
    let mut c = cfg(Role::Slave, port, blob(&script));
    c.pacing = Pacing::OriginalTiming { speed: 1.0 };
    c.frame_times_ns = (0..6).map(|i| i * 250_000_000).collect();
    c.proto_config = Some(r#"{"session":{"t1":3,"t2":1}}"#.into());
    let run = Running::spawn(c);
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    assert!(is_i(&p.recv(ms(1000)).unwrap()));
    assert!(is_i(&p.recv(ms(1000)).unwrap()));
    p.send_u(U_STOPDT_ACT);
    // Two I-frames unacknowledged: no con yet.
    assert!(p.recv(ms(300)).is_none(), "STOPDT con before acks");
    p.ack();
    let a = p.recv(ms(500)).expect("STOPDT con");
    assert!(is_u(&a, U_STOPDT_CON), "{a:?}");
    // Stopped: no I-frames even though pacing deadlines pass.
    assert!(p.recv(ms(700)).is_none(), "I-frame while stopped");
    p.send_u(U_STARTDT_ACT);
    p.recv_until(ms(500), |a| is_u(a, U_STARTDT_CON))
        .expect("STARTDT con");
    for _ in 0..4 {
        assert!(is_i(&p.recv(ms(1500)).expect("resumed I-frame")));
    }
    p.ack();
    std::thread::sleep(ms(100));
    drop(p);
    let (rep, _, _) = run.join_within(ms(2000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.messages_sent, 6);
    assert_eq!(rep.protocol.protocol_violations, 0, "{:?}", kinds(&rep));
}

/// F006: a duplicate STARTDT act is confirmed again.
#[test]
fn slave_duplicate_startdt_is_confirmed() {
    let (run, port) = slave(
        blob(&[sp_asdu(1, 1), sp_asdu(2, 1), sp_asdu(3, 1)]),
        r#"{"session":{"t1":3,"t2":1}}"#,
    );
    let mut p = Peer::connect(port);
    p.send_u(U_STARTDT_ACT);
    p.send_u(U_STARTDT_ACT);
    let (mut cons, mut frames) = (0, 0);
    while let Some(a) = p.recv(ms(500)) {
        if is_u(&a, U_STARTDT_CON) {
            cons += 1;
        } else if is_i(&a) {
            frames += 1;
        }
    }
    assert_eq!((cons, frames), (2, 3));
    p.ack();
    std::thread::sleep(ms(100));
    drop(p);
    let (rep, _, _) = run.join_within(ms(2000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.protocol.protocol_violations, 0);
}

/// F001: a lone received I-frame (< w) is acknowledged after t2. Also
/// F144/F003: an empty script with loop-forever goes straight to
/// idle-serve (TESTFR, GI answered) without spinning, and cancel ends
/// it cleanly with a FIN.
#[test]
fn slave_empty_script_idle_serves_without_spinning() {
    let port = free_port();
    let mut c = cfg(Role::Slave, port, Vec::new());
    c.loop_iterations = 0;
    // Command echo off: the command must not be answered here.
    c.proto_config =
        Some(r#"{"session":{"t1":2,"t2":0.4,"t3":30},"commands":{"enabled":false}}"#.into());
    let run = Running::spawn(c);
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    // Single command, then silence: S-frame at t2.
    p.send_i(vec![45, 1, 6, 0, 1, 0, 1, 0, 0, 1]);
    let t = Instant::now();
    let s = p
        .recv_until(ms(1500), |a| matches!(a, Apdu::S { .. }))
        .expect("t2 S-frame");
    assert!(matches!(s, Apdu::S { nr: 1 }), "{s:?}");
    assert!(
        t.elapsed() >= ms(300) && t.elapsed() < ms(1000),
        "t2 ack after {:?}",
        t.elapsed()
    );
    p.send_u(U_TESTFR_ACT);
    p.recv_until(ms(300), |a| is_u(a, U_TESTFR_CON))
        .expect("TESTFR con");
    // Empty inventory: the GI gets a negative (unknown CA) mirror.
    p.send_i(gi_act());
    let a = p.recv_until(ms(300), is_i).expect("GI answer");
    assert_eq!(cot(asdu_of(&a).unwrap()), 46);
    p.ack();
    std::thread::sleep(ms(700));
    assert_eq!(
        run.progress
            .iter_current
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    run.cancel();
    assert!(p.sees_fin(ms(1000)), "no FIN on cancel");
    let (rep, wall, cpu) = run.join_within(ms(1000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert!(
        cpu < wall / 5,
        "idle session burned {cpu:?} CPU in {wall:?}"
    );
}

/// F003/F025: loop-forever, master acknowledges then disconnects: the
/// session ends on its own, promptly, with an error and no spin.
#[test]
fn slave_loop_forever_exits_after_master_disconnect() {
    let port = free_port();
    let mut c = cfg(
        Role::Slave,
        port,
        blob(&[sp_asdu(1, 1), sp_asdu(2, 1), sp_asdu(3, 1)]),
    );
    c.loop_iterations = 0;
    let run = Running::spawn(c);
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    let mut n = 0;
    while n < 6 {
        if is_i(&p.recv(ms(1000)).expect("I-frame")) {
            n += 1;
        }
    }
    p.ack();
    std::thread::sleep(ms(50));
    drop(p);
    let (rep, _, cpu) = run.join_within(ms(1500));
    let err = rep.error.clone().unwrap_or_default();
    assert!(err.contains("peer closed"), "{err}");
    assert!(cpu < ms(500), "CPU {cpu:?}");
    let iters = run_iters(&rep);
    assert!(iters < 1000, "{iters}");
}

fn run_iters(rep: &ProtoReport) -> u64 {
    // At most k unacknowledged frames after the master's last ack: a
    // spinning loop would have counted millions of sends.
    rep.messages_sent
}

/// F010: the slave's V(R) wraps past 32767 and N(S) is checked across
/// the wrap.
#[test]
fn slave_receive_sequence_wraps_past_32767() {
    const N: u32 = 32_800;
    let port = free_port();
    let mut c = cfg(Role::Slave, port, Vec::new());
    c.proto_config = Some(r#"{"session":{"t1":5,"t2":1,"t3":30}}"#.into());
    let run = Running::spawn(c);
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    for i in 0..N {
        p.send_i(sp_asdu(i as u16, 1));
        if (i + 1) % 8 == 0 {
            // w=8: one S-frame per 8 I-frames, acknowledging them all.
            let a = p.recv(ms(2000)).expect("S-frame");
            assert!(
                matches!(a, Apdu::S { nr } if nr == p.vs),
                "{a:?} vs {}",
                p.vs
            );
        }
    }
    drop(p);
    let (rep, _, _) = run.join_within(ms(3000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.messages_received, u64::from(N));
    assert_eq!(rep.protocol.protocol_violations, 0, "{:?}", kinds(&rep));
}

/// F008/F147: wrong N(S) from the peer is a protocol error that closes
/// the connection.
#[test]
fn slave_rejects_ns_out_of_sequence() {
    let (run, port) = slave(Vec::new(), r#"{"session":{"t1":3,"t2":1}}"#);
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    p.vs = 5;
    p.send_i(sp_asdu(1, 1));
    assert!(p.sees_fin(ms(1000)));
    let (rep, _, _) = run.join_within(ms(1000));
    assert_eq!(kinds(&rep), vec!["ns_mismatch".to_string()]);
    assert!(rep.protocol.protocol_errors[0].fatal);
    assert!(rep.protocol.protocol_errors[0].detail.contains("N(S)=5"));
    assert!(rep.error.unwrap_or_default().contains("protocol violation"));
}

/// F008/F147: an N(R) acknowledging frames never sent is a protocol
/// error that closes the connection.
#[test]
fn slave_rejects_nr_beyond_vs() {
    let (run, port) = slave(
        blob(&[sp_asdu(1, 1), sp_asdu(2, 1)]),
        r#"{"session":{"t1":3,"t2":1}}"#,
    );
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    assert!(is_i(&p.recv(ms(1000)).unwrap()));
    assert!(is_i(&p.recv(ms(1000)).unwrap()));
    p.send(&Apdu::S { nr: 40 });
    assert!(p.sees_fin(ms(1000)));
    let (rep, _, _) = run.join_within(ms(1000));
    assert_eq!(kinds(&rep), vec!["nr_out_of_window".to_string()]);
    assert!(rep.error.unwrap_or_default().contains("protocol violation"));
}

/// F008 / live framing: junk between frames is a framing error, not
/// something to skip.
#[test]
fn slave_rejects_malformed_frame() {
    let (run, port) = slave(Vec::new(), r#"{"session":{"t1":3,"t2":1}}"#);
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    use std::io::Write as _;
    p.s.write_all(&[0x00, 0x68, 4, 0x01, 0, 0, 0]).unwrap();
    assert!(p.sees_fin(ms(1000)));
    let (rep, _, _) = run.join_within(ms(1000));
    assert_eq!(kinds(&rep), vec!["malformed_frame".to_string()]);
}

/// F142: t3 idle sends TESTFR act; a missing con closes after t1.
#[test]
fn slave_t3_testfr_then_t1_close() {
    let (run, port) = slave(Vec::new(), r#"{"session":{"t1":0.6,"t2":0.3,"t3":0.4}}"#);
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    let t = Instant::now();
    let a = p.recv(ms(1500)).expect("TESTFR act");
    assert!(is_u(&a, U_TESTFR_ACT), "{a:?}");
    assert!(
        t.elapsed() >= ms(300) && t.elapsed() < ms(900),
        "t3 after {:?}",
        t.elapsed()
    );
    p.send_u(U_TESTFR_CON);
    let a = p.recv(ms(1500)).expect("second TESTFR act");
    assert!(is_u(&a, U_TESTFR_ACT));
    // No con this time.
    let t = Instant::now();
    assert!(p.sees_fin(ms(2000)), "no close after t1");
    assert!(
        t.elapsed() >= ms(400),
        "closed before t1: {:?}",
        t.elapsed()
    );
    let (rep, _, _) = run.join_within(ms(1000));
    assert_eq!(rep.protocol.keepalives_sent, 2);
    assert_eq!(kinds(&rep), vec!["t1_timeout".to_string()]);
    assert!(rep.error.unwrap_or_default().contains("t1 expired"));
}

// ---------------------------------------------------------------------
// Script extraction
// ---------------------------------------------------------------------

fn frame(ns: u16, asdu: Vec<u8>) -> Vec<u8> {
    Apdu::I { ns, nr: 0, asdu }.serialize()
}

/// Gap awareness: a frame spliced from bytes on both sides of a capture
/// gap passes the whole-stream framer but is never put in the script;
/// the frames around it keep their pacing indices.
#[test]
fn extract_script_restarts_framing_at_capture_gaps() {
    let f: Vec<Vec<u8>> = (0..4).map(|i| frame(i, sp_asdu(i + 1, 1))).collect();
    let len = f[1].len();
    assert_eq!(len, f[2].len());
    // Lose f1[10..] and f2[..10]: the splice f1[..10] + f2[10..] has
    // f1's header and length and ends right before f3's 0x68.
    let mut stream = f[0].clone();
    let gap = stream.len() + 10;
    stream.extend_from_slice(&f[1][..10]);
    stream.extend_from_slice(&f[2][10..]);
    stream.extend_from_slice(&f[3]);
    let spliced: Vec<u8> = [&f[1][6..10], &f[2][10..]].concat();
    let whole: Vec<Vec<u8>> = crate::apci::frames(&stream)
        .filter_map(|fr| fr.asdu().map(<[u8]>::to_vec))
        .collect();
    assert!(
        whole.contains(&spliced),
        "test premise: framer accepts splice"
    );

    let mut c = cfg(Role::Master, 0, stream.clone());
    let no_gaps = extract_script(&c, "test");
    assert_eq!(no_gaps.frames.len(), 3);
    c.capture_gaps = vec![gap];
    let s = extract_script(&c, "test");
    let asdus: Vec<&Vec<u8>> = s.frames.iter().map(|f| &f.asdu).collect();
    assert_eq!(asdus, vec![&sp_asdu(1, 1), &sp_asdu(4, 1)]);
    assert!(!asdus.contains(&&spliced));
    assert_eq!(
        s.frames.iter().map(|f| f.time_idx).collect::<Vec<_>>(),
        vec![0, 2]
    );
    assert_eq!(s.gaps, 1);
    assert_eq!(s.dropped_frames, 1);
    assert!(s.skipped_bytes > 0);
    let mut rep = ProtoReport::default();
    s.record(&mut rep);
    assert_eq!(rep.protocol.script_dropped_frames, 1);
}

#[test]
fn resync_skips_leading_partial_frame_bytes() {
    let mut clean = Vec::new();
    for ns in 0..3u16 {
        clean.extend_from_slice(&frame(
            ns,
            vec![
                0x65, 0x01, 0x06, 0x00, 0x01, 0x00, ns as u8, 0x00, 0x00, 0x00,
            ],
        ));
    }
    // Junk prefix including one 0x68 that does not start a frame.
    let mut junk = vec![0x42, 0x68, 0xff, 0x00, 0x07, 0x99, 0xaa];
    junk.extend_from_slice(&clean);
    assert_eq!(crate::apci::find_resync(&junk), 7);
    let c = cfg(Role::Master, 0, junk);
    let s = extract_script(&c, "test");
    assert_eq!(s.frames.len(), 3);
    assert_eq!(s.skipped_bytes, 7);
    let _ = MS;
}

/// Security: GI/CI activations are only answered in the started state,
/// and a repeated GI while one is being answered gets a negative ActCon
/// instead of a second full response.
#[test]
fn slave_answers_gi_only_when_started_and_rejects_duplicates() {
    let (run, port) = slave(
        blob(&[sp_asdu(1, 1)]),
        r#"{"session":{"k":1,"w":1,"t1":3,"t2":0.5,"t3":30}}"#,
    );
    let mut p = Peer::connect(port);
    // Before STARTDT: ignored (acknowledged, never answered).
    p.send_i(gi_act());
    master_handshake(&mut p);
    let a = p.recv_until(ms(1000), is_i).expect("script frame");
    assert_eq!(asdu_of(&a).unwrap(), &sp_asdu(1, 1)[..]);
    // Window (k=1) full: GI #1 queues a full response, #2 and #3 are
    // rejected while it is outstanding.
    p.send_i(gi_act());
    p.send_i(gi_act());
    p.send_i(gi_act());
    std::thread::sleep(ms(100));
    let mut out = Vec::new();
    while out.len() < 5 {
        p.ack();
        let a = p.recv_until(ms(1000), is_i).expect("response frame");
        out.push(asdu_of(&a).unwrap().to_vec());
    }
    p.ack();
    assert!(p.recv_until(ms(300), is_i).is_none(), "extra I-frame");
    drop(p);
    let (rep, _, _) = run.join_within(ms(2000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    let cots: Vec<u8> = out.iter().map(|a| a[2]).collect();
    assert_eq!(cots, vec![7, 20, 10, 0x47, 0x47]);
    assert_eq!(rep.protocol.synthesized_frames, 5);
    assert_eq!(rep.protocol.command_response_us.len(), 3);
    assert_eq!(rep.messages_received, 4);
}

/// `{"gi_ci_synthesis": false}`: captured bursts are replayed verbatim
/// and live GI/CI is not answered.
#[test]
fn slave_synthesis_off_replays_captured_bursts() {
    let captured = vec![
        sp_asdu(1, 1),
        vec![100, 1, 7, 0, 1, 0, 0, 0, 0, 20],
        vec![1, 1, 20, 0, 1, 0, 2, 0, 0, 1],
        vec![100, 1, 10, 0, 1, 0, 0, 0, 0, 20],
    ];
    let (run, port) = slave(
        blob(&captured),
        r#"{"gi_ci_synthesis":false,"session":{"t1":3,"t2":0.5,"idle_serve_secs":0.3}}"#,
    );
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    let mut got = Vec::new();
    while got.len() < 4 {
        let a = p.recv_until(ms(1000), is_i).expect("captured frame");
        got.push(asdu_of(&a).unwrap().to_vec());
    }
    p.ack();
    p.send_i(gi_act());
    assert!(p.recv_until(ms(250), is_i).is_none(), "GI answered");
    assert!(p.sees_fin(ms(2000)));
    let (rep, _, _) = run.join_within(ms(2000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(got, captured);
    assert_eq!(rep.protocol.stripped_capture_frames, 0);
    assert_eq!(rep.protocol.synthesized_frames, 0);
}
