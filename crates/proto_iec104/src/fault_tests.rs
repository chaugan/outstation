//! Fault injection (`proto_config.faults`) against the in-process mock
//! peer: one test per fault kind, each also checking the recorded
//! fault and the detected peer reaction.

use super::*;
use crate::apdu::{
    Apdu, U_STARTDT_ACT, U_STARTDT_CON, U_STOPDT_ACT, U_STOPDT_CON, U_TESTFR_ACT, U_TESTFR_CON,
};
use crate::mockpeer::{asdu_of, blob, cfg, free_port, gi_act, is_i, is_u, sp_asdu, Peer, Running};
use protoplay::{FaultReaction, Pacing, Role};
use std::net::{Ipv4Addr, TcpListener};
use std::time::{Duration, Instant};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn script(n: u16) -> Vec<u8> {
    blob(&(0..n).map(|i| sp_asdu(i, 1)).collect::<Vec<_>>())
}

fn slave(payload: Vec<u8>, proto_config: &str) -> (Running, u16) {
    let port = free_port();
    let mut c = cfg(Role::Slave, port, payload);
    c.proto_config = Some(proto_config.into());
    (Running::spawn(c), port)
}

fn master_handshake(p: &mut Peer) {
    p.send_u(U_STARTDT_ACT);
    p.recv_until(ms(3000), |a| is_u(a, U_STARTDT_CON))
        .expect("STARTDT con");
}

fn server_handshake(p: &mut Peer) {
    let a = p.recv(ms(3000)).expect("STARTDT act");
    assert!(is_u(&a, U_STARTDT_ACT), "{a:?}");
    p.send_u(U_STARTDT_CON);
}

fn listener() -> (TcpListener, u16) {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

fn reaction(rep: &ProtoReport) -> &FaultReaction {
    rep.protocol
        .fault_reaction
        .as_ref()
        .expect("fault_reaction recorded")
}

fn only_fault(rep: &ProtoReport, kind: &str) -> u64 {
    let f = &rep.protocol.faults_injected;
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].kind, kind);
    f[0].frames_affected
}

/// `withhold_acks`: no S-frame and a frozen N(R) while the window is
/// open, then the overdue acknowledgement. The master closing is
/// recorded as the reaction, not as a session error.
#[test]
fn withhold_acks_freezes_nr_then_acks() {
    let port = free_port();
    let mut c = cfg(Role::Slave, port, script(2));
    c.pacing = Pacing::OriginalTiming { speed: 1.0 };
    c.frame_times_ns = vec![0, 400_000_000];
    c.proto_config = Some(
        r#"{"session":{"t1":3,"t2":0.2,"idle_serve_secs":5},
            "faults":[{"at":{"ms":0},"kind":"withhold_acks","duration_ms":800}]}"#
            .into(),
    );
    let run = Running::spawn(c);
    let t0 = Instant::now();
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    p.recv_until(ms(1000), is_i).expect("frame 0");
    p.send_i(sp_asdu(7, 1));
    p.send_i(sp_asdu(8, 1));
    // Frame 1 at 400 ms repeats N(R) 0; no S-frame inside the window.
    let a = p.recv(ms(1000)).expect("frame 1");
    assert!(matches!(a, Apdu::I { nr: 0, .. }), "{a:?}");
    let s = p
        .recv_until(ms(1500), |a| matches!(a, Apdu::S { .. }))
        .expect("ack after the window");
    assert!(matches!(s, Apdu::S { nr: 2 }), "{s:?}");
    assert!(t0.elapsed() >= ms(750), "acked after {:?}", t0.elapsed());
    p.ack();
    drop(p);
    let (rep, _, _) = run.join_within(ms(3000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(only_fault(&rep, "withhold_acks"), 2);
    assert!(reaction(&rep).peer_closed);
}

/// `drop_iframes`: the dropped frame's N(S) is consumed, so the peer
/// sees a sequence gap; it hangs up, which is the recorded reaction.
#[test]
fn drop_iframes_consumes_ns() {
    let (l, port) = listener();
    let mut c = cfg(Role::Master, port, script(4));
    c.pacing = Pacing::OriginalTiming { speed: 1.0 };
    c.frame_times_ns = vec![0, 0, 0, 300_000_000];
    c.proto_config = Some(
        r#"{"session":{"t1":3,"t2":0.5},
            "faults":[{"at":{"frame":2},"kind":"drop_iframes","pct":100,"duration_ms":100}]}"#
            .into(),
    );
    let run = Running::spawn(c);
    let mut p = Peer::accept(&l);
    p.strict = false;
    server_handshake(&mut p);
    for _ in 0..3 {
        p.recv_until(ms(2000), is_i).expect("I-frame");
    }
    assert_eq!(p.ns_log, vec![0, 1, 3]);
    drop(p); // a conformant slave closes on the sequence error
    let (rep, _, _) = run.join_within(ms(3000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.messages_sent, 3);
    assert_eq!(only_fault(&rep, "drop_iframes"), 1);
    assert!(rep.protocol.faults_injected[0].detail.ends_with("N(S) 2"));
    let r = reaction(&rep);
    assert!(r.peer_closed && !r.peer_reset, "{r:?}");
    assert!(r
        .summary
        .starts_with("1 fault(s) injected; peer reaction: closed the connection"));
}

/// `duplicate_iframes`: frames go out twice with the same N(S); the
/// master answering with STOPDT is detected.
#[test]
fn duplicate_iframes_and_peer_stopdt() {
    let (run, port) = slave(
        script(3),
        r#"{"session":{"t1":3,"t2":0.5,"idle_serve_secs":5},
            "faults":[{"at":{"frame":1},"kind":"duplicate_iframes","pct":100,"duration_ms":200}]}"#,
    );
    let mut p = Peer::connect(port);
    p.strict = false;
    master_handshake(&mut p);
    for _ in 0..5 {
        p.recv_until(ms(1000), is_i).expect("I-frame");
    }
    assert_eq!(p.ns_log, vec![0, 1, 1, 2, 2]);
    p.ack();
    p.send_u(U_STOPDT_ACT);
    p.recv_until(ms(1000), |a| is_u(a, U_STOPDT_CON))
        .expect("STOPDT con");
    drop(p);
    let (rep, _, _) = run.join_within(ms(3000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.messages_sent, 3);
    assert_eq!(only_fault(&rep, "duplicate_iframes"), 2);
    let r = reaction(&rep);
    assert!(r.peer_stopdt && r.peer_closed, "{r:?}");
    assert!(r.summary.contains("sent STOPDT act"), "{}", r.summary);
}

/// `corrupt_ns`: one frame carries V(S) + 16384; the peer acknowledges
/// that bogus number and the resulting protocol error is reported as
/// its reaction.
#[test]
fn corrupt_ns_and_peer_protocol_error() {
    let (l, port) = listener();
    let mut c = cfg(Role::Master, port, script(3));
    c.proto_config = Some(
        r#"{"session":{"t1":3,"t2":0.5},
            "faults":[{"at":{"frame":1},"kind":"corrupt_ns","count":1}]}"#
            .into(),
    );
    let run = Running::spawn(c);
    let mut p = Peer::accept(&l);
    p.strict = false;
    server_handshake(&mut p);
    for _ in 0..3 {
        p.recv_until(ms(2000), is_i).expect("I-frame");
    }
    assert_eq!(p.ns_log, vec![0, 16385, 2]);
    p.send(&Apdu::S { nr: 16386 });
    assert!(p.sees_fin(ms(1500)), "master did not close");
    let (rep, _, _) = run.join_within(ms(3000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(only_fault(&rep, "corrupt_ns"), 1);
    let r = reaction(&rep);
    assert_eq!(r.protocol_errors, vec!["nr_out_of_window".to_string()]);
    assert!(r.first_reaction_ms.is_some());
}

/// `testfr_silence`: TESTFR act is ignored and t3 sends nothing while
/// the window is open; afterwards TESTFR works again. A reset by the
/// peer is told apart from a close.
#[test]
fn testfr_silence_then_peer_reset() {
    let (run, port) = slave(
        script(1),
        r#"{"session":{"t1":3,"t2":0.2,"t3":0.3,"idle_serve_secs":5},
            "faults":[{"at":{"ms":0},"kind":"testfr_silence","duration_ms":700}]}"#,
    );
    let t0 = Instant::now();
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    p.recv_until(ms(1000), is_i).expect("script frame");
    p.ack();
    p.send_u(U_TESTFR_ACT);
    // Neither a con nor our own TESTFR (t3 = 0.3 s) inside the window.
    let quiet = ms(650).saturating_sub(t0.elapsed());
    assert!(p.recv(quiet).is_none(), "frame during TESTFR silence");
    // (The slave's accept loop polls every 50 ms, so its clock may
    // start a little after ours.)
    std::thread::sleep(ms(950).saturating_sub(t0.elapsed()));
    p.send_u(U_TESTFR_ACT);
    p.recv_until(ms(500), |a| is_u(a, U_TESTFR_CON))
        .expect("TESTFR con after the window");
    p.reset();
    let (rep, _, _) = run.join_within(ms(3000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(only_fault(&rep, "testfr_silence"), 1);
    let r = reaction(&rep);
    assert!(r.peer_reset && !r.peer_closed, "{r:?}");
    assert!(r.summary.contains("reset the connection"), "{}", r.summary);
}

/// `delay`: replayed and synthesized frames are held the extra time.
#[test]
fn delay_holds_outgoing_iframes() {
    let (run, port) = slave(
        script(1),
        r#"{"session":{"t1":3,"t2":0.5,"idle_serve_secs":5},
            "faults":[{"at":{"ms":0},"kind":"delay","ms":300,"duration_ms":5000}]}"#,
    );
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    let t = Instant::now();
    p.recv_until(ms(1000), is_i).expect("script frame");
    assert!(
        t.elapsed() >= ms(250),
        "script frame after {:?}",
        t.elapsed()
    );
    p.ack();
    p.send_i(gi_act());
    let t = Instant::now();
    for _ in 0..3 {
        p.recv_until(ms(1000), is_i).expect("GI response");
    }
    assert!(
        t.elapsed() >= ms(250),
        "GI answered after {:?}",
        t.elapsed()
    );
    p.ack();
    drop(p);
    let (rep, _, _) = run.join_within(ms(3000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(only_fault(&rep, "delay"), 4);
    assert!(rep.protocol.command_response_us[0] >= 250_000);
    assert!(reaction(&rep).summary.contains("closed the connection"));
}

/// The fault scheduler stays cancellable: a frame held by a long
/// `delay` does not hold up a cancel.
#[test]
fn delay_is_cancellable() {
    let (l, port) = listener();
    let mut c = cfg(Role::Master, port, script(1));
    c.proto_config = Some(
        r#"{"faults":[{"at":{"ms":0},"kind":"delay","ms":60000,"duration_ms":60000}]}"#.into(),
    );
    let run = Running::spawn(c);
    let mut p = Peer::accept(&l);
    server_handshake(&mut p);
    std::thread::sleep(ms(200));
    run.cancel();
    let t = Instant::now();
    assert!(p.sees_fin(ms(1500)), "no FIN after cancel");
    assert!(t.elapsed() < ms(1000));
    let (rep, _, _) = run.join_within(ms(1000));
    assert!(rep.error.unwrap_or_default().contains("cancelled"));
    assert_eq!(rep.messages_sent, 0);
}

/// `rst`: abortive close (RST, not FIN); the run does not count it as
/// an error.
#[test]
fn rst_aborts_the_connection() {
    let (run, port) = slave(
        script(1),
        r#"{"session":{"t1":3,"t2":0.5,"idle_serve_secs":5},
            "faults":[{"at":{"ms":200},"kind":"rst"}]}"#,
    );
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    p.recv_until(ms(1000), is_i).expect("script frame");
    assert!(p.sees_rst(ms(1500)), "no RST");
    let (rep, _, _) = run.join_within(ms(2000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.protocol.faults_injected[0].kind, "rst");
    assert!(reaction(&rep).summary.contains("none observed"));
}

/// `stopdt` (master): STOPDT act mid-script, STARTDT act once
/// confirmed, then the script carries on.
#[test]
fn master_stopdt_then_restart() {
    let (l, port) = listener();
    let mut c = cfg(Role::Master, port, script(2));
    c.proto_config = Some(
        r#"{"session":{"t1":3,"t2":0.5},"faults":[{"at":{"frame":1},"kind":"stopdt"}]}"#.into(),
    );
    let run = Running::spawn(c);
    let mut p = Peer::accept(&l);
    server_handshake(&mut p);
    assert!(is_i(&p.recv(ms(2000)).expect("frame 0")));
    let a = p.recv(ms(1000)).expect("STOPDT act");
    assert!(is_u(&a, U_STOPDT_ACT), "{a:?}");
    p.ack();
    p.send_u(U_STOPDT_CON);
    let a = p.recv(ms(1000)).expect("STARTDT act");
    assert!(is_u(&a, U_STARTDT_ACT), "{a:?}");
    p.send_u(U_STARTDT_CON);
    let a = p.recv(ms(1000)).expect("frame 1");
    assert_eq!(asdu_of(&a).unwrap(), &sp_asdu(1, 1)[..]);
    p.ack();
    p.recv_until(ms(2000), |a| is_u(a, U_STOPDT_ACT))
        .expect("final STOPDT act");
    p.send_u(U_STOPDT_CON);
    assert!(p.sees_fin(ms(1500)));
    let (rep, _, _) = run.join_within(ms(2000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(only_fault(&rep, "stopdt"), 1);
    assert_eq!(rep.protocol.protocol_violations, 0);
}

/// A `stopdt` that fires before data transfer started waits for it.
#[test]
fn master_stopdt_before_startdt_is_deferred() {
    let (l, port) = listener();
    let mut c = cfg(Role::Master, port, script(1));
    c.proto_config =
        Some(r#"{"session":{"t1":3,"t2":0.5},"faults":[{"at":{"ms":0},"kind":"stopdt"}]}"#.into());
    let run = Running::spawn(c);
    let mut p = Peer::accept(&l);
    let a = p.recv(ms(3000)).expect("STARTDT act");
    assert!(is_u(&a, U_STARTDT_ACT), "{a:?}");
    std::thread::sleep(ms(100));
    p.send_u(U_STARTDT_CON);
    let a = p.recv(ms(1000)).expect("STOPDT act");
    assert!(is_u(&a, U_STOPDT_ACT), "{a:?}");
    p.send_u(U_STOPDT_CON);
    let a = p.recv(ms(1000)).expect("STARTDT act again");
    assert!(is_u(&a, U_STARTDT_ACT), "{a:?}");
    p.send_u(U_STARTDT_CON);
    assert!(is_i(&p.recv(ms(1000)).expect("frame 0")));
    p.ack();
    p.recv_until(ms(2000), |a| is_u(a, U_STOPDT_ACT))
        .expect("final STOPDT act");
    p.send_u(U_STOPDT_CON);
    let (rep, _, _) = run.join_within(ms(2000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(only_fault(&rep, "stopdt"), 1);
}

/// `stopdt` (slave): an unsolicited STOPDT act from the controlled
/// station; the master's con is the recorded reaction, not a violation.
#[test]
fn slave_unsolicited_stopdt() {
    let (run, port) = slave(
        script(1),
        r#"{"session":{"t1":3,"t2":0.5,"idle_serve_secs":5},
            "faults":[{"at":{"ms":100},"kind":"stopdt"}]}"#,
    );
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    p.recv_until(ms(1000), |a| is_u(a, U_STOPDT_ACT))
        .expect("STOPDT act from the slave");
    p.send_u(U_STOPDT_CON);
    std::thread::sleep(ms(100));
    drop(p);
    let (rep, _, _) = run.join_within(ms(2000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.protocol.protocol_violations, 0);
    let r = reaction(&rep);
    assert!(
        r.summary.contains("confirmed our STOPDT act"),
        "{}",
        r.summary
    );
}

/// `malformed_apdu`: APDUs with an invalid length octet reach the peer.
#[test]
fn malformed_apdu_is_sent() {
    let (run, port) = slave(
        script(1),
        r#"{"session":{"t1":3,"t2":0.5,"idle_serve_secs":5},
            "faults":[{"at":{"ms":100},"kind":"malformed_apdu","count":2}]}"#,
    );
    let mut p = Peer::connect(port);
    p.strict = false;
    master_handshake(&mut p);
    p.recv_until(ms(1000), is_i).expect("script frame");
    assert!(p.recv(ms(400)).is_none());
    assert_eq!(p.malformed, 2);
    drop(p);
    let (rep, _, _) = run.join_within(ms(2000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(only_fault(&rep, "malformed_apdu"), 2);
    assert!(reaction(&rep).peer_closed);
}

/// `slow_ack`: the t2 acknowledgement goes out `extra_ms` late.
#[test]
fn slow_ack_defers_acknowledgements() {
    let (run, port) = slave(
        script(1),
        r#"{"session":{"t1":3,"t2":0.2,"idle_serve_secs":5},
            "faults":[{"at":{"ms":0},"kind":"slow_ack","extra_ms":400}]}"#,
    );
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    p.recv_until(ms(1000), is_i).expect("script frame");
    p.ack();
    p.send_i(sp_asdu(9, 1));
    let t = Instant::now();
    let s = p
        .recv_until(ms(1500), |a| matches!(a, Apdu::S { .. }))
        .expect("deferred ack");
    assert!(matches!(s, Apdu::S { nr: 1 }), "{s:?}");
    assert!(
        t.elapsed() >= ms(550) && t.elapsed() < ms(1200),
        "ack after {:?}",
        t.elapsed()
    );
    drop(p);
    let (rep, _, _) = run.join_within(ms(2000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(only_fault(&rep, "slow_ack"), 1);
}

/// A bad fault plan is refused before anything is bound or sent.
#[test]
fn invalid_fault_plan_is_rejected() {
    let mut c = cfg(Role::Slave, free_port(), script(1));
    c.proto_config = Some(r#"{"faults":[{"at":{"ms":1},"kind":"meteor"}]}"#.into());
    let rep = crate::session::run_slave_session(c);
    let err = rep.error.unwrap_or_default();
    assert!(err.contains("faults") && err.contains("meteor"), "{err}");
    assert!(!rep.connected);
}
