//! Command echo (slave) and command round-trip metrics (master)
//! against the in-process mock peer.

use super::*;
use crate::apdu::{U_STARTDT_ACT, U_STARTDT_CON, U_STOPDT_ACT, U_STOPDT_CON};
use crate::asdu::encode_cp56time2a_local;
use crate::mockpeer::{asdu_of, blob, cfg, free_port, gi_act, is_i, is_u, sp_asdu, Peer, Running};
use protoplay::{CommandTypeStats, Role};
use std::net::{Ipv4Addr, TcpListener};
use std::time::Duration;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn master_handshake(p: &mut Peer) {
    p.send_u(U_STARTDT_ACT);
    p.recv_until(ms(3000), |a| is_u(a, U_STARTDT_CON))
        .expect("STARTDT con");
}

/// Send `cmd` and collect `n` I-frame answers, then acknowledge.
fn exchange(p: &mut Peer, cmd: Vec<u8>, n: usize) -> Vec<Vec<u8>> {
    p.send_i(cmd);
    let mut out = Vec::new();
    while out.len() < n {
        let a = p.recv_until(ms(1000), is_i).expect("command answer");
        out.push(asdu_of(&a).unwrap().to_vec());
    }
    p.ack();
    out
}

fn cots(v: &[Vec<u8>]) -> Vec<u8> {
    v.iter().map(|a| a[2]).collect()
}

fn wall_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn stats(rep: &ProtoReport, type_id: u8) -> CommandTypeStats {
    rep.protocol
        .commands
        .iter()
        .find(|c| c.type_id == type_id)
        .cloned()
        .unwrap_or_else(|| panic!("no stats for type {type_id}: {:?}", rep.protocol.commands))
}

pub(crate) fn command_script() -> Vec<Vec<u8>> {
    vec![
        sp_asdu(100, 0),
        vec![45, 1, 7, 0, 1, 0, 100, 0, 0, 1], // captured ActCon
        vec![1, 1, 11, 0, 1, 0, 100, 0, 0, 1], // captured return info
        vec![45, 1, 10, 0, 1, 0, 100, 0, 0, 1], // captured ActTerm
        vec![13, 1, 3, 0, 1, 0, 0x2c, 1, 0, 0, 0, 0, 0, 0],
        vec![1, 1, 12, 0, 1, 0, 100, 0, 0, 0], // local command at the RTU
    ]
}

/// T11 / F139: the slave answers every command class like a real RTU:
/// select-before-operate, execute with return information, deactivate,
/// the four rejection classes, a stale time tag, clock sync, read,
/// test and reset process; captured command confirmations and remote
/// return information (COT 11) are not replayed, local return
/// information (COT 12) is; per-type round trips are reported.
#[test]
fn slave_echoes_commands() {
    let port = free_port();
    let mut c = cfg(Role::Slave, port, blob(&command_script()));
    c.proto_config = Some(
        r#"{"session":{"t1":3,"t2":0.5,"idle_serve_secs":5},"commands":{"return_info":"retrem"}}"#
            .into(),
    );
    let run = Running::spawn(c);
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    let mut script = Vec::new();
    while script.len() < 3 {
        let a = p.recv_until(ms(1000), is_i).expect("script frame");
        script.push(asdu_of(&a).unwrap().to_vec());
    }
    p.ack();
    // The captured ActCon / ActTerm and, with return information on,
    // the captured remote return info (COT 11) are stripped; the local
    // return info (COT 12) is ordinary data and stays.
    let s = command_script();
    assert_eq!(script, vec![s[0].clone(), s[4].clone(), s[5].clone()]);

    let sc = |sco: u8| vec![45, 1, 6, 0, 1, 0, 100, 0, 0, sco];
    // Select, execute (ActCon, return info, ActTerm), deactivate.
    let r = exchange(&mut p, sc(0x81), 1);
    assert_eq!(r, vec![vec![45, 1, 7, 0, 1, 0, 100, 0, 0, 0x81]]);
    let r = exchange(&mut p, sc(0x01), 3);
    assert_eq!(cots(&r), vec![7, 11, 10]);
    assert_eq!(r[1], vec![1, 1, 11, 0, 1, 0, 100, 0, 0, 1]);
    let mut deact = sc(0x81);
    deact[2] = 8;
    assert_eq!(cots(&exchange(&mut p, deact, 1)), vec![9]);
    // Unknown IOA, unknown type, unknown CA.
    let mut c = sc(1);
    c[6] = 99;
    assert_eq!(cots(&exchange(&mut p, c, 1)), vec![0x40 | 47]);
    let r = exchange(&mut p, vec![110, 1, 6, 0, 1, 0, 1, 0, 0, 0, 0, 0], 1);
    assert_eq!(cots(&r), vec![0x40 | 44]);
    let mut c = sc(1);
    c[4] = 9;
    assert_eq!(cots(&exchange(&mut p, c, 1)), vec![0x40 | 46]);
    // Time-tagged: stale is rejected, fresh is executed.
    let ta = |stamp: u64| {
        let mut a = vec![58, 1, 6, 0, 1, 0, 100, 0, 0, 0];
        a.extend_from_slice(&encode_cp56time2a_local(stamp, false));
        a
    };
    let r = exchange(&mut p, ta(wall_ns() - 60_000_000_000), 1);
    assert_eq!(cots(&r), vec![0x40 | 7]);
    let fresh = ta(wall_ns());
    let r = exchange(&mut p, fresh.clone(), 3);
    assert_eq!(cots(&r), vec![7, 11, 10]);
    assert_eq!(r[0][10..], fresh[10..], "time tag echoed");
    // Clock sync echoes the time; read returns the commanded value 0.
    let mut cs = vec![103, 1, 6, 0, 1, 0, 0, 0, 0];
    cs.extend_from_slice(&encode_cp56time2a_local(wall_ns(), false));
    let r = exchange(&mut p, cs.clone(), 1);
    assert_eq!(cots(&r), vec![7]);
    assert_eq!(r[0][9..], cs[9..]);
    let r = exchange(&mut p, vec![102, 1, 5, 0, 1, 0, 100, 0, 0], 1);
    assert_eq!(r, vec![vec![1, 1, 5, 0, 1, 0, 100, 0, 0, 0]]);
    let mut ts = vec![107, 1, 6, 0, 1, 0, 0, 0, 0, 0x34, 0x12];
    ts.extend_from_slice(&encode_cp56time2a_local(wall_ns(), false));
    assert_eq!(cots(&exchange(&mut p, ts, 1)), vec![7]);
    let rp = vec![105, 1, 6, 0, 1, 0, 0, 0, 0, 1];
    assert_eq!(cots(&exchange(&mut p, rp, 1)), vec![7]);
    // GI reflects the commanded state.
    let r = exchange(&mut p, gi_act(), 4);
    assert_eq!(cots(&r), vec![7, 20, 20, 10]);
    assert_eq!(r[1], vec![1, 1, 20, 0, 1, 0, 100, 0, 0, 0]);
    drop(p);

    let (rep, _, _) = run.join_within(ms(3000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    assert_eq!(rep.protocol.stripped_capture_frames, 3);
    let sc = stats(&rep, 45);
    assert_eq!(
        (
            sc.commands,
            sc.act_con,
            sc.deact_con,
            sc.negative,
            sc.act_term
        ),
        (5, 2, 1, 2, 1)
    );
    assert_eq!(sc.actcon_us.len(), 5);
    assert_eq!(sc.actterm_us.len(), 1);
    assert!(sc.actcon_us.iter().all(|&us| us < 300_000), "{sc:?}");
    let ta = stats(&rep, 58);
    assert_eq!(
        (ta.commands, ta.negative, ta.act_con, ta.act_term),
        (2, 1, 1, 1)
    );
    assert_eq!(stats(&rep, 110).negative, 1);
    assert_eq!(stats(&rep, 102).act_con, 1);
    assert_eq!(stats(&rep, 100).act_term, 1);
    let neg: Vec<(u8, u8)> = rep
        .protocol
        .negative_confirmations
        .iter()
        .map(|n| (n.type_id, n.cot))
        .collect();
    assert_eq!(neg, vec![(45, 47), (110, 44), (45, 46), (58, 7)]);
    assert_eq!(rep.protocol.negative_confirmations[0].ioa, 99);
    // 20 answers, all tagged as synthesized.
    assert_eq!(rep.protocol.synthesized_frames, 20);
    assert_eq!(rep.messages_sent, 23);
}

/// `{"commands":{"enabled":false}}`: commands are not answered and the
/// captured confirmations are replayed verbatim.
#[test]
fn slave_command_echo_off_replays_captured_confirmations() {
    let port = free_port();
    let mut c = cfg(Role::Slave, port, blob(&command_script()));
    c.proto_config = Some(
        r#"{"session":{"t1":3,"t2":0.5,"idle_serve_secs":0.3},"commands":{"enabled":false}}"#
            .into(),
    );
    let run = Running::spawn(c);
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    let mut got = Vec::new();
    while got.len() < 6 {
        let a = p.recv_until(ms(1000), is_i).expect("script frame");
        got.push(asdu_of(&a).unwrap().to_vec());
    }
    p.ack();
    p.send_i(vec![45, 1, 6, 0, 1, 0, 100, 0, 0, 1]);
    assert!(p.recv_until(ms(250), is_i).is_none(), "command answered");
    assert!(p.sees_fin(ms(2000)));
    let (rep, _, _) = run.join_within(ms(2000));
    assert_eq!(got, command_script());
    assert_eq!(rep.protocol.stripped_capture_frames, 0);
    assert!(rep.protocol.commands.is_empty());
}

/// F009 / T11: in master mode the replayed commands' round trips to
/// the live slave are measured per type: ActCon and ActTerm latency,
/// negative confirmations, and commands left unanswered.
#[test]
fn master_measures_command_round_trips() {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    let mut se = vec![50, 1, 6, 0, 1, 0, 6, 0, 0];
    se.extend_from_slice(&1.5f32.to_le_bytes());
    se.push(0x80); // select
    let script = vec![
        vec![45, 1, 6, 0, 1, 0, 5, 0, 0, 1],
        se.clone(),
        gi_act(),
        vec![102, 1, 5, 0, 1, 0, 7, 0, 0],
        vec![46, 1, 6, 0, 1, 0, 8, 0, 0, 2],
    ];
    let mut c = cfg(Role::Master, port, blob(&script));
    c.proto_config = Some(r#"{"session":{"t1":3,"t2":0.5}}"#.into());
    let run = Running::spawn(c);
    let mut p = Peer::accept(&l);
    let a = p.recv(ms(3000)).expect("STARTDT act");
    assert!(is_u(&a, U_STARTDT_ACT));
    p.send_u(U_STARTDT_CON);
    for _ in 0..5 {
        assert!(is_i(&p.recv(ms(2000)).expect("command")));
    }
    let mirror = |a: &[u8], cot: u8| {
        let mut m = a.to_vec();
        m[2] = cot;
        m
    };
    std::thread::sleep(ms(60));
    p.send_i(mirror(&script[0], 7));
    p.send_i(mirror(&se, 0x47));
    std::thread::sleep(ms(60));
    p.send_i(mirror(&script[0], 10));
    p.send_i(mirror(&script[2], 7));
    p.send_i(vec![1, 1, 20, 0, 1, 0, 1, 0, 0, 1]);
    p.send_i(mirror(&script[2], 10));
    p.send_i(vec![1, 1, 5, 0, 1, 0, 7, 0, 0, 1]);
    p.ack();
    p.recv_until(ms(3000), |a| is_u(a, U_STOPDT_ACT))
        .expect("STOPDT act");
    p.send_u(U_STOPDT_CON);
    assert!(p.sees_fin(ms(1500)));
    let (rep, _, _) = run.join_within(ms(3000));
    assert!(rep.error.is_none(), "{:?}", rep.error);
    let sc = stats(&rep, 45);
    assert_eq!((sc.commands, sc.act_con, sc.act_term), (1, 1, 1));
    assert!(sc.actcon_us[0] >= 50_000, "{sc:?}");
    assert!(sc.actterm_us[0] >= sc.actcon_us[0] + 50_000, "{sc:?}");
    let se_st = stats(&rep, 50);
    assert_eq!((se_st.commands, se_st.negative, se_st.act_con), (1, 1, 0));
    let gi = stats(&rep, 100);
    assert_eq!((gi.act_con, gi.act_term), (1, 1));
    assert_eq!(stats(&rep, 102).act_con, 1);
    let dc = stats(&rep, 46);
    assert_eq!((dc.commands, dc.unanswered), (1, 1));
    assert_eq!(rep.protocol.negative_confirmations.len(), 1);
    let n = &rep.protocol.negative_confirmations[0];
    assert_eq!((n.type_id, n.ca, n.ioa, n.cot), (50, 1, 6, 7));
}

/// Concatenate logged frames into a flow snapshot's payload and
/// byte-offset to timestamp map.
fn flow_of(log: &[(u64, Vec<u8>)]) -> (Vec<u8>, Vec<(u64, usize)>) {
    let mut payload = Vec::new();
    let mut offsets = Vec::new();
    for (t, bytes) in log {
        offsets.push((*t, payload.len()));
        payload.extend_from_slice(bytes);
    }
    (payload, offsets)
}

/// T11: a slave replay with live commands still scores 100%: the
/// captured confirmations are not expected and every synthesized
/// command answer (ActCon, return information, ActTerm, read reply,
/// rejections) is removed from the delivered side, next to a live GI.
#[test]
fn replay_with_live_commands_scores_100() {
    use crate::analysis::analyze_iec104_flow;
    use protoplay::{AnalyzeCtx, FlowSnapshot, RunFacts};

    let config =
        r#"{"session":{"t1":3,"t2":0.5,"idle_serve_secs":5},"commands":{"return_info":"retrem"}}"#;
    let port = free_port();
    let mut c = cfg(Role::Slave, port, blob(&command_script()));
    c.proto_config = Some(config.into());
    let run = Running::spawn(c);
    let mut p = Peer::connect(port);
    master_handshake(&mut p);
    for _ in 0..3 {
        p.recv_until(ms(1000), is_i).expect("script frame");
    }
    p.ack();
    exchange(&mut p, gi_act(), 4);
    let sc = |sco: u8| vec![45, 1, 6, 0, 1, 0, 100, 0, 0, sco];
    exchange(&mut p, sc(0x81), 1);
    exchange(&mut p, sc(0x01), 3);
    exchange(&mut p, vec![45, 1, 6, 0, 1, 0, 99, 0, 0, 1], 1);
    exchange(&mut p, vec![102, 1, 5, 0, 1, 0, 100, 0, 0], 1);
    let mut cs = vec![103, 1, 6, 0, 1, 0, 0, 0, 0];
    cs.extend_from_slice(&encode_cp56time2a_local(wall_ns(), false));
    exchange(&mut p, cs, 1);
    let (rx, tx) = (p.rx_log.clone(), p.tx_log.clone());
    drop(p);
    let (rep, _, _) = run.join_within(ms(3000));
    assert!(rep.error.is_none(), "{:?}", rep.error);

    let src = blob(&command_script());
    let src_offsets: Vec<(u64, usize)> = crate::apci::frames(&src)
        .enumerate()
        .map(|(i, f)| (i as u64 * 1_000_000, f.offset))
        .collect();
    let (pb, pb_off) = flow_of(&rx);
    let (tg, tg_off) = flow_of(&tx);
    let ctx = AnalyzeCtx {
        role: Role::Slave,
        mode_correct: false,
        captured_first_ts_ns: 0,
        target_port: 2404,
        proto_config: Some(config.into()),
        cp56_tolerance_ms: 50.0,
        run: RunFacts::default(),
    };
    let a = analyze_iec104_flow(
        Some(FlowSnapshot {
            payload: &src,
            packet_offsets: &src_offsets,
        }),
        Some(FlowSnapshot {
            payload: &pb,
            packet_offsets: &pb_off,
        }),
        None,
        Some(FlowSnapshot {
            payload: &tg,
            packet_offsets: &tg_off,
        }),
        &ctx,
    );
    assert_eq!(
        a.verdict, "good_delivery",
        "{} {:?}",
        a.verdict_reason, a.notes
    );
    assert_eq!(a.score_pct, 100.0);
    let pb = &a.protocol_specific["playback"];
    assert_eq!(pb["command_echo"], true);
    assert_eq!(pb["source_command_stripped"], 2);
    assert_eq!(pb["source_return_info_stripped"], 1);
    assert_eq!(pb["command_responses_excluded"], 7);
    assert_eq!(pb["synthesized_excluded"], 11);
    assert_eq!(pb["delivered_iframes"], 3);
    assert_eq!(a.protocol_specific["gi_ci_audit"]["gi_compliant"], 1);
    assert!(a.protocol_specific["verdict_dimensions"]["faults"].is_null());
}
