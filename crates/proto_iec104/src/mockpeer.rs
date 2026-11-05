//! In-process scripted IEC 104 peer over 127.0.0.1 for session tests.
//!
//! A [`Peer`] is the far end of a session under test: the server for a
//! master session ([`Peer::accept`]) or the master for a slave session
//! ([`Peer::connect`]). It tracks its own V(S)/V(R) so tests can send
//! well-formed I-frames and acknowledgements, and checks every
//! received I-frame's N(S) against its V(R).

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use protoplay::{ClientSegment, MessageProgress, Pacing, ProtoReport, ProtoRunCfg, Role};

use crate::apdu::Apdu;

pub(crate) struct Peer {
    pub s: TcpStream,
    /// Our V(S): N(S) of the next I-frame we send.
    pub vs: u16,
    /// Our V(R): number of I-frames received (mod 2^15).
    pub vr: u16,
    /// I-frames received since we last acknowledged.
    pub unacked: u16,
    /// Assert that received I-frames are in sequence (default). When
    /// off, V(R) follows the received N(S) and every N(S) is logged in
    /// `ns_log`, so fault-injection tests can inspect the sequence.
    pub strict: bool,
    pub ns_log: Vec<u16>,
    /// APDUs with an invalid length octet seen (non-strict mode).
    pub malformed: u32,
    /// Raw bytes received / sent, with the time (ns since the peer was
    /// created) each frame was read or written, for analyzer tests.
    pub rx_log: Vec<(u64, Vec<u8>)>,
    pub tx_log: Vec<(u64, Vec<u8>)>,
    t0: Instant,
}

impl Peer {
    fn new(s: TcpStream) -> Self {
        s.set_nodelay(true).ok();
        Self {
            s,
            vs: 0,
            vr: 0,
            unacked: 0,
            strict: true,
            ns_log: Vec::new(),
            malformed: 0,
            rx_log: Vec::new(),
            tx_log: Vec::new(),
            t0: Instant::now(),
        }
    }

    fn stamp(&self) -> u64 {
        self.t0.elapsed().as_nanos() as u64
    }

    /// Connect to a slave session listening on `port`, retrying while
    /// the listener comes up.
    pub fn connect(port: u16) -> Self {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match TcpStream::connect((Ipv4Addr::LOCALHOST, port)) {
                Ok(s) => return Self::new(s),
                Err(e) if Instant::now() < deadline => {
                    let _ = e;
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("connect to slave on {port}: {e}"),
            }
        }
    }

    /// Wrap an accepted or connected stream.
    pub fn from_stream(s: TcpStream) -> Self {
        Self::new(s)
    }

    /// Accept the connection of a master session.
    pub fn accept(listener: &TcpListener) -> Self {
        let (s, _) = listener.accept().expect("accept");
        Self::new(s)
    }

    pub fn send(&mut self, apdu: &Apdu) {
        let bytes = apdu.serialize();
        self.s.write_all(&bytes).expect("peer write");
        let t = self.stamp();
        self.tx_log.push((t, bytes));
    }

    /// Abortive close: RST instead of FIN.
    pub fn reset(self) {
        socket2::SockRef::from(&self.s)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
    }

    pub fn send_u(&mut self, code: u8) {
        self.send(&Apdu::U { code });
    }

    /// Acknowledge every I-frame received so far.
    pub fn ack(&mut self) {
        let nr = self.vr;
        self.send(&Apdu::S { nr });
        self.unacked = 0;
    }

    /// Send an I-frame with the next N(S) and our current V(R).
    pub fn send_i(&mut self, asdu: Vec<u8>) {
        let apdu = Apdu::I {
            ns: self.vs,
            nr: self.vr,
            asdu,
        };
        self.send(&apdu);
        self.vs = (self.vs + 1) & 0x7fff;
        self.unacked = 0;
    }

    /// Read one APDU within `timeout`. `None` on timeout or EOF.
    /// Received I-frames advance V(R); their N(S) is asserted to be in
    /// sequence.
    pub fn recv(&mut self, timeout: Duration) -> Option<Apdu> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            self.s
                .set_read_timeout(Some(left.max(Duration::from_millis(1))))
                .unwrap();
            let mut hdr = [0u8; 2];
            self.s.read_exact(&mut hdr).ok()?;
            assert_eq!(hdr[0], 0x68, "session sent a bad start octet");
            let mut body = vec![0u8; hdr[1] as usize];
            self.s.read_exact(&mut body).ok()?;
            let t = self.stamp();
            let parsed = Apdu::parse(&body);
            let apdu = match parsed {
                Ok(a) if hdr[1] >= 4 => a,
                _ if !self.strict => {
                    self.malformed += 1;
                    continue;
                }
                _ => panic!("session sent a malformed APDU: {hdr:02x?} {body:02x?}"),
            };
            let mut raw = hdr.to_vec();
            raw.extend_from_slice(&body);
            self.rx_log.push((t, raw));
            if let Apdu::I { ns, .. } = apdu {
                if self.strict {
                    assert_eq!(ns, self.vr, "session sent N(S) out of sequence");
                } else {
                    self.ns_log.push(ns);
                }
                self.vr = (ns + 1) & 0x7fff;
                self.unacked += 1;
            }
            return Some(apdu);
        }
    }

    /// Is the connection reset (RST) within `timeout`?
    pub fn sees_rst(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 512];
        loop {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            self.s
                .set_read_timeout(Some(left.max(Duration::from_millis(1))))
                .unwrap();
            match self.s.read(&mut buf) {
                Ok(0) => return false,
                Ok(_) => continue,
                Err(e) => return e.kind() == ErrorKind::ConnectionReset,
            }
        }
    }

    /// Read until `pred` matches (returning that APDU) or `timeout`.
    pub fn recv_until(&mut self, timeout: Duration, pred: impl Fn(&Apdu) -> bool) -> Option<Apdu> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.checked_duration_since(Instant::now())?;
            let a = self.recv(left)?;
            if pred(&a) {
                return Some(a);
            }
        }
    }

    /// Does the session close the connection (FIN: read returns 0)
    /// within `timeout`? Frames that arrive first are discarded.
    pub fn sees_fin(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 512];
        loop {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            self.s
                .set_read_timeout(Some(left.max(Duration::from_millis(1))))
                .unwrap();
            match self.s.read(&mut buf) {
                Ok(0) => return true,
                Ok(_) => continue,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return false
                }
                // A reset after the FIN still means the session closed.
                Err(_) => return true,
            }
        }
    }
}

pub(crate) fn is_u(a: &Apdu, code: u8) -> bool {
    matches!(a, Apdu::U { code: c } if *c == code)
}

pub(crate) fn is_i(a: &Apdu) -> bool {
    matches!(a, Apdu::I { .. })
}

/// I-frame ASDU of `a`, if any.
pub(crate) fn asdu_of(a: &Apdu) -> Option<&[u8]> {
    match a {
        Apdu::I { asdu, .. } => Some(asdu),
        _ => None,
    }
}

/// `M_SP_NA_1` spontaneous single point at CA 1.
pub(crate) fn sp_asdu(ioa: u16, value: u8) -> Vec<u8> {
    vec![1, 1, 3, 0, 1, 0, ioa as u8, (ioa >> 8) as u8, 0, value & 1]
}

/// `C_IC_NA_1` station GI activation at CA 1.
pub(crate) fn gi_act() -> Vec<u8> {
    vec![100, 1, 6, 0, 1, 0, 0, 0, 0, 20]
}

/// Serialize ASDUs as captured I-frames.
pub(crate) fn blob(asdus: &[Vec<u8>]) -> Vec<u8> {
    let mut b = Vec::new();
    for (i, a) in asdus.iter().enumerate() {
        b.extend(
            Apdu::I {
                ns: i as u16,
                nr: 0,
                asdu: a.clone(),
            }
            .serialize(),
        );
    }
    b
}

pub(crate) fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub(crate) fn cfg(role: Role, port: u16, payload: Vec<u8>) -> ProtoRunCfg {
    ProtoRunCfg {
        bind_ip: Ipv4Addr::LOCALHOST,
        bind_iface: None,
        target_ip: Ipv4Addr::LOCALHOST,
        target_port: port,
        tcp_nodelay: true,
        client_segments: vec![ClientSegment {
            rel_ts_ns: 0,
            bytes: payload,
        }],
        connect_timeout: Duration::from_secs(2),
        speed: 1.0,
        proto_config: None,
        progress: None,
        role,
        listen_port: port,
        pacing: Pacing::AsFastAsPossible,
        frame_times_ns: Vec::new(),
        loop_iterations: 1,
        capture_gaps: Vec::new(),
    }
}

/// CPU time consumed by the calling thread.
pub(crate) fn thread_cpu() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid pointer to a timespec; CLOCK_THREAD_CPUTIME_ID is
    // always available on Linux.
    unsafe {
        libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts);
    }
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// A session running on its own thread.
pub(crate) struct Running {
    pub handle: JoinHandle<(ProtoReport, Duration, Duration)>,
    pub progress: MessageProgress,
}

impl Running {
    /// Run a master or slave session (per `cfg.role`) on a new thread,
    /// with a progress sink attached.
    pub fn spawn(mut cfg: ProtoRunCfg) -> Self {
        let progress = MessageProgress::default();
        cfg.progress = Some(progress.clone());
        let handle = std::thread::spawn(move || {
            let t = Instant::now();
            let report = match cfg.role {
                Role::Master => crate::session::run_session(cfg),
                Role::Slave => crate::session::run_slave_session(cfg),
            };
            (report, t.elapsed(), thread_cpu())
        });
        Self { handle, progress }
    }

    pub fn cancel(&self) {
        self.progress.cancel.store(true, Ordering::Relaxed);
    }

    /// Wait up to `timeout` for the session to return; panics if it
    /// does not. Returns (report, wall time, session-thread CPU time).
    pub fn join_within(self, timeout: Duration) -> (ProtoReport, Duration, Duration) {
        let deadline = Instant::now() + timeout;
        while !self.handle.is_finished() {
            if Instant::now() >= deadline {
                self.cancel();
                let _ = self.handle.join();
                panic!("session did not return within {timeout:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.handle.join().expect("session thread panicked")
    }
}
