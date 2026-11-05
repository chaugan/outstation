//! Live WebSocket progress stream.

use crate::error::{ApiPath, LockExt};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use serde::Serialize;

use crate::dto::*;
use crate::runs::*;
use crate::state::*;

/// WebSocket endpoint that streams a compact run snapshot every 200 ms
/// while the connection is open. Used by the per-run live network
/// diagram + progress card so the UI doesn't need to poll. Closes
/// itself once the run reaches a terminal state.
pub(crate) async fn api_run_live_ws(
    State(state): State<AppState>,
    ApiPath(id): ApiPath<u64>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| run_live_loop(state, id, socket))
}

/// Sliding-window rate estimator. Pushes (timestamp, counter) samples
/// and reports pps = (newest_count - oldest_count) / elapsed_seconds
/// across the window. Used so slow-paced sessions (e.g., 1.3 msg/s in
/// original-pcap-timing mode) don't show pps=0 just because no
/// messages happened in the last 200 ms WS tick.
#[derive(Default)]
pub(crate) struct SessionRateWindow {
    pub(crate) samples: std::collections::VecDeque<(std::time::Instant, u64, u64)>,
}

impl SessionRateWindow {
    const WINDOW_SECS: f64 = 1.5;
    const CAP: usize = 12;

    fn push(&mut self, now: std::time::Instant, sent: u64, recv: u64) {
        self.samples.push_back((now, sent, recv));
        while let Some(front) = self.samples.front() {
            if now.duration_since(front.0).as_secs_f64() > Self::WINDOW_SECS
                || self.samples.len() > Self::CAP
            {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    fn pps(&self) -> (u64, u64) {
        if self.samples.len() < 2 {
            return (0, 0);
        }
        let (t0, s0, r0) = *self.samples.front().unwrap();
        let (t1, s1, r1) = *self.samples.back().unwrap();
        let dt = t1.duration_since(t0).as_secs_f64();
        if dt < 0.05 {
            return (0, 0);
        }
        // ceil so any non-zero count delta in the window reports at
        // least 1 pps (otherwise a 1.3 msg/s session would round to
        // 0 and the diagram animation would die).
        let pps_s = ((s1.saturating_sub(s0) as f64) / dt).ceil() as u64;
        let pps_r = ((r1.saturating_sub(r0) as f64) / dt).ceil() as u64;
        (pps_s, pps_r)
    }
}

/// Counts an open stream in the metrics for as long as it lives.
struct LiveSocketGauge(std::sync::Arc<crate::metrics::Metrics>);

impl LiveSocketGauge {
    fn new(m: std::sync::Arc<crate::metrics::Metrics>) -> Self {
        m.live_sockets
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self(m)
    }
}

impl Drop for LiveSocketGauge {
    fn drop(&mut self) {
        self.0
            .live_sockets
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Stream frames until the run is terminal, the server shuts down, or
/// the client goes away. The socket is read between ticks so a Close
/// (or a dropped connection) ends the stream at once instead of after
/// the next failed send, which a half-open socket may never produce
/// (N23, F106).
pub(crate) async fn run_live_loop(state: AppState, id: u64, mut socket: WebSocket) {
    let _gauge = LiveSocketGauge::new(state.metrics.clone());
    let interval = std::time::Duration::from_millis(200);
    // Sliding-window rate estimators for the global aggregate and for
    // each per-source session. Indexed by per_source position.
    let mut global_win = SessionRateWindow::default();
    let mut session_wins: Vec<SessionRateWindow> = Vec::new();
    loop {
        let frame = {
            let Some(entry) = state.get_run(id) else {
                break;
            };
            let mut rs = entry.lock_safe().clone();
            refresh_progress(&mut rs);

            let now = std::time::Instant::now();

            // Resize the per-session window vec to match the current
            // session count (may grow as workers spawn).
            if session_wins.len() != rs.per_source_progress.len() {
                session_wins.resize_with(rs.per_source_progress.len(), SessionRateWindow::default);
            }

            let total_recv: u64 = rs.per_source_progress.iter().map(|p| p.received).sum();
            global_win.push(now, rs.sent, total_recv);
            let (pps_sent, pps_recv) = global_win.pps();

            let per_session: Vec<_> = rs
                .per_source_progress
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    session_wins[i].push(now, p.sent, p.received);
                    let (pps_s, pps_r) = session_wins[i].pps();
                    LivePerSession {
                        src_ip: p.src_ip.clone(),
                        state: p.state.clone(),
                        planned: p.planned,
                        sent: p.sent,
                        received: p.received,
                        unacked: p.unacked,
                        listen_port: p.listen_port,
                        pps_sent: pps_s,
                        pps_recv: pps_r,
                        iter_current: p.iter_current,
                        iter_total: p.iter_total,
                    }
                })
                .collect();

            let terminal = !matches!(rs.status, RunStatus::Running);
            (
                LiveFrame {
                    run_id: rs.id,
                    status: rs.status.as_str().to_string(),
                    mode: rs.mode,
                    role: rs.role,
                    planned: rs.planned,
                    sent: rs.sent,
                    bytes: rs.bytes_progress,
                    pps_sent,
                    pps_recv,
                    per_session,
                },
                terminal,
            )
        };
        let (msg, terminal) = frame;
        let payload = match serde_json::to_string(&msg) {
            Ok(s) => s,
            Err(_) => break,
        };
        if socket.send(Message::Text(payload)).await.is_err() {
            break;
        }
        if terminal {
            // Send one final tick so the client sees the terminal
            // state before we close.
            break;
        }
        let tick = tokio::time::sleep(interval);
        tokio::pin!(tick);
        loop {
            tokio::select! {
                _ = &mut tick => break,
                _ = state.shutdown.cancelled() => return,
                msg = socket.recv() => match msg {
                    // Pings are answered by the WebSocket layer; other
                    // client messages are ignored.
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                    Some(Ok(_)) => {}
                },
            }
        }
    }
}

#[derive(Serialize)]
pub(crate) struct LiveFrame {
    pub(crate) run_id: u64,
    pub(crate) status: String,
    pub(crate) mode: &'static str,
    pub(crate) role: &'static str,
    pub(crate) planned: u64,
    pub(crate) sent: u64,
    pub(crate) bytes: u64,
    pub(crate) pps_sent: u64,
    pub(crate) pps_recv: u64,
    pub(crate) per_session: Vec<LivePerSession>,
}

#[derive(Serialize)]
pub(crate) struct LivePerSession {
    pub(crate) src_ip: Option<String>,
    pub(crate) state: String,
    pub(crate) planned: u64,
    pub(crate) sent: u64,
    pub(crate) received: u64,
    pub(crate) unacked: u64,
    pub(crate) listen_port: u16,
    /// Per-session uplink rate (messages/s sent by this session to
    /// the live target since the last WS tick). Drives the live
    /// network diagram's animation speed.
    pub(crate) pps_sent: u64,
    /// Per-session downlink rate (messages/s received from the live
    /// target since the last WS tick).
    pub(crate) pps_recv: u64,
    /// Current iteration this session is on (1-based, 0 before start).
    pub(crate) iter_current: u64,
    /// Total iterations planned (0 = unbounded).
    pub(crate) iter_total: u64,
}
