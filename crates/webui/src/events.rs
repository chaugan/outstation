//! Server-sent event stream of run lifecycle events (`GET /api/events`).
//!
//! Every event is sent as
//!
//! ```text
//! event: run_started            (or run_finished / run_stopped)
//! data: {"type":"run_started","run_id":3,"client_ip":"10.0.0.5",
//!        "client_id":"tab-abc","time":1730000000,"status":"running"}
//! ```
//!
//! `client_ip` is the peer that caused the event (the starter for
//! `run_started`/`run_finished`, the stopper for `run_stopped`).
//! `client_id` echoes the optional `X-Client-Id` request header so a
//! browser tab can recognise its own actions. On connect the stream
//! first sends one `hello` event whose `active` field describes the
//! active run (or null).

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::Stream;
use serde::Serialize;
use tokio::sync::broadcast::error::RecvError;

use crate::state::{ActiveRun, AppState};

#[derive(Clone, Debug, Serialize)]
pub struct RunEvent {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub run_id: u64,
    pub client_ip: String,
    pub client_id: Option<String>,
    pub time: u64,
    pub status: &'static str,
}

#[derive(Serialize)]
struct Hello {
    #[serde(rename = "type")]
    kind: &'static str,
    active: Option<ActiveRun>,
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl AppState {
    pub(crate) fn emit(
        &self,
        kind: &'static str,
        run_id: u64,
        client_ip: &str,
        client_id: Option<String>,
        status: &'static str,
    ) {
        // No subscribers is fine.
        let _ = self.events.send(RunEvent {
            kind,
            run_id,
            client_ip: client_ip.to_string(),
            client_id,
            time: now_secs(),
            status,
        });
    }
}

fn to_event<T: Serialize>(name: &str, v: &T) -> Event {
    Event::default()
        .event(name)
        .json_data(v)
        .unwrap_or_else(|_| Event::default().event(name).data("{}"))
}

pub(crate) async fn api_events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.events.subscribe();
    let token = state.shutdown.clone();
    let hello = to_event(
        "hello",
        &Hello {
            kind: "hello",
            active: state.active_run(),
        },
    );
    let stream = futures_util::stream::unfold(
        (Some(hello), rx, token),
        |(mut first, mut rx, token)| async move {
            if let Some(ev) = first.take() {
                return Some((Ok(ev), (None, rx, token)));
            }
            loop {
                tokio::select! {
                    _ = token.cancelled() => return None,
                    r = rx.recv() => match r {
                        Ok(ev) => return Some((Ok(to_event(ev.kind, &ev)), (None, rx, token))),
                        Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => return None,
                    },
                }
            }
        },
    );
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}
