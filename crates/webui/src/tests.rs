//! Axum-level API tests: the real router driven with
//! `tower::ServiceExt::oneshot`, a temp state dir and a real SQLite DB.
//! Runs use a fake [`RunExecutor`] so the lifecycle can be exercised
//! without CAP_NET_ADMIN.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use pcapload::LoadedPcap;
use sched::{BenchmarkConfig, BenchmarkReport, RunConfig, RunContext, RunReport, SessionReport};
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::error::LockExt;
use crate::runs::RunExecutor;
use crate::state::{AppState, ServeConfig};

const HOST: &str = "127.0.0.1:8080";
const ORIGIN: &str = "http://127.0.0.1:8080";

#[derive(Clone, Copy)]
enum Behaviour {
    /// Block until the run is cancelled, then return an empty report.
    BlockUntilCancel,
    Panic,
    /// One session per entry; `Some(err)` marks it failed.
    Sessions(&'static [Option<&'static str>]),
}

/// Host-safety fields of the last job handed to the executor:
/// (run_id, protected_addrs, force, bridge_name, tap_prefix).
type SeenCfg = (
    u64,
    Vec<std::net::IpAddr>,
    bool,
    Option<String>,
    Option<String>,
);

struct Fake {
    behaviour: Behaviour,
    entered: Arc<AtomicBool>,
    seen: Arc<std::sync::Mutex<Option<SeenCfg>>>,
}

impl Fake {
    fn bench(&self, ctx: &RunContext) -> Result<BenchmarkReport> {
        self.entered.store(true, Ordering::SeqCst);
        match self.behaviour {
            Behaviour::BlockUntilCancel => {
                while !ctx.is_cancelled() {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(BenchmarkReport::default())
            }
            Behaviour::Panic => panic!("boom in sched"),
            Behaviour::Sessions(s) => Ok(BenchmarkReport {
                per_session: s
                    .iter()
                    .enumerate()
                    .map(|(i, e)| SessionReport {
                        src_ip: Ipv4Addr::new(10, 0, 0, i as u8 + 1),
                        src_mac: [0; 6],
                        tap: String::new(),
                        flow_idx: i,
                        started_at_ns: 0,
                        proto_report: protoplay::ProtoReport {
                            messages_sent: 10,
                            latency_samples_us: vec![100; 10],
                            error: e.map(str::to_string),
                            ..Default::default()
                        },
                    })
                    .collect(),
                total_messages_sent: 10 * s.len() as u64,
                ..Default::default()
            }),
        }
    }
}

impl RunExecutor for Fake {
    fn run_raw(&self, _: Arc<LoadedPcap>, c: RunConfig, ctx: RunContext) -> Result<RunReport> {
        *self.seen.lock().unwrap() = Some((
            c.run_id,
            c.protected_addrs.clone(),
            c.force_protected_nic,
            c.bridge_name.clone(),
            c.tap_prefix.clone(),
        ));
        self.bench(&ctx).map(|_| RunReport::default())
    }
    fn run_benchmark(
        &self,
        _: Arc<LoadedPcap>,
        c: BenchmarkConfig,
        _: Arc<dyn protoplay::ProtoReplayer>,
        ctx: RunContext,
    ) -> Result<BenchmarkReport> {
        *self.seen.lock().unwrap() = Some((
            c.run_id,
            c.protected_addrs.clone(),
            c.force_protected_nic,
            c.bridge_name.clone(),
            c.tap_prefix.clone(),
        ));
        self.bench(&ctx)
    }
}

/// A minimal classic pcap with `n` Ethernet/IPv4/UDP frames.
fn tiny_pcap(n: usize) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&4u16.to_le_bytes());
    v.extend_from_slice(&0i32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&65535u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    for i in 0..n {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00]);
        let payload = [0u8; 4];
        let total = 20 + 8 + payload.len();
        f.extend_from_slice(&[
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0,
            0,
            64,
            17,
            0,
            0,
        ]);
        f.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        f.extend_from_slice(&[0x13, 0x88, 0x13, 0x89, 0, 12, 0, 0]);
        f.extend_from_slice(&payload);
        v.extend_from_slice(&(1_700_000_000u32 + i as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(f.len() as u32).to_le_bytes());
        v.extend_from_slice(&(f.len() as u32).to_le_bytes());
        v.extend_from_slice(&f);
    }
    v
}

struct H {
    state: AppState,
    app: Router,
    dir: tempfile::TempDir,
    entered: Arc<AtomicBool>,
    seen: Arc<std::sync::Mutex<Option<SeenCfg>>>,
}

fn cfg_for(dir: &Path) -> ServeConfig {
    ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        library_dir: dir.join("state/library"),
        state_dir: dir.join("state"),
        ephemeral: false,
        allow_hosts: vec!["outstation.lan".into()],
        max_upload_bytes: 64 * 1024,
        min_free_bytes: 0,
        capture_max_total_bytes: u64::MAX,
        capture_max_count: 1000,
        heavy_concurrency: 2,
    }
}

fn harness(b: Behaviour) -> H {
    let dir = tempfile::tempdir().unwrap();
    harness_in(dir, b)
}

fn harness_in(dir: tempfile::TempDir, b: Behaviour) -> H {
    harness_cfg(dir, b, |_| {})
}

fn harness_cfg(dir: tempfile::TempDir, b: Behaviour, f: impl FnOnce(&mut ServeConfig)) -> H {
    let entered = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(std::sync::Mutex::new(None));
    let fake = Arc::new(Fake {
        behaviour: b,
        entered: entered.clone(),
        seen: seen.clone(),
    });
    let mut cfg = cfg_for(dir.path());
    f(&mut cfg);
    let state = AppState::open_with_executor(cfg, fake).unwrap();
    crate::restore(&state).unwrap();
    let app = crate::router(state.clone()).layer(MockConnectInfo(crate::security::ConnAddrs::new(
        SocketAddr::from(([10, 0, 0, 7], 5555)),
        Some(SocketAddr::from(([10, 0, 0, 1], 8080))),
    )));
    H {
        state,
        app,
        dir,
        entered,
        seen,
    }
}

impl H {
    fn add_pcap(&self, id: &str) -> PathBuf {
        let p = self.state.library_dir.join(format!("{id}.pcap"));
        std::fs::write(&p, tiny_pcap(3)).unwrap();
        let e = json!({"id": id, "name": format!("{id} name"), "uploaded_at_ms": 1,
            "size_bytes": 1, "packets": 3, "ip_sources": 1, "non_ip_sources": 0,
            "tcp_flows": 0, "duration_ms": 0.0});
        std::fs::write(
            self.state.library_dir.join(format!("{id}.json")),
            e.to_string(),
        )
        .unwrap();
        p
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, headers, body)
    }

    async fn call(&self, method: Method, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut b = Request::builder()
            .method(method.clone())
            .uri(uri)
            .header("host", HOST);
        if method != Method::GET {
            b = b.header("origin", ORIGIN);
        }
        let req = match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let (s, _, bytes) = self.send(req).await;
        let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (s, v)
    }

    async fn multipart(
        &self,
        uri: &str,
        parts: &[(&str, Option<&str>, Vec<u8>)],
    ) -> (StatusCode, Value) {
        let boundary = "XBOUNDARYX";
        let mut body = Vec::new();
        for (name, filename, data) in parts {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            match filename {
                Some(f) => body.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\n\
                         Content-Type: application/octet-stream\r\n\r\n"
                    )
                    .as_bytes(),
                ),
                None => body.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
                ),
            }
            body.extend_from_slice(data);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("host", HOST)
            .header("origin", ORIGIN)
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        let (s, _, bytes) = self.send(req).await;
        (s, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn wait_status(&self, id: u64, want: &str) -> Value {
        for _ in 0..400 {
            let (_, v) = self
                .call(Method::GET, &format!("/api/runs/{id}"), None)
                .await;
            if v["status"] == want {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("run {id} never reached {want}");
    }

    fn files_in(&self, sub: &str) -> Vec<String> {
        std::fs::read_dir(self.dir.path().join(sub))
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn bench_req(pcap_id: &str) -> Value {
    json!({"pcap_id": pcap_id, "target_ip": "10.0.0.50", "mode": "benchmark",
           "role": "master", "warmup_secs": 0})
}

// ---------------------------------------------------------------------------
// Same-origin / Host guard (F042, F046, F050)

#[tokio::test]
async fn host_and_origin_guard() {
    let h = harness(Behaviour::BlockUntilCancel);
    let get = |host: &str| {
        Request::builder()
            .uri("/api/status")
            .header("host", host)
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(h.send(get("127.0.0.1:8080")).await.0, StatusCode::OK);
    assert_eq!(h.send(get("outstation.lan:8080")).await.0, StatusCode::OK);
    let (s, _, b) = h.send(get("evil.example")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["code"], "host_not_allowed");

    // POST without Origin, with a foreign Origin, and with a matching one.
    let post = |origin: Option<&str>| {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/api/runs/1/stop")
            .header("host", HOST);
        if let Some(o) = origin {
            b = b.header("origin", o);
        }
        b.body(Body::empty()).unwrap()
    };
    assert_eq!(h.send(post(None)).await.0, StatusCode::FORBIDDEN);
    assert_eq!(
        h.send(post(Some("http://evil.example"))).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(h.send(post(Some(ORIGIN))).await.0, StatusCode::NOT_FOUND);

    // Cross-site WebSocket upgrade is refused before the handler.
    let ws = Request::builder()
        .uri("/api/runs/1/live")
        .header("host", HOST)
        .header("upgrade", "websocket")
        .header("origin", "http://evil.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(h.send(ws).await.0, StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Error shape and validation (F056, F052, F148, F089, F049, F092, F146)

#[tokio::test]
async fn errors_have_common_shape() {
    let h = harness(Behaviour::BlockUntilCancel);
    h.add_pcap("pcr_1");
    let (s, v) = h.call(Method::GET, "/api/nope", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(v["code"], "not_found");
    let (s, v) = h.call(Method::GET, "/api/runs/abc", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["code"], "invalid_path");
    // Unknown enum value: 422 with JSON body, not plain text.
    let mut r = bench_req("pcr_1");
    r["mode"] = json!("benchmrk");
    let (s, v) = h.call(Method::POST, "/api/run", Some(r)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v["code"], "invalid_request");
    assert!(v["error"].as_str().unwrap().contains("benchmrk"));
}

#[tokio::test]
async fn invalid_requests_never_create_runs() {
    let h = harness(Behaviour::BlockUntilCancel);
    h.add_pcap("pcr_1");
    let cases = [
        (
            json!({"pcap_id": "pcr_1", "target_ip": "10.0.0.50", "target_mac": "zz"}),
            "invalid_request",
        ),
        (
            json!({"pcap": "/etc/hostname", "target_ip": "10.0.0.50"}),
            "raw_path_rejected",
        ),
        (
            {
                let mut r = bench_req("pcr_1");
                r["speed"] = json!(0.0);
                r
            },
            "invalid_request",
        ),
        (
            {
                let mut r = bench_req("pcr_1");
                r["proto_name"] = json!("modbus_tcp");
                r
            },
            "protocol_not_ready",
        ),
        (
            {
                let mut r = bench_req("pcr_1");
                r["proto_name"] = json!("nope");
                r
            },
            "invalid_request",
        ),
        (
            {
                let mut r = bench_req("pcr_1");
                r["nic"] = json!("+");
                r
            },
            "invalid_request",
        ),
        (
            {
                let mut r = bench_req("pcr_1");
                r["proto_config"] = json!("{not json");
                r
            },
            "invalid_request",
        ),
        (bench_req("../../etc/passwd"), "invalid_id"),
        (bench_req("pcr_404"), "not_found"),
    ];
    for (req, code) in cases {
        let (s, v) = h.call(Method::POST, "/api/run", Some(req.clone())).await;
        assert!(s.is_client_error(), "{req}: {s}");
        assert_eq!(v["code"], code, "{req}: {v}");
    }
    let (_, runs) = h.call(Method::GET, "/api/runs", None).await;
    assert_eq!(runs, json!([]));
    assert!(h.state.db.load_all().unwrap().is_empty());
    assert!(h.state.active_run().is_none());
}

#[tokio::test]
async fn inspect_takes_library_ids_only() {
    let h = harness(Behaviour::BlockUntilCancel);
    h.add_pcap("pcr_1");
    let (s, v) = h
        .call(
            Method::POST,
            "/api/inspect",
            Some(json!({"path": "/etc/hostname"})),
        )
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("raw_path_rejected"))
    );
    let (s, v) = h
        .call(
            Method::POST,
            "/api/inspect",
            Some(json!({"pcap_id": "../x"})),
        )
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_id"))
    );
    let (s, v) = h
        .call(
            Method::POST,
            "/api/inspect",
            Some(json!({"pcap_id": "pcr_1"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["packets"], 3);
}

// ---------------------------------------------------------------------------
// Run lifecycle (F037, F048, F070, F074, F086, F094, F030)

#[tokio::test]
async fn second_run_gets_409_until_first_stops() {
    let h = harness(Behaviour::BlockUntilCancel);
    h.add_pcap("pcr_1");
    let mut rx = h.state.events.subscribe();
    let (s, v) = h
        .call(Method::POST, "/api/run", Some(bench_req("pcr_1")))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_u64().unwrap();
    assert_eq!(id, 1);
    let ev = rx.recv().await.unwrap();
    assert_eq!(
        (ev.kind, ev.run_id, ev.client_ip.as_str()),
        ("run_started", 1, "10.0.0.7")
    );

    let (s, v) = h
        .call(Method::POST, "/api/run", Some(bench_req("pcr_1")))
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(v["code"], "run_active");
    assert_eq!(v["active_run_id"], 1);
    assert_eq!(v["client_ip"], "10.0.0.7");
    assert!(v["started_at"].as_u64().unwrap() > 0);

    // ?status=running filter and slim summary.
    let (_, running) = h.call(Method::GET, "/api/runs?status=running", None).await;
    assert_eq!(running.as_array().unwrap().len(), 1);
    assert_eq!(running[0]["started_by"], "10.0.0.7");
    let (s, _) = h.call(Method::GET, "/api/runs?status=bogus", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Deleting a live run is refused.
    let (s, _) = h.call(Method::DELETE, "/api/runs/1", None).await;
    assert_eq!(s, StatusCode::CONFLICT);

    let (s, _) = h.call(Method::POST, "/api/runs/1/stop", None).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let ev = rx.recv().await.unwrap();
    assert_eq!(ev.kind, "run_stopped");
    h.wait_status(1, "stopped").await;
    let ev = rx.recv().await.unwrap();
    assert_eq!((ev.kind, ev.status), ("run_finished", "stopped"));
    assert!(h.state.active_run().is_none());

    let (s, v) = h
        .call(Method::POST, "/api/run", Some(bench_req("pcr_1")))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["id"], 2);
    let (s, _) = h.call(Method::POST, "/api/runs/2/stop", None).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    h.wait_status(2, "stopped").await;
}

#[tokio::test]
async fn panicking_worker_marks_run_failed_and_frees_slot() {
    let h = harness(Behaviour::Panic);
    h.add_pcap("pcr_1");
    let (s, _) = h
        .call(Method::POST, "/api/run", Some(bench_req("pcr_1")))
        .await;
    assert_eq!(s, StatusCode::OK);
    let v = h.wait_status(1, "failed").await;
    assert!(
        v["error"].as_str().unwrap().contains("boom in sched"),
        "{v}"
    );
    assert!(v["finished_at"].as_u64().is_some());
    assert!(h.state.active_run().is_none());
    let row = &h.state.db.load_all().unwrap()[0];
    assert_eq!(row.status, "failed");
    assert!(row.finished_at.is_some());
}

#[tokio::test]
async fn status_is_derived_from_sessions() {
    for (sessions, want) in [
        (&[None, None][..], "completed"),
        (&[None, Some("bind failed")][..], "partial"),
        (&[Some("bind failed"), Some("bind failed")][..], "failed"),
        (&[][..], "failed"),
    ] {
        let h = harness(Behaviour::Sessions(sessions));
        h.add_pcap("pcr_1");
        let (s, _) = h
            .call(Method::POST, "/api/run", Some(bench_req("pcr_1")))
            .await;
        assert_eq!(s, StatusCode::OK);
        let v = h.wait_status(1, want).await;
        if want != "completed" {
            assert!(v["error"].is_string(), "{v}");
        }
        // Slim list carries counts but no per-session rows or samples.
        let (_, list) = h.call(Method::GET, "/api/runs", None).await;
        let b = &list[0]["benchmark"];
        assert_eq!(b["sessions"], sessions.len());
        assert!(b.get("per_session").is_none());
        assert!(b.get("aggregate_latency_histogram").is_none());
        // Detail has them, as a histogram (no raw samples).
        if !sessions.is_empty() {
            assert_eq!(
                v["benchmark"]["per_session"].as_array().unwrap().len(),
                sessions.len()
            );
            assert_eq!(
                v["benchmark"]["aggregate_latency_histogram"]["total"],
                10 * sessions.len()
            );
            assert!(v["benchmark"].get("aggregate_latency_samples_us").is_none());
        }
    }
}

#[tokio::test]
async fn stop_and_delete_clear_a_run_without_worker() {
    let h = harness(Behaviour::BlockUntilCancel);
    // A run marked running whose worker does not exist (e.g. the thread
    // died before it could finalise).
    let mut rs = crate::persist::stored_to_runstate(
        &crate::db::StoredRun {
            id: 9,
            status: "running".into(),
            target_ip: "10.0.0.1".into(),
            mode: "raw".into(),
            ..Default::default()
        },
        &h.state.cfg.library_dir,
        &h.state.cfg.captures_dir(),
    )
    .unwrap();
    rs.status = crate::dto::RunStatus::Running;
    h.state
        .db
        .insert_run_start(&crate::persist::runstate_to_stored(&rs))
        .unwrap();
    h.state
        .runs
        .lock_safe()
        .insert(9, Arc::new(std::sync::Mutex::new(rs)));
    let (s, v) = h.call(Method::POST, "/api/runs/9/stop", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "stopped");
    let (s, _) = h.call(Method::DELETE, "/api/runs/9", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(h.state.db.load_all().unwrap().is_empty());
}

#[tokio::test]
async fn graceful_shutdown_cancels_and_joins_workers() {
    let h = harness(Behaviour::BlockUntilCancel);
    h.add_pcap("pcr_1");
    let (s, _) = h
        .call(Method::POST, "/api/run", Some(bench_req("pcr_1")))
        .await;
    assert_eq!(s, StatusCode::OK);
    while !h.entered.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let left = crate::shutdown(&h.state, Duration::from_secs(5)).await;
    assert!(left.is_empty());
    assert_eq!(h.state.db.load_all().unwrap()[0].status, "stopped");
    // New runs are refused while shutting down.
    let (s, v) = h
        .call(Method::POST, "/api/run", Some(bench_req("pcr_1")))
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("shutting_down"))
    );
}

// ---------------------------------------------------------------------------
// Persistence across restart (F073, F078, F090)

#[tokio::test]
async fn restart_restores_history_and_never_reuses_ids() {
    let h = harness(Behaviour::Sessions(&[None]));
    h.add_pcap("pcr_1");
    for want in [1, 2] {
        let (_, v) = h
            .call(Method::POST, "/api/run", Some(bench_req("pcr_1")))
            .await;
        assert_eq!(v["id"], want);
        h.wait_status(want, "completed").await;
    }
    let (s, _) = h.call(Method::DELETE, "/api/runs/2", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let H { state, dir, .. } = h;
    drop(state);
    let h = harness_in(dir, Behaviour::Sessions(&[None]));
    let (_, list) = h.call(Method::GET, "/api/runs", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["pcap_id"], "pcr_1");
    let (_, v) = h
        .call(Method::POST, "/api/run", Some(bench_req("pcr_1")))
        .await;
    assert_eq!(v["id"], 3, "deleted id 2 must not be reused");
}

#[tokio::test]
async fn db_open_failure_is_fatal_unless_ephemeral() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = cfg_for(dir.path());
    std::fs::create_dir_all(&cfg.state_dir).unwrap();
    // A directory where the DB file should be makes open fail.
    std::fs::create_dir_all(cfg.db_path()).unwrap();
    assert!(AppState::open(cfg.clone()).is_err());
    cfg.ephemeral = true;
    let st = AppState::open(cfg).unwrap();
    assert!(st.db.path().is_none());
}

// ---------------------------------------------------------------------------
// Captures (F055, F072, F133, F149)

#[tokio::test]
async fn benchmark_capture_downloads_from_state_dir() {
    let h = harness(Behaviour::Sessions(&[None]));
    h.add_pcap("pcr_1");
    let (_, v) = h
        .call(Method::POST, "/api/run", Some(bench_req("pcr_1")))
        .await;
    let id = v["id"].as_u64().unwrap();
    h.wait_status(id, "completed").await;
    let (s, _) = h
        .call(Method::GET, &format!("/api/runs/{id}/download"), None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "no capture written by the fake");
    let cap = h.state.cfg.captures_dir().join(format!("run_{id}.pcap"));
    assert!(cap.starts_with(h.dir.path()));
    std::fs::write(&cap, tiny_pcap(2)).unwrap();
    let (_, list) = h.call(Method::GET, "/api/runs", None).await;
    assert_eq!(list[0]["has_capture"], true);
    let req = Request::builder()
        .uri(format!("/api/runs/{id}/download"))
        .header("host", HOST)
        .body(Body::empty())
        .unwrap();
    let (s, hd, body) = h.send(req).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body, tiny_pcap(2));
    assert_eq!(
        hd["content-disposition"],
        "attachment; filename=\"run_1.pcap\"; filename*=UTF-8''run_1.pcap"
    );
    // Deleting the run removes its capture.
    h.call(Method::DELETE, &format!("/api/runs/{id}"), None)
        .await;
    assert!(!cap.exists());
}

// ---------------------------------------------------------------------------
// Library (F057, F077, F091, F101, F151)

#[tokio::test]
async fn library_ids_are_validated_everywhere() {
    let h = harness(Behaviour::BlockUntilCancel);
    // A JSON file outside the library that parses as an entry.
    std::fs::write(
        h.dir.path().join("state/evil.json"),
        json!({"id": "x", "name": "n", "uploaded_at_ms": 1, "size_bytes": 1, "packets": 0,
               "ip_sources": 0, "non_ip_sources": 0, "tcp_flows": 0, "duration_ms": 0.0})
        .to_string(),
    )
    .unwrap();
    for id in ["..%2Fevil", "..%2F..%2Fetc%2Fpasswd", "a.b"] {
        let (s, v) = h
            .call(
                Method::PATCH,
                &format!("/api/pcaps/{id}"),
                Some(json!({"name": "x"})),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{id}: {v}");
        assert_eq!(v["code"], "invalid_id");
        let (s, _) = h
            .call(Method::DELETE, &format!("/api/pcaps/{id}"), None)
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = h
            .call(Method::GET, &format!("/api/pcaps/{id}/download"), None)
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }
    // A symlink inside the library pointing outside is refused.
    std::os::unix::fs::symlink(
        h.dir.path().join("state/evil.json"),
        h.state.library_dir.join("pcr_link.json"),
    )
    .unwrap();
    let (s, v) = h
        .call(
            Method::PATCH,
            "/api/pcaps/pcr_link",
            Some(json!({"name": "x"})),
        )
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_id"))
    );
}

#[tokio::test]
async fn rename_uses_path_id_and_download_escapes_name() {
    let h = harness(Behaviour::BlockUntilCancel);
    h.add_pcap("pcr_1");
    // Sidecar claims a different id; the path id must win.
    let side = h.state.library_dir.join("pcr_1.json");
    let mut e: Value = serde_json::from_slice(&std::fs::read(&side).unwrap()).unwrap();
    e["id"] = json!("../../elsewhere");
    std::fs::write(&side, e.to_string()).unwrap();
    let (s, v) = h
        .call(
            Method::PATCH,
            "/api/pcaps/pcr_1",
            Some(json!({"name": "a \"quoted\" ø.pcap"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["id"], "pcr_1");
    let req = Request::builder()
        .uri("/api/pcaps/pcr_1/download")
        .header("host", HOST)
        .body(Body::empty())
        .unwrap();
    let (s, hd, body) = h.send(req).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body, tiny_pcap(3));
    assert_eq!(
        hd["content-disposition"],
        "attachment; filename=\"a _quoted_ _.pcap\"; \
         filename*=UTF-8''a%20%22quoted%22%20%C3%B8.pcap"
    );
}

#[tokio::test]
async fn library_delete_lists_dependent_runs() {
    let h = harness(Behaviour::Sessions(&[None]));
    h.add_pcap("pcr_1");
    let (_, v) = h
        .call(Method::POST, "/api/run", Some(bench_req("pcr_1")))
        .await;
    h.wait_status(v["id"].as_u64().unwrap(), "completed").await;
    let (s, v) = h.call(Method::DELETE, "/api/pcaps/pcr_1", None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(v["code"], "pcap_in_use");
    assert_eq!(v["runs"], json!([1]));
    let (s, _) = h
        .call(Method::DELETE, "/api/pcaps/pcr_1?force=1", None)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(!h.state.library_dir.join("pcr_1.pcap").exists());
}

#[tokio::test]
async fn uploads_leave_no_part_files() {
    let h = harness(Behaviour::BlockUntilCancel);
    // Not a pcap: rejected, nothing left behind.
    let (s, v) = h
        .multipart(
            "/api/pcaps",
            &[("file", Some("x.pcap"), b"hello world".to_vec())],
        )
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("not_a_pcap"))
    );
    // Over the size cap: 413, nothing left behind.
    let mut big = tiny_pcap(1);
    big.resize(100 * 1024, 0);
    let (s, v) = h
        .multipart("/api/pcaps", &[("file", Some("big.pcap"), big)])
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::PAYLOAD_TOO_LARGE, Some("too_large"))
    );
    assert!(
        h.files_in("state/library").is_empty(),
        "{:?}",
        h.files_in("state/library")
    );
    // A good upload lands as <id>.pcap + <id>.json.
    let (s, v) = h
        .multipart("/api/pcaps", &[("file", Some("ok.pcap"), tiny_pcap(2))])
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    assert!(h.state.library_dir.join(format!("{id}.pcap")).is_file());
    // The upload's own temp file is gone as soon as the request returns.
    assert!(!h.state.library_dir.join(format!(".{id}.part")).exists());
    // The background viability pass writes its sidecar atomically via a
    // transient `.<id>.json.part`; wait for it to settle, then require
    // that nothing `.part` is left at all.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while h
        .files_in("state/library")
        .iter()
        .any(|f| f.ends_with(".part"))
    {
        assert!(
            std::time::Instant::now() < deadline,
            "{:?}",
            h.files_in("state/library")
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn startup_sweeps_part_and_tmp_files() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = cfg_for(dir.path());
    std::fs::create_dir_all(&cfg.library_dir).unwrap();
    std::fs::create_dir_all(cfg.tmp_dir()).unwrap();
    std::fs::write(cfg.library_dir.join(".pcr_5.part"), b"x").unwrap();
    std::fs::write(cfg.tmp_dir().join("analyze_x.pcap"), b"x").unwrap();
    let h = harness_in(dir, Behaviour::BlockUntilCancel);
    assert!(h.files_in("state/library").is_empty());
    assert!(h.files_in("state/tmp").is_empty());
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(h.state.cfg.tmp_dir())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
}

// ---------------------------------------------------------------------------
// Analyze (F051, F132, F108)

#[tokio::test]
async fn analyze_temp_file_removed_on_error_and_success() {
    let h = harness_cfg(
        tempfile::tempdir().unwrap(),
        Behaviour::Sessions(&[None]),
        |c| c.max_upload_bytes = 8 * 1024 * 1024,
    );
    // Real IEC 104 fixture so the success path runs the analyser.
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/synth_iec104_rtus200_ts.pcap");
    std::fs::copy(&fixture, h.state.library_dir.join("pcr_1.pcap")).unwrap();
    let mut r = bench_req("pcr_1");
    r["role"] = json!("slave");
    let (_, v) = h.call(Method::POST, "/api/run", Some(r)).await;
    let id = v["id"].as_u64().unwrap();
    h.wait_status(id, "completed").await;

    // Disagreeing run ids: error; temp file gone.
    let (s, v) = h
        .multipart(
            "/api/analyze?run_id=1",
            &[
                ("run_id", None, b"2".to_vec()),
                ("file", Some("c.pcap"), tiny_pcap(2)),
            ],
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(h.files_in("state/tmp").is_empty());

    // Unknown run: error after the upload was streamed; temp file gone.
    let (s, _) = h
        .multipart(
            "/api/analyze?run_id=77",
            &[("file", Some("c.pcap"), tiny_pcap(2))],
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(h.files_in("state/tmp").is_empty());

    // Oversized upload: 413; temp file gone.
    let mut big = tiny_pcap(1);
    big.resize(9 * 1024 * 1024, 0);
    let (s, _) = h
        .multipart("/api/analyze?run_id=1", &[("file", Some("c.pcap"), big)])
        .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(h.files_in("state/tmp").is_empty());

    // Success via the query-string run_id, analysing the source pcap
    // against itself.
    let capture = std::fs::read(&fixture).unwrap();
    let (s, v) = h
        .multipart(
            "/api/analyze?run_id=1",
            &[("file", Some("c.pcap"), capture)],
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["run_id"], 1);
    assert_eq!(v["run_selection"], "explicit");
    assert_eq!(v["warnings"], json!([]));
    assert!(h.files_in("state/tmp").is_empty());

    // T06 / F067: the analysis is stored; summary and per-endpoint
    // details are fetched separately.
    let aid = v["analysis_id"].as_u64().expect("analysis_id");
    let endpoint = v["slaves"][0]["slave_ip"].as_str().unwrap().to_string();
    let (s, list) = h.call(Method::GET, "/api/runs/1/analyses", None).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert_eq!(list[0]["id"], aid);
    assert_eq!(list[0]["verdict"], v["verdict"]);
    let (s, summary) = h
        .call(Method::GET, &format!("/api/analyses/{aid}"), None)
        .await;
    assert_eq!(s, StatusCode::OK, "{summary}");
    assert_eq!(summary["verdict"], v["verdict"]);
    assert!(summary.get("details_by_ip").is_none());
    let (s, detail) = h
        .call(
            Method::GET,
            &format!("/api/analyses/{aid}/endpoints/{endpoint}"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{detail}");
    assert_eq!(detail["verdict"], v["details_by_ip"][&endpoint]["verdict"]);
    let (s, _) = h
        .call(
            Method::GET,
            &format!("/api/analyses/{aid}/endpoints/192.0.2.1"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn analyze_warns_when_run_sent_nothing() {
    let h = harness_cfg(
        tempfile::tempdir().unwrap(),
        Behaviour::Sessions(&[Some("bind failed")]),
        |c| c.max_upload_bytes = 8 * 1024 * 1024,
    );
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/synth_iec104_rtus200_ts.pcap");
    std::fs::copy(&fixture, h.state.library_dir.join("pcr_1.pcap")).unwrap();
    let mut r = bench_req("pcr_1");
    r["role"] = json!("slave");
    h.call(Method::POST, "/api/run", Some(r)).await;
    h.wait_status(1, "failed").await;
    let capture = std::fs::read(&fixture).unwrap();
    // run_id only as a form field this time; no run_id at all is the
    // implicit "latest" path.
    let (s, v) = h
        .multipart("/api/analyze", &[("file", Some("c.pcap"), capture)])
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["run_selection"], "latest");
    let w = v["warnings"].to_string();
    assert!(w.to_lowercase().contains("failed"), "{w}");
    // F093: a failed run can never be certified.
    assert_ne!(v["verdict"], "all_correct", "{v}");
    assert!(v["run_warning"].is_string(), "{v}");
    assert!(h.files_in("state/tmp").is_empty());
}

// ---------------------------------------------------------------------------
// Status and events (F076)

#[tokio::test]
async fn status_reports_real_health() {
    let h = harness(Behaviour::BlockUntilCancel);
    let (s, v) = h.call(Method::GET, "/api/status", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["db"]["writable"], true);
    assert_eq!(v["db"]["ephemeral"], false);
    assert!(v["free_disk_bytes"].as_u64().is_some());
    assert!(v["capabilities"]["cap_eff"].is_string());
    assert_eq!(v["active_run"], Value::Null);
    assert!(v["version"].is_string());
}

#[tokio::test]
async fn event_stream_starts_with_hello() {
    let h = harness(Behaviour::BlockUntilCancel);
    let req = Request::builder()
        .uri("/api/events")
        .header("host", HOST)
        .body(Body::empty())
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let mut body = resp.into_body().into_data_stream();
    use futures_util::StreamExt;
    let first = tokio::time::timeout(Duration::from_secs(2), body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&first);
    assert!(text.contains("event: hello"), "{text}");
    assert!(text.contains("\"active\":null"), "{text}");
    // Shutdown ends the stream.
    h.state.shutdown.cancel();
    let end = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(chunk) = body.next().await {
            if chunk.is_err() {
                break;
            }
        }
    })
    .await;
    assert!(end.is_ok());
}

// ---------------------------------------------------------------------------
// T03/T04 integration: host-safety inputs reach sched

#[tokio::test]
async fn run_protects_ui_address_and_derives_names_from_run_id() {
    let h = harness(Behaviour::BlockUntilCancel);
    h.add_pcap("pcr_1");
    // Request-supplied bridge/tap names are ignored; `force` is threaded.
    let mut req = bench_req("pcr_1");
    req["bridge"] = json!("br0");
    req["tap_prefix"] = json!("eth");
    req["force"] = json!(true);
    let (s, v) = h.call(Method::POST, "/api/run", Some(req)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_u64().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let seen = loop {
        if let Some(c) = h.seen.lock().unwrap().clone() {
            break c;
        }
        assert!(std::time::Instant::now() < deadline, "executor never ran");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    let (run_id, protected, force, bridge, tap) = seen;
    assert_eq!(run_id, id, "sched gets the allocated run id");
    // MockConnectInfo's local address is 10.0.0.1: the address the UI
    // was reached on must be protected.
    assert_eq!(
        protected,
        vec!["10.0.0.1".parse::<std::net::IpAddr>().unwrap()]
    );
    assert!(force);
    assert_eq!((bridge, tap), (None, None), "names derived from run id");
}
