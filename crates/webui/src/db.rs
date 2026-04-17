//! SQLite persistence for run history.
//!
//! Schema (v1):
//!
//! ```sql
//! CREATE TABLE runs (
//!     id            INTEGER PRIMARY KEY,
//!     started_at    INTEGER NOT NULL,
//!     finished_at   INTEGER,
//!     status        TEXT NOT NULL,
//!     pcap          TEXT NOT NULL,
//!     target_ip     TEXT NOT NULL,
//!     target_mac    TEXT NOT NULL,
//!     mode          TEXT NOT NULL,
//!     role          TEXT NOT NULL,
//!     target_port   INTEGER NOT NULL,
//!     speed         REAL NOT NULL,
//!     top_speed     INTEGER NOT NULL,
//!     realtime      INTEGER NOT NULL,
//!     planned       INTEGER NOT NULL DEFAULT 0,
//!     sent          INTEGER NOT NULL DEFAULT 0,
//!     bytes         INTEGER NOT NULL DEFAULT 0,
//!     error         TEXT,
//!     report_json   TEXT,
//!     benchmark_json TEXT,
//!     per_source_json TEXT,
//!     throughput_json TEXT
//! );
//! ```
//!
//! All operations are synchronous — rusqlite only — and protected by
//! the AppState mutex. SQLite is fast enough at this scale that
//! blocking the tokio executor briefly is fine.

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

#[derive(Debug, Clone)]
pub struct StoredRun {
    pub id: u64,
    pub started_at: u64,
    pub status: String,
    pub pcap: String,
    pub target_ip: String,
    pub target_mac: String,
    pub mode: String,
    pub role: String,
    pub target_port: u16,
    pub speed: f64,
    pub top_speed: bool,
    pub realtime: bool,
    /// Free-form JSON the run was started with as the protocol
    /// replayer's `proto_config`. Persisted so the post-run analyser
    /// can read protocol-specific settings (e.g. IEC 104 CP56 rewrite
    /// + zone, ASDU rewrite map). Optional — `None` means defaults.
    pub proto_config: Option<String>,
    pub planned: u64,
    pub sent: u64,
    pub bytes: u64,
    pub error: Option<String>,
    pub report_json: Option<String>,
    pub benchmark_json: Option<String>,
    pub per_source_json: Option<String>,
    pub throughput_json: Option<String>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path).with_context(|| format!("open sqlite at {path:?}"))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            CREATE TABLE IF NOT EXISTS runs (
                id              INTEGER PRIMARY KEY,
                started_at      INTEGER NOT NULL,
                finished_at     INTEGER,
                status          TEXT NOT NULL,
                pcap            TEXT NOT NULL,
                target_ip       TEXT NOT NULL,
                target_mac      TEXT NOT NULL,
                mode            TEXT NOT NULL,
                role            TEXT NOT NULL,
                target_port     INTEGER NOT NULL,
                speed           REAL NOT NULL,
                top_speed       INTEGER NOT NULL,
                realtime        INTEGER NOT NULL,
                planned         INTEGER NOT NULL DEFAULT 0,
                sent            INTEGER NOT NULL DEFAULT 0,
                bytes           INTEGER NOT NULL DEFAULT 0,
                error           TEXT,
                report_json     TEXT,
                benchmark_json  TEXT,
                per_source_json TEXT,
                throughput_json TEXT,
                proto_config    TEXT
            );
            "#,
        )
        .context("create schema")?;
        // Forward migrations for databases created before these
        // columns existed. Each ALTER is ignored if the column is
        // already present (sqlite errors are absorbed).
        //
        // Older schemas had typed `rewrite_cp56_to_now` /
        // `cp56_zone` columns for IEC 104. Those have been folded into
        // the generic `proto_config` JSON; the legacy ALTERs are kept
        // here so DBs that pre-date the JSON migration stay readable.
        let _ = conn.execute(
            "ALTER TABLE runs ADD COLUMN rewrite_cp56_to_now INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE runs ADD COLUMN cp56_zone TEXT NOT NULL DEFAULT 'local'",
            [],
        );
        let _ = conn.execute("ALTER TABLE runs ADD COLUMN proto_config TEXT", []);
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Insert a row when a run starts. `report_json` etc. are NULL at
    /// this point and get filled in by [`Db::update_finished`].
    pub fn insert_run_start(&self, run: &StoredRun) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO runs
             (id, started_at, status, pcap, target_ip, target_mac, mode, role,
              target_port, speed, top_speed, realtime, planned, sent, bytes,
              proto_config)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                run.id as i64,
                run.started_at as i64,
                run.status,
                run.pcap,
                run.target_ip,
                run.target_mac,
                run.mode,
                run.role,
                run.target_port as i64,
                run.speed,
                run.top_speed as i64,
                run.realtime as i64,
                run.planned as i64,
                run.sent as i64,
                run.bytes as i64,
                run.proto_config,
            ],
        )?;
        Ok(())
    }

    /// Update a row when a run completes/fails/stops. Pass the full
    /// final state including any reports.
    pub fn update_finished(
        &self,
        id: u64,
        status: &str,
        error: Option<&str>,
        report_json: Option<&str>,
        benchmark_json: Option<&str>,
        per_source_json: Option<&str>,
        throughput_json: Option<&str>,
        planned: u64,
        sent: u64,
        bytes: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let finished_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        conn.execute(
            "UPDATE runs SET
                status = ?2,
                finished_at = ?3,
                error = ?4,
                report_json = ?5,
                benchmark_json = ?6,
                per_source_json = ?7,
                throughput_json = ?8,
                planned = ?9,
                sent = ?10,
                bytes = ?11
             WHERE id = ?1",
            params![
                id as i64,
                status,
                finished_at,
                error,
                report_json,
                benchmark_json,
                per_source_json,
                throughput_json,
                planned as i64,
                sent as i64,
                bytes as i64,
            ],
        )?;
        Ok(())
    }

    /// Mark every row whose status is still "running" as failed —
    /// called once at server startup so a previous-process crash
    /// doesn't leave runs stuck in the running state forever.
    pub fn mark_orphans_failed(&self, message: &str) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE runs SET status = 'failed', error = COALESCE(error, ?1)
             WHERE status = 'running'",
            params![message],
        )?;
        Ok(n)
    }

    /// Load every persisted run back into memory at startup.
    pub fn load_all(&self) -> Result<Vec<StoredRun>> {
        let conn = self.conn.lock().unwrap();
        // SELECT both the new proto_config column and the legacy
        // CP56 columns so DBs written by either schema generation
        // round-trip cleanly. The mapping below prefers proto_config
        // when present and synthesises an IEC 104 JSON from the legacy
        // columns when not — keeping pre-migration runs analysable.
        let mut stmt = conn.prepare(
            "SELECT id, started_at, status, pcap, target_ip, target_mac, mode, role,
                    target_port, speed, top_speed, realtime, planned, sent, bytes,
                    error, report_json, benchmark_json, per_source_json, throughput_json,
                    proto_config, rewrite_cp56_to_now, cp56_zone
             FROM runs
             ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            let proto_config_raw: Option<String> = row.get(20).ok();
            // Legacy IEC 104 columns. Optional because future schemas
            // may drop them entirely; tolerate absence by mapping to None.
            let legacy_rewrite: Option<bool> = row
                .get::<_, Option<i64>>(21)
                .ok()
                .flatten()
                .map(|v| v != 0);
            let legacy_zone: Option<String> = row.get::<_, Option<String>>(22).ok().flatten();
            // Migration: if proto_config is unset but the legacy
            // CP56 columns hold non-default values, synthesise a tiny
            // IEC 104 proto_config JSON so the analyser can still
            // interpret CP56 drift correctly.
            let proto_config = proto_config_raw.or_else(|| {
                let rewrite = legacy_rewrite.unwrap_or(false);
                let zone = legacy_zone.clone().unwrap_or_else(|| "local".into());
                if rewrite || zone != "local" {
                    Some(format!(
                        r#"{{"cp56":{{"rewrite_to_now":{},"zone":"{}"}}}}"#,
                        rewrite, zone
                    ))
                } else {
                    None
                }
            });
            Ok(StoredRun {
                id: row.get::<_, i64>(0)? as u64,
                started_at: row.get::<_, i64>(1)? as u64,
                status: row.get(2)?,
                pcap: row.get(3)?,
                target_ip: row.get(4)?,
                target_mac: row.get(5)?,
                mode: row.get(6)?,
                role: row.get(7)?,
                target_port: row.get::<_, i64>(8)? as u16,
                speed: row.get(9)?,
                top_speed: row.get::<_, i64>(10)? != 0,
                realtime: row.get::<_, i64>(11)? != 0,
                planned: row.get::<_, i64>(12)? as u64,
                sent: row.get::<_, i64>(13)? as u64,
                bytes: row.get::<_, i64>(14)? as u64,
                error: row.get(15)?,
                report_json: row.get(16)?,
                benchmark_json: row.get(17)?,
                per_source_json: row.get(18)?,
                throughput_json: row.get(19)?,
                proto_config,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn delete(&self, id: u64) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute("DELETE FROM runs WHERE id = ?1", params![id as i64])?)
    }

    /// Highest existing run id, used to seed the in-memory next-id
    /// counter so new runs don't collide with restored ones.
    pub fn max_id(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let id: i64 = conn
            .query_row("SELECT COALESCE(MAX(id), 0) FROM runs", [], |row| row.get(0))?;
        Ok(id as u64)
    }
}
