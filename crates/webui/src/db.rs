//! SQLite persistence for run history.
//!
//! The schema is versioned with `PRAGMA user_version` and upgraded by
//! [`migrate`] one step at a time:
//!
//! * v0 → v1: legacy column additions (`rewrite_cp56_to_now`,
//!   `cp56_zone`, `proto_config`, `proto`), applied only if missing.
//! * v1 → v2: rebuild `runs` with `INTEGER PRIMARY KEY AUTOINCREMENT`
//!   so ids are never reused (F073, F078), and add `started_by` and
//!   `pcap_id`.
//!
//! A fresh database is created directly at the latest version.
//!
//! All operations are synchronous rusqlite calls behind one mutex.
//! They are short (single-row writes, one bulk read at startup).

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use tracing::{info, warn};

use crate::error::LockExt;

/// Latest schema version understood by this binary.
pub const SCHEMA_VERSION: i64 = 2;

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
    path: Option<Arc<std::path::PathBuf>>,
}

#[derive(Debug, Clone, Default)]
pub struct StoredRun {
    pub id: u64,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub status: String,
    pub pcap: String,
    /// Library id of the source pcap, if the run used one.
    pub pcap_id: Option<String>,
    /// Peer address of the client that started the run.
    pub started_by: Option<String>,
    pub target_ip: String,
    pub target_mac: String,
    pub mode: String,
    pub role: String,
    pub target_port: u16,
    pub speed: f64,
    pub top_speed: bool,
    pub realtime: bool,
    /// Name of the protocol replayer the run used (e.g. `"iec104"`).
    /// Optional — legacy rows without this column fall back to
    /// `"iec104"` since that was the only shipped protocol.
    pub proto: Option<String>,
    /// Free-form JSON the run was started with as the protocol
    /// replayer's `proto_config`. `None` means defaults.
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

const CREATE_RUNS_V2: &str = r#"
    CREATE TABLE runs (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at          INTEGER NOT NULL,
        finished_at         INTEGER,
        status              TEXT NOT NULL,
        pcap                TEXT NOT NULL,
        target_ip           TEXT NOT NULL,
        target_mac          TEXT NOT NULL,
        mode                TEXT NOT NULL,
        role                TEXT NOT NULL,
        target_port         INTEGER NOT NULL,
        speed               REAL NOT NULL,
        top_speed           INTEGER NOT NULL,
        realtime            INTEGER NOT NULL,
        planned             INTEGER NOT NULL DEFAULT 0,
        sent                INTEGER NOT NULL DEFAULT 0,
        bytes               INTEGER NOT NULL DEFAULT 0,
        error               TEXT,
        report_json         TEXT,
        benchmark_json      TEXT,
        per_source_json     TEXT,
        throughput_json     TEXT,
        proto_config        TEXT,
        rewrite_cp56_to_now INTEGER NOT NULL DEFAULT 0,
        cp56_zone           TEXT NOT NULL DEFAULT 'local',
        proto               TEXT,
        started_by          TEXT,
        pcap_id             TEXT
    );
"#;

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![name],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for n in names {
        if n? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Bring the schema up to [`SCHEMA_VERSION`]. Each step runs in a
/// transaction and fails loudly; nothing is silently swallowed.
fn migrate(conn: &mut Connection) -> Result<()> {
    let mut version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version > SCHEMA_VERSION {
        bail!(
            "database schema version {version} is newer than this binary supports \
             ({SCHEMA_VERSION}); refusing to open it"
        );
    }
    if !table_exists(conn, "runs")? {
        let tx = conn.transaction()?;
        tx.execute_batch(CREATE_RUNS_V2)?;
        tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
        tx.commit()?;
        return Ok(());
    }
    if version < 1 {
        let tx = conn.transaction()?;
        for (col, ddl) in [
            (
                "rewrite_cp56_to_now",
                "ALTER TABLE runs ADD COLUMN rewrite_cp56_to_now INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "cp56_zone",
                "ALTER TABLE runs ADD COLUMN cp56_zone TEXT NOT NULL DEFAULT 'local'",
            ),
            (
                "proto_config",
                "ALTER TABLE runs ADD COLUMN proto_config TEXT",
            ),
            ("proto", "ALTER TABLE runs ADD COLUMN proto TEXT"),
        ] {
            if !column_exists(&tx, "runs", col)? {
                tx.execute(ddl, [])
                    .with_context(|| format!("migrate v1: {ddl}"))?;
            }
        }
        tx.execute_batch("PRAGMA user_version = 1")?;
        tx.commit()?;
        version = 1;
        info!("runs db migrated to schema v1");
    }
    if version < 2 {
        let tx = conn.transaction()?;
        tx.execute_batch("ALTER TABLE runs RENAME TO runs_v1")?;
        tx.execute_batch(CREATE_RUNS_V2)?;
        tx.execute_batch(
            "INSERT INTO runs (id, started_at, finished_at, status, pcap, target_ip,
                 target_mac, mode, role, target_port, speed, top_speed, realtime, planned,
                 sent, bytes, error, report_json, benchmark_json, per_source_json,
                 throughput_json, proto_config, rewrite_cp56_to_now, cp56_zone, proto)
             SELECT id, started_at, finished_at, status, pcap, target_ip,
                 target_mac, mode, role, target_port, speed, top_speed, realtime, planned,
                 sent, bytes, error, report_json, benchmark_json, per_source_json,
                 throughput_json, proto_config, rewrite_cp56_to_now, cp56_zone, proto
             FROM runs_v1;
             DROP TABLE runs_v1;",
        )
        .context("migrate v2: rebuild runs with AUTOINCREMENT")?;
        tx.execute_batch("PRAGMA user_version = 2")?;
        tx.commit()?;
        info!("runs db migrated to schema v2");
    }
    Ok(())
}

impl Db {
    /// Open (creating if needed) the run database at `path` and
    /// migrate it to the latest schema.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("create db dir {parent:?}"))?;
        }
        let mut conn =
            Connection::open(path).with_context(|| format!("open sqlite at {path:?}"))?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")
            .context("set pragmas")?;
        migrate(&mut conn).context("migrate runs schema")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path: Some(Arc::new(path.to_path_buf())),
        })
    }

    /// In-memory database for `--ephemeral` and tests.
    pub fn open_in_memory() -> Result<Self> {
        let mut conn = Connection::open_in_memory()?;
        migrate(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path: None,
        })
    }

    /// Filesystem path of the database, `None` when in memory.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref().map(|p| p.as_path())
    }

    /// Cheap writability probe for `/api/status`: rewrite the schema
    /// version (a header write) inside a transaction.
    pub fn check_writable(&self) -> Result<()> {
        let mut conn = self.conn.lock_safe();
        let tx = conn.transaction()?;
        tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
        tx.commit()?;
        Ok(())
    }

    /// Insert a row when a run starts. Plain INSERT: an id collision
    /// is an error, never an overwrite of an older run.
    pub fn insert_run_start(&self, run: &StoredRun) -> Result<()> {
        let conn = self.conn.lock_safe();
        conn.execute(
            "INSERT INTO runs
             (id, started_at, status, pcap, target_ip, target_mac, mode, role,
              target_port, speed, top_speed, realtime, planned, sent, bytes,
              proto_config, proto, started_by, pcap_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                     ?16, ?17, ?18, ?19)",
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
                run.proto,
                run.started_by,
                run.pcap_id,
            ],
        )?;
        Ok(())
    }

    /// Update a row when a run completes, fails or stops.
    pub fn update_finished(&self, run: &StoredRun) -> Result<()> {
        let conn = self.conn.lock_safe();
        let finished_at = run.finished_at.map(|v| v as i64).unwrap_or_else(now_secs);
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
                run.id as i64,
                run.status,
                finished_at,
                run.error,
                run.report_json,
                run.benchmark_json,
                run.per_source_json,
                run.throughput_json,
                run.planned as i64,
                run.sent as i64,
                run.bytes as i64,
            ],
        )?;
        Ok(())
    }

    /// Mark every row whose status is still "running" as failed —
    /// called once at server startup so a previous-process crash
    /// doesn't leave runs stuck in the running state forever.
    pub fn mark_orphans_failed(&self, message: &str) -> Result<usize> {
        let conn = self.conn.lock_safe();
        let n = conn.execute(
            "UPDATE runs SET status = 'failed', error = COALESCE(error, ?1),
                 finished_at = COALESCE(finished_at, ?2)
             WHERE status = 'running'",
            params![message, now_secs()],
        )?;
        Ok(n)
    }

    /// Load every persisted run. Rows that cannot be decoded are logged
    /// and skipped, so one bad row never hides the rest of the history.
    pub fn load_all(&self) -> Result<Vec<StoredRun>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare(
            "SELECT id, started_at, status, pcap, target_ip, target_mac, mode, role,
                    target_port, speed, top_speed, realtime, planned, sent, bytes,
                    error, report_json, benchmark_json, per_source_json, throughput_json,
                    proto_config, rewrite_cp56_to_now, cp56_zone, proto, finished_at,
                    started_by, pcap_id
             FROM runs
             ORDER BY id",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        let mut skipped = 0usize;
        while let Some(row) = rows.next()? {
            match decode_row(row) {
                Ok(r) => out.push(r),
                Err(e) => {
                    skipped += 1;
                    let id: Option<i64> = row.get(0).ok();
                    warn!(?id, error = %e, "skipping unreadable run row");
                }
            }
        }
        if skipped > 0 {
            warn!(skipped, "some run rows could not be read and were skipped");
        }
        Ok(out)
    }

    pub fn delete(&self, id: u64) -> Result<usize> {
        let conn = self.conn.lock_safe();
        Ok(conn.execute("DELETE FROM runs WHERE id = ?1", params![id as i64])?)
    }

    /// Highest run id ever handed out: the larger of the current
    /// maximum and the AUTOINCREMENT sequence, so a deleted newest run
    /// never has its id reused.
    pub fn max_id(&self) -> Result<u64> {
        let conn = self.conn.lock_safe();
        let max: i64 = conn.query_row("SELECT COALESCE(MAX(id), 0) FROM runs", [], |row| {
            row.get(0)
        })?;
        let seq: Option<i64> = if table_exists(&conn, "sqlite_sequence")? {
            conn.query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'runs'",
                [],
                |row| row.get(0),
            )
            .optional()?
        } else {
            None
        };
        Ok(max.max(seq.unwrap_or(0)).max(0) as u64)
    }
}

fn decode_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRun> {
    let proto_config_raw: Option<String> = row.get(20)?;
    let proto: Option<String> = row.get(23)?;
    let legacy_rewrite: Option<bool> = row.get::<_, Option<i64>>(21)?.map(|v| v != 0);
    let legacy_zone: Option<String> = row.get(22)?;
    // Migration: if proto_config is unset but the legacy CP56 columns
    // hold non-default values, synthesise a tiny IEC 104 proto_config
    // JSON so the analyser can still interpret CP56 drift correctly.
    let proto_config = proto_config_raw.or_else(|| {
        let rewrite = legacy_rewrite.unwrap_or(false);
        let zone = legacy_zone.clone().unwrap_or_else(|| "local".into());
        if rewrite || zone != "local" {
            Some(serde_json::json!({"cp56": {"rewrite_to_now": rewrite, "zone": zone}}).to_string())
        } else {
            None
        }
    });
    let target_port: i64 = row.get(8)?;
    Ok(StoredRun {
        id: row.get::<_, i64>(0)? as u64,
        started_at: row.get::<_, i64>(1)? as u64,
        status: row.get(2)?,
        pcap: row.get(3)?,
        target_ip: row.get(4)?,
        target_mac: row.get(5)?,
        mode: row.get(6)?,
        role: row.get(7)?,
        target_port: u16::try_from(target_port).unwrap_or(0),
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
        proto,
        finished_at: row.get::<_, Option<i64>>(24)?.map(|v| v as u64),
        started_by: row.get(25)?,
        pcap_id: row.get(26)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: u64) -> StoredRun {
        StoredRun {
            id,
            started_at: 100,
            status: "running".into(),
            pcap: "/lib/x.pcap".into(),
            target_ip: "10.0.0.1".into(),
            target_mac: String::new(),
            mode: "benchmark".into(),
            role: "master".into(),
            target_port: 2404,
            speed: 1.0,
            ..Default::default()
        }
    }

    #[test]
    fn insert_never_overwrites() {
        let db = Db::open_in_memory().unwrap();
        db.insert_run_start(&sample(1)).unwrap();
        assert!(db.insert_run_start(&sample(1)).is_err());
    }

    #[test]
    fn max_id_survives_deleting_newest() {
        let db = Db::open_in_memory().unwrap();
        db.insert_run_start(&sample(1)).unwrap();
        db.insert_run_start(&sample(2)).unwrap();
        db.delete(2).unwrap();
        assert_eq!(db.max_id().unwrap(), 2);
    }

    #[test]
    fn bad_row_is_skipped_not_fatal() {
        let db = Db::open_in_memory().unwrap();
        db.insert_run_start(&sample(1)).unwrap();
        db.insert_run_start(&sample(2)).unwrap();
        db.conn
            .lock_safe()
            .execute("UPDATE runs SET speed = 'fast' WHERE id = 1", [])
            .unwrap();
        let rows = db.load_all().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, 2);
        assert_eq!(db.max_id().unwrap(), 2);
    }

    #[test]
    fn orphans_get_finished_at() {
        let db = Db::open_in_memory().unwrap();
        db.insert_run_start(&sample(1)).unwrap();
        assert_eq!(db.mark_orphans_failed("restart").unwrap(), 1);
        let r = &db.load_all().unwrap()[0];
        assert_eq!(r.status, "failed");
        assert_eq!(r.error.as_deref(), Some("restart"));
        assert!(r.finished_at.is_some());
    }

    #[test]
    fn migrates_legacy_v0_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runs.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            // Schema as shipped before T04: no AUTOINCREMENT, no
            // proto column, user_version 0.
            conn.execute_batch(
                "CREATE TABLE runs (
                    id INTEGER PRIMARY KEY, started_at INTEGER NOT NULL,
                    finished_at INTEGER, status TEXT NOT NULL, pcap TEXT NOT NULL,
                    target_ip TEXT NOT NULL, target_mac TEXT NOT NULL, mode TEXT NOT NULL,
                    role TEXT NOT NULL, target_port INTEGER NOT NULL, speed REAL NOT NULL,
                    top_speed INTEGER NOT NULL, realtime INTEGER NOT NULL,
                    planned INTEGER NOT NULL DEFAULT 0, sent INTEGER NOT NULL DEFAULT 0,
                    bytes INTEGER NOT NULL DEFAULT 0, error TEXT, report_json TEXT,
                    benchmark_json TEXT, per_source_json TEXT, throughput_json TEXT,
                    proto_config TEXT);
                 INSERT INTO runs (id, started_at, status, pcap, target_ip, target_mac, mode,
                    role, target_port, speed, top_speed, realtime)
                 VALUES (7, 1, 'completed', '/p', '10.0.0.1', '', 'raw', '', 0, 1.0, 0, 0);",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let rows = db.load_all().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, 7);
        assert_eq!(rows[0].proto, None);
        db.delete(7).unwrap();
        assert_eq!(db.max_id().unwrap(), 7, "AUTOINCREMENT sequence kept");
        let v: i64 = db
            .conn
            .lock_safe()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        // Re-opening is a no-op.
        drop(db);
        Db::open(&path).unwrap();
    }

    #[test]
    fn refuses_newer_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runs.sqlite");
        Connection::open(&path)
            .unwrap()
            .execute_batch("PRAGMA user_version = 99")
            .unwrap();
        assert!(Db::open(&path).is_err());
    }
}
