//! N7: one process per state directory. A second `serve`, a `bench` and
//! a plain `cleanup` all refuse while a server holds the state
//! directory; `cleanup --force` still runs. Unprivileged: the server is
//! started without CAP_NET_ADMIN, so its startup cleanup cannot touch
//! the host.

use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

fn outstation(state: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_outstation"));
    c.env("OUTSTATION_LIBRARY_DIR", state.join("library"))
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null());
    c
}

fn serve(state: &Path) -> Child {
    outstation(state)
        .args(["serve", "--ephemeral", "--bind", "127.0.0.1:0"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve")
}

fn run(mut c: Command) -> Output {
    c.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        assert!(Instant::now() < deadline, "command did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn a_live_server_holds_its_state_directory() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    let mut first = serve(state);
    // Wait until the server holds the lock.
    let lock = state.join(webui::statelock::LOCK_FILE);
    let deadline = Instant::now() + Duration::from_secs(20);
    while webui::statelock::held_by(state).is_none() {
        assert!(
            first.try_wait().unwrap().is_none(),
            "first server exited early"
        );
        assert!(Instant::now() < deadline, "server never took {lock:?}");
        std::thread::sleep(Duration::from_millis(20));
    }

    // A second server on the same state directory refuses to start.
    let mut c = outstation(state);
    c.args(["serve", "--ephemeral", "--bind", "127.0.0.1:0"]);
    let o = run(c);
    assert!(!o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("in use"), "{}", text(&o));

    // cleanup refuses without --force ...
    let mut c = outstation(state);
    c.args(["cleanup", "--state-dir"]).arg(state);
    let o = run(c);
    assert!(!o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("--force"), "{}", text(&o));
    // ... and runs with it.
    let mut c = outstation(state);
    c.args(["cleanup", "--force", "--state-dir"]).arg(state);
    let o = run(c);
    assert!(o.status.success(), "{}", text(&o));

    // bench refuses with the run-error exit code.
    let profile = state.join("p.json");
    std::fs::write(
        &profile,
        r#"{"target_ip": "192.0.2.10", "mode": "benchmark", "role": "master"}"#,
    )
    .unwrap();
    let mut c = outstation(state);
    c.args(["bench", "--pcap", "/nonexistent.pcap", "--profile"])
        .arg(&profile)
        .arg("--state-dir")
        .arg(state);
    let o = run(c);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("in use"), "{}", text(&o));

    // The first server is still alive and unharmed.
    assert!(first.try_wait().unwrap().is_none());
    unsafe {
        libc::kill(first.id() as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while first.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "server did not stop");
        std::thread::sleep(Duration::from_millis(50));
    }
    // Once it is gone, cleanup runs without --force.
    let mut c = outstation(state);
    c.args(["cleanup", "--state-dir"]).arg(state);
    let o = run(c);
    assert!(o.status.success(), "{}", text(&o));
}
