# Adding a new protocol replayer

`pcapreplay`'s protocol layer is split into a small set of extension
points so a new TCP-based protocol can be wired in without touching the
scheduler, web UI, analysis shell, or capture loop. This doc walks
through the moving parts; **`crates/proto_iec104` is the canonical
worked example** — look there any time this recipe is ambiguous.

## TL;DR

1. **New crate.** `cargo new --lib crates/proto_<name>` (or reuse one of
   the existing stub crates under `crates/` — four are already shipped
   as placeholders: `proto_modbus_tcp`, `proto_dnp3_tcp`,
   `proto_iec61850_mms`, `proto_iec60870_6_iccp`).
2. **Implement [`ProtoReplayer`]** on your replayer struct. Four methods
   are required (`name`, `well_known_ports`, `readiness`, `run`); the
   rest have useful defaults.
3. **Register** by adding one line to `proto_registry::build()` in
   `crates/proto_registry/src/lib.rs`.
4. *(optional but recommended)* **Drop `static/<name>_ui.js`** in your
   crate with a per-slave renderer that registers on
   `window.PROTOCOL_RENDERERS[<name>]`. `crates/webui/build.rs` picks
   it up automatically.
5. *(optional)* **Tag protocol-specific form fields** in
   `crates/webui/src/index.html` with `<div data-proto="<name>">` so
   they only appear when the user picks your protocol in the run form.
6. `cargo build` — you're done. The new protocol shows up in `/api/protocols`,
   in the run form's protocol selector, and in the analyzer's per-slave
   dispatcher.

[`ProtoReplayer`]: ../crates/protoplay/src/lib.rs

## Trait surface

The full contract lives in `crates/protoplay/src/lib.rs` as
`trait ProtoReplayer`. What each method does and when to override:

| Method | Default? | What it does |
|---|---|---|
| `name() -> &'static str` | required | Stable identifier — matches `/api/protocols`, `run-proto` selector, DB column, UI `data-proto` attribute. Use lowercase, no spaces: `"iec104"`, `"modbus_tcp"`. |
| `well_known_ports() -> &'static [u16]` | required | Ports your protocol usually lives on. Drives the run form's default target port and the generic `quick_viability` fallback. |
| `readiness() -> Readiness` | required | `Ready` when `run()` is production-quality; `Stub` when compile-only. `Stub` replayers still appear in the selector (disabled). |
| `run(cfg: ProtoRunCfg) -> ProtoReport` | required | Drives one live session against the target. Must handle its own handshake, teardown, flow control, and write-sequence rewriting. `cfg` carries the bind/target IPs, role (master vs slave), pacing mode, per-frame timestamps, a shared `MessageProgress` sink, and the run's `proto_config` JSON. |
| `extract_message_times_ns(payload, offsets) -> Vec<u64>` | empty | One ns-relative timestamp per protocol message in a reassembled flow. Needed for `Pacing::OriginalTiming`. Implement if your framing is length-prefixed (most SCADA protocols). Default returns `vec![]`, which makes the scheduler fall back to as-fast-as-possible. |
| `quick_viability(view, file_size) -> ProtoViability` | generic | Walk an uploaded pcap and emit a session-count / memory / verdict summary for the UI's upload path. The default counts TCP flows on `well_known_ports()` — override for richer notes (mid-flow vs clean handshake, per-side byte totals, etc.). |
| `analyze_flow(orig_pb, cap_pb, orig_tg, cap_tg, ctx) -> ProtoSlaveAnalysis` | stub | Per-slave post-run analysis. Compare captured playback/target against the original pcap, produce a score + verdict + per-message pacing samples + a protocol-specific JSON blob for the UI. The default is a stub — override to populate the analyzer page. |
| `aggregate_fleet_drift(per_slave, iters) -> Option<FleetDriftTimeline>` | `None` | Fold per-slave `protocol_specific` blobs into a fleet-wide drift timeline. Only implement if your protocol has a meaningful drift concept (IEC 104: CP56Time2a stamp vs wire time). |

### Minimal replayer

```rust
use protoplay::{ProtoReplayer, ProtoRunCfg, ProtoReport, Readiness, Role};

pub struct MyReplayer;

impl ProtoReplayer for MyReplayer {
    fn name(&self) -> &'static str { "my_proto" }
    fn well_known_ports(&self) -> &'static [u16] { &[1234] }
    fn readiness(&self) -> Readiness { Readiness::Ready }

    fn run(&self, cfg: ProtoRunCfg) -> ProtoReport {
        match cfg.role {
            Role::Master => my_session::run_master(cfg),
            Role::Slave  => my_session::run_slave(cfg),
        }
    }
}
```

## Registering

One line in `crates/proto_registry/src/lib.rs`:

```rust
pub fn build() -> Vec<Arc<dyn ProtoReplayer>> {
    vec![
        Arc::new(proto_iec104::Iec104Replayer::new()),
        Arc::new(proto_my_proto::MyReplayer),   // ← here
        // …
    ]
}
```

The `outstation` binary, the `webui` crate's `/api/protocols` handler,
and the analyzer dispatcher all consult this one registry — no other
Rust files need to change.

## Protocol-specific UI (optional)

### Per-slave drill-down renderer

Drop `crates/proto_<name>/static/<name>_ui.js`. `crates/webui/build.rs`
globs every `proto_*/static/*.js` at compile time and concatenates
them into the served `index.html` through a
`<!-- @@PROTO_STATIC_JS@@ -->` placeholder. Rebuild webui and the new
file is picked up automatically.

Each UI file is expected to register two entry points on the global
`PROTOCOL_RENDERERS` dispatch table:

```javascript
(function () {
  // render_slave_detail(ip, detail) -> HTML string for the per-slave
  //   drill-down. `detail.protocol_specific` is the JSON blob your
  //   `analyze_flow` impl produced.
  function renderSlaveDetail(slaveIp, d) {
    const ps = d.protocol_specific || {};
    // …build HTML from ps.*…
    return html;
  }

  // init_slave_charts(slug, detail) -> wire up any ECharts instances
  //   the HTML above put placeholders for. Call trackAnalysisChart(c)
  //   so the core re-renders & resize handler disposes them cleanly.
  function initSlaveCharts(slug, d) {
    const ps = d.protocol_specific || {};
    // …echarts.init(...); trackAnalysisChart(chart); …
  }

  window.PROTOCOL_RENDERERS = window.PROTOCOL_RENDERERS || {};
  window.PROTOCOL_RENDERERS['my_proto'] = { renderSlaveDetail, initSlaveCharts };
})();
```

Helpers the core exposes: `el(id)`, `esc(str)`, `getCssVar(name)`,
`slaveSlug(ip)`, `trackAnalysisChart(chart)`. `echarts` is in scope.

### Run-form protocol-specific fields

Wrap any form control that only applies to your protocol in
`<div data-proto="my_proto">`. The core toggles visibility on the
`run-proto` select's `change` event — a block with `data-proto="iec104"`
is visible when IEC 104 is selected and hidden otherwise.

Submit path: if you need protocol-specific knobs serialized into the
run request, extend the `startRun()` handler in `index.html` to stuff
them into the `proto_config` JSON. Your `run()` and `analyze_flow()`
impls then parse their own sub-object out of that JSON (see
`proto_iec104::asdu::Iec104ProtoConfig::parse` for the pattern).

## Checklist — runtime wiring

* **Mid-flow pcap support.** If your protocol appears in capture pcaps
  that don't start at the SYN, `run()` should tolerate leading
  partial-frame bytes. See `proto_iec104::session::find_apci_resync`
  for a worked example of scanning for the first clean message boundary.
* **Slave-mode accept loop.** The scheduler drives
  `MessageProgress.ready` on the slave side; your `run_slave_session`
  must spin on it (and check `cancel`) before opening its
  `TcpListener`. Copy the pattern from `proto_iec104::session::run_slave_session`.
* **Test-frame responsiveness.** If your protocol has a keepalive ping
  (IEC 104 `TESTFR_act`), don't use `thread::sleep` while pacing —
  drain the RX channel with `recv_timeout` instead so keepalives can
  be answered mid-gap. This was the single biggest source of partial-
  replay bugs during the IEC 104 work.
* **Rewrite hooks.** If your protocol embeds stable identifiers the
  user may want to remap at replay time (addresses, object IDs,
  tag names), parse a rewrite map out of `proto_config` JSON and
  apply it per-message inside `run()`. Don't bake it into the
  trait — each protocol's knobs stay in its own JSON sub-object.

## What *not* to touch

* **`crates/sched`.** The scheduler is protocol-agnostic — it hands
  your replayer a `ProtoRunCfg` and observes its `MessageProgress`
  atomics. Changes there should be rare and they apply to every
  protocol.
* **`crates/webui/src/analysis.rs`.** The analyzer shell is generic.
  Per-slave protocol work belongs in your crate's `analyze_flow`;
  fleet aggregation belongs in `aggregate_fleet_drift`. The shell
  calls both through the trait.
* **Direct deps in `crates/webui/Cargo.toml`.** webui only depends on
  `protoplay` + `proto_registry`. Your crate is reached transitively
  through the registry — no webui Cargo edit needed.

## Checklist — before shipping

* [ ] `cargo build --release --workspace` clean.
* [ ] `cargo test --workspace --lib` green.
* [ ] Live smoke: upload a pcap in your protocol, start a run, capture
      the output, feed it back to `/api/analyze`, confirm the per-slave
      drill-down renders with your data.
* [ ] `/api/protocols` lists the new name + ports.
* [ ] The run form's `run-proto` selector shows your protocol as
      enabled (readiness = `Ready`) or disabled-stub (`Stub`).
* [ ] Fields tagged `data-proto="<name>"` appear only when your
      protocol is picked.

---

**Questions about a specific extension point?** Open
`crates/proto_iec104/src/lib.rs`, `crates/proto_iec104/src/session.rs`,
`crates/proto_iec104/src/analysis.rs`, and
`crates/proto_iec104/static/iec104_ui.js` side by side. Every method
above has a working, shipped implementation in those four files.
