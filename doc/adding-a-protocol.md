# Adding a new protocol replayer

outstation's protocol layer is a trait plus a registry, so a new TCP-based protocol can be added without changing the scheduler, the run pipeline, the capture or the analysis shell. A few places in the web UI and the library upload still assume IEC 104; they are listed [below](#what-is-still-iec-104-specific). **`crates/proto_iec104` is the worked example**: look there whenever this page is unclear.

## TL;DR

1. **New crate.** `cargo new --lib crates/proto_<name>` and add it to the workspace `members` in [`Cargo.toml`](../Cargo.toml), or fill in one of the four stub crates: `proto_modbus_tcp`, `proto_dnp3_tcp`, `proto_iec61850_mms`, `proto_iec60870_6_iccp`.
2. **Implement [`ProtoReplayer`](../crates/protoplay/src/lib.rs)** on your replayer. Four methods are required (`name`, `well_known_ports`, `readiness`, `run`); the others have defaults.
3. **Register** it with one line in `proto_registry::build()` in [`crates/proto_registry/src/lib.rs`](../crates/proto_registry/src/lib.rs).
4. *(Recommended)* **Add `static/<name>_ui.js`** to your crate with a per-endpoint renderer registered on `window.PROTOCOL_RENDERERS['<name>']`. [`crates/webui/build.rs`](../crates/webui/build.rs) splices it into the page.
5. *(Optional)* **Protocol-specific form fields**: mark them `data-proto="<name>"` in [`crates/webui/src/index.html`](../crates/webui/src/index.html) and serialise them in [`crates/webui/src/ui/30-configure.js`](../crates/webui/src/ui/30-configure.js).

After `cargo build` the protocol appears in `GET /api/protocols` and `outstation list-protocols`. The run form's protocol selector is built from `/api/protocols`: a `Ready` replayer can be selected, a `Stub` one is listed but disabled, and the server refuses benchmarks with a stub (400 `protocol_not_ready`). The analyzer reaches your `analyze_flow` through the registry, by the run's protocol name.

## Trait surface

The contract is `trait ProtoReplayer` in [`crates/protoplay/src/lib.rs`](../crates/protoplay/src/lib.rs).

| Method | Default | What it does |
|---|---|---|
| `name() -> &'static str` | required | Stable identifier: the `proto_name` of a run request, the `/api/protocols` name, the `PROTOCOL_RENDERERS` key and the `data-proto` value. Lowercase, no spaces: `"iec104"`, `"modbus_tcp"` |
| `well_known_ports() -> &'static [u16]` | required | The protocol's usual ports, shown by `/api/protocols` and `list-protocols` |
| `readiness() -> Readiness` | required | `Ready` when `run()` works; `Stub` while it does not |
| `run(cfg: ProtoRunCfg) -> ProtoReport` | required | Drives one live session: connection, handshake, flow control, teardown. `cfg` carries the bind and target addresses, the role, the pacing, per-frame timestamps, a shared `MessageProgress` (counters and the cancel and ready flags), the bind device and the run's `proto_config` string |
| `validate_config(proto_config: Option<&str>) -> anyhow::Result<()>` | accepts anything | Checks a benchmark request's `proto_config` before anything runs: `validate_settings` in [`crates/webui/src/runbuild.rs`](../crates/webui/src/runbuild.rs) calls it when a run is submitted, a profile is saved and the CLI starts a benchmark. An `Err` rejects the request with `invalid_proto_config` (400 over HTTP); the message is shown as is (prefixed with `proto_config: ` unless it already starts with `proto_config`). IEC 104's `proto_config (faults): …` style is mapped onto its editor fields by `35-iec104-config.js`; other protocols get no field mapping. `None` means no config (absent or blank). Not called for raw runs. IEC 104 delegates to `asdu::validate_proto_config` |
| `extract_message_times_ns(payload, offsets) -> Vec<u64>` | empty | One timestamp per protocol message of a reassembled flow, for original-timing pacing. An empty result makes the scheduler fall back to as-fast-as-possible |
| `quick_viability(view, file_size) -> ProtoViability` | counts flows on `well_known_ports()` | Session counts, memory estimate and a verdict for an uploaded pcap. Not called for your protocol yet; see below |
| `analyze_flow(…) -> ProtoSlaveAnalysis` | empty analysis | Per-endpoint post-run analysis: compare the captured flows with the source, return score, verdict, `outcome` (pass, fail, inconclusive), pacing samples and a `protocol_specific` JSON object for the UI. Without it, analysis reports nothing useful for your protocol |
| `aggregate_fleet_drift(per_slave, iters) -> Option<FleetDriftTimeline>` | `None` | Fold per-endpoint data into a fleet-wide drift timeline, if the protocol has a drift concept (IEC 104: CP56Time2a stamp vs wire time) |

### Minimal replayer

```rust
use protoplay::{ProtoReplayer, ProtoReport, ProtoRunCfg, Readiness, Role};

pub struct MyReplayer;

impl ProtoReplayer for MyReplayer {
    fn name(&self) -> &'static str { "my_proto" }
    fn well_known_ports(&self) -> &'static [u16] { &[1234] }
    fn readiness(&self) -> Readiness { Readiness::Ready }

    fn run(&self, cfg: ProtoRunCfg) -> ProtoReport {
        match cfg.role {
            Role::Master => my_session::run_master(cfg),
            Role::Slave => my_session::run_slave(cfg),
        }
    }
}
```

## Registering

One line in [`crates/proto_registry/src/lib.rs`](../crates/proto_registry/src/lib.rs):

```rust
pub fn build() -> Vec<Arc<dyn ProtoReplayer>> {
    vec![
        Arc::new(proto_iec104::Iec104Replayer::new()),
        Arc::new(proto_my_proto::MyReplayer),   // here
        // …
    ]
}
```

Add your crate to `proto_registry`'s `Cargo.toml`. The binary, `/api/protocols`, run validation, `outstation bench` and the analyzer all look protocols up in this registry. `webui` depends only on `protoplay` and `proto_registry`.

## Protocol-specific UI

### Per-endpoint renderer

Add `crates/proto_<name>/static/<name>_ui.js`. `build.rs` collects every `crates/proto_*/static/*.js` at compile time and splices it into the served page at the `<!-- @@PROTO_STATIC_JS@@ -->` placeholder in `index.html`, after the core modules in [`crates/webui/src/ui/`](../crates/webui/src/ui/). The files are classic scripts that share the page's global scope.

Register up to three functions:

```javascript
(function () {
  // HTML for one endpoint's drill-down. d.protocol_specific is what
  // your analyze_flow returned.
  function renderSlaveDetail(slaveIp, d) {
    const ps = d.protocol_specific || {};
    return `<p>${esc(ps.summary || '')}</p>`;
  }

  // Create charts for the placeholders the HTML above made. Register
  // every chart with trackAnalysisChart(c) so it is disposed on re-render.
  function initSlaveCharts(slug, d) { /* echarts.init(...); trackAnalysisChart(c); */ }

  // Optional extra HTML for the fleet section of the report.
  function renderFleetExtras(report) { return ''; }

  window.PROTOCOL_RENDERERS = window.PROTOCOL_RENDERERS || {};
  window.PROTOCOL_RENDERERS['my_proto'] = { renderSlaveDetail, initSlaveCharts, renderFleetExtras };
})();
```

Without a renderer the Analysis view shows a generic drill-down (TCP flow and notes). Helpers from the core: `el(id)`, `esc(str)`, `getCssVar(name)`, `slaveSlug(ip)`, `trackAnalysisChart(chart)`; `echarts` is in scope. Always pass untrusted strings through `esc()`.

### Run-form fields

Put controls that only apply to your protocol in a container with `data-proto="my_proto"` in `index.html`. `applyVisibility()` in `30-configure.js` shows it only when that protocol is selected.

To send those settings, extend `buildProtoConfig()` in `30-configure.js`. It currently returns `null` for every protocol except `iec104`, so today a run of another protocol gets no `proto_config` from the form. Your `validate_config()`, `run()` and `analyze_flow()` parse the JSON string themselves; parse it the same way in all three so a config that passes validation cannot fail later in the session; [`Iec104ProtoConfig::parse`](../crates/proto_iec104/src/asdu.rs) is the pattern (strict, typed, errors instead of silent defaults).

## What is still IEC-104-specific

- **Upload viability.** `compute_viability` in [`crates/webui/src/library.rs`](../crates/webui/src/library.rs) always calls the IEC 104 replayer's `quick_viability`, whatever the capture holds. Pick the replayer by port (or let the user choose) before relying on your own `quick_viability`.
- **Form serialisation.** `buildProtoConfig()` only builds `proto_config` for `iec104` (above), and the "IEC 104 options" card is IEC 104 only.
- **Raw runs** record `iec104` as their protocol name (`default_proto_name` in [`crates/webui/src/dto.rs`](../crates/webui/src/dto.rs)); raw replay is protocol-agnostic, so this only matters if you key anything on it.
- **`ProtoRunCfg` and reports** carry some IEC 104 vocabulary: `ProtocolStats` documents its fields in IEC 104 terms (S-frames, TESTFR, GI/CI), although the fields themselves are generic.

## Runtime checklist

- **Mid-flow captures.** Captures that do not start at the SYN begin with a partial message. Resynchronise to the first clean message boundary and restart framing at every capture gap; see [`proto_iec104::apci`](../crates/proto_iec104/src/apci.rs) (`frames`, `find_resync`).
- **Slave accept loop.** The scheduler sets `MessageProgress.ready` when the user arms a listener. Wait for it, and check `cancel`, before binding; see `run_slave_session` in [`crates/proto_iec104/src/session.rs`](../crates/proto_iec104/src/session.rs).
- **Keep serving while you wait.** Never `thread::sleep` through a pacing gap: the peer's keepalives and acknowledgements need answers in the meantime. IEC 104 waits in one place, [`Link::wait_until`](../crates/proto_iec104/src/link.rs), which services the receive side, the timers and cancellation every 50 ms.
- **Close properly.** Shut the socket down on every exit path so the peer sees FIN.
- **Rewrite hooks.** If users need to remap identifiers (addresses, object ids, tags), parse a map from `proto_config` and apply it per message inside `run()`, and apply the same map to the expected side in `analyze_flow`.

## What not to touch

- **`crates/sched`.** The scheduler is protocol-agnostic: it hands your replayer a `ProtoRunCfg` and reads its `MessageProgress`. Changes there apply to every protocol.
- **`crates/webui/src/analysis.rs`.** The analysis shell pairs endpoints, rolls up the fleet and persists results generically. Per-endpoint work belongs in your `analyze_flow`, fleet drift in `aggregate_fleet_drift`.
- **`crates/webui/Cargo.toml`.** No direct dependency on your crate; the registry is enough.

## Before shipping

- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` pass.
- [ ] `python3 -I scripts/check-spa-js.py` passes (syntax of the spliced SPA, including your `static/*.js`).
- [ ] `outstation list-protocols` and `GET /api/protocols` list the name, status and ports.
- [ ] The run form's selector offers the protocol (`Ready`) or shows it disabled (`Stub`).
- [ ] Live smoke test: upload a capture, run a benchmark, and check that the automatic analysis renders your drill-down.
- [ ] Fields marked `data-proto="<name>"` appear only for your protocol, and `buildProtoConfig()` sends them.

Open [`lib.rs`](../crates/proto_iec104/src/lib.rs), [`session.rs`](../crates/proto_iec104/src/session.rs), [`link.rs`](../crates/proto_iec104/src/link.rs), [`analysis.rs`](../crates/proto_iec104/src/analysis.rs) and [`static/iec104_ui.js`](../crates/proto_iec104/static/iec104_ui.js) side by side for a complete implementation of every point above.
