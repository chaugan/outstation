// 40-runs.js — the single runs poller (slim /api/runs, full
// /api/runs/:id only for expanded runs), the runs list with keyed
// updates, run cards that scale to 200 sessions (state summary,
// filter, sort, pages), slave controls, the detail panel and its
// charts (throughput sparkline, ack-latency and gap histograms), the
// auto-analysis state, re-run / load-into-Configure / compare actions,
// and the per-session command and fault-injection sections.
'use strict';

// ---------------------------------------------------------------------------
// Poller (F105, F118): one loop, survives outages with backoff, always
// reschedules, and reports its health to the status bar.

const poll = { timer: null, inflight: false, again: false, failures: 0 };

// Server-side pages of /api/runs (F054): the poll refreshes the newest
// page; older pages are fetched on demand and kept (finished runs do
// not change).
// `?runs_page=N` in the page URL overrides the page size (tests).
const RUNS_PAGE = (() => {
  const n = Number(new URLSearchParams(location.search).get('runs_page'));
  return Number.isInteger(n) && n > 0 && n <= 1000 ? n : 100;
})();
const olderRuns = { loaded: false, more: false, busy: false };

// The running run's sessions come from its live WebSocket frames
// (F103/F105) while that stream is fresh; the list then only needs
// slow polling for summaries.
function liveFrameFor(id) {
  const f = typeof diag !== 'undefined' ? diag.latest : null;
  if (!f || f.run_id !== id || !diag.ws || diag.ws.readyState !== 1) return null;
  return Date.now() - (diag.latestAt || 0) < 3000 ? f : null;
}

async function pollRuns() {
  if (poll.inflight) { poll.again = true; return; }
  poll.inflight = true;
  clearTimeout(poll.timer);
  let delay = 4000;
  try {
    const res = await api(`/api/runs?limit=${RUNS_PAGE}`, 'GET', null, { timeout: 10000 });
    if (res.ok && Array.isArray(res.data)) {
      const fresh = res.data;
      const minFresh = fresh.length ? fresh[fresh.length - 1].id : Infinity;
      const hasMore = !!(res.headers && res.headers.get('x-has-more') === 'true');
      // Runs that slid off the first page stay listed once older pages
      // were loaded; before that, "Load older runs" covers them.
      const kept = olderRuns.loaded ? S.runs.filter(r => r.id < minFresh) : [];
      if (!olderRuns.loaded) olderRuns.more = hasMore;
      S.runs = fresh.concat(kept);
      S.runsLoaded = true;
      poll.failures = 0;
      await refreshExpandedDetails();
      setPollHealth(true);
      emit('runs', S.runs);
      const running = S.runs.find(r => r.status === 'running');
      delay = document.hidden ? 10000 : (running ? (liveFrameFor(running.id) ? 4000 : 1000) : 4000);
    } else {
      poll.failures++;
      delay = Math.min(15000, 1000 * 2 ** Math.min(4, poll.failures - 1));
      setPollHealth(false, delay);
    }
  } catch (e) {
    // A rendering bug must not stop the loop; keep it visible though.
    console.error('runs poll', e);
    delay = 4000;
  } finally {
    poll.inflight = false;
    poll.timer = setTimeout(pollRuns, poll.again ? 50 : delay);
    poll.again = false;
  }
}

async function loadOlderRuns() {
  if (olderRuns.busy) return;
  olderRuns.busy = true;
  renderRuns();
  const before = S.runs.length ? Math.min(...S.runs.map(r => r.id)) : '';
  const res = await api(`/api/runs?limit=${RUNS_PAGE}&before=${before}`, 'GET', null, { timeout: 20000 });
  olderRuns.busy = false;
  if (!res.ok || !Array.isArray(res.data)) { notify(`Could not load older runs: ${res.error || 'bad reply'}`); renderRuns(); return; }
  const have = new Set(S.runs.map(r => r.id));
  S.runs = S.runs.concat(res.data.filter(r => !have.has(r.id)));
  olderRuns.loaded = true;
  olderRuns.more = !!(res.headers && res.headers.get('x-has-more') === 'true');
  announce(`${res.data.length} older runs loaded`);
  emit('runs', S.runs);
}

// A live frame of the running run: refresh its card at most once a
// second without waiting for the (thinned) list poll.
let _liveCardAt = 0;
function onLiveFrame(frame) {
  recordLiveFrame(frame);
  const r = S.runs.find(x => x.id === frame.run_id);
  if (!r || r.status !== 'running') return;
  r.sent = frame.sent;
  r.planned = frame.planned;
  if (frame.status && frame.status !== 'running') { pollRunsSoon(); return; }
  if (S.view !== 'runs' || Date.now() - _liveCardAt < 1000) return;
  _liveCardAt = Date.now();
  renderRuns();
}

function pollRunsSoon() {
  clearTimeout(poll.timer);
  poll.timer = setTimeout(pollRuns, 150);
}

document.addEventListener('visibilitychange', () => { if (!document.hidden) pollRunsSoon(); });

// ---------------------------------------------------------------------------
// Per-run UI state.

const runUi = {
  expanded: new Set(),
  msg: new Map(),     // id -> {cls, html}: result of the card's last action
  filter: '',
  status: '',
  page: 0,
  per: new Map(),     // id -> {sessions: bool|undefined, q, state, sort, page, benchPage, open:Set}
};
const RUNS_PER_PAGE = 20;
const ROWS_PER_PAGE = 25;

function ui(id) {
  if (!runUi.per.has(id)) runUi.per.set(id, { sessions: undefined, q: '', state: '', sort: 'state', page: 0, benchPage: 0, open: new Set() });
  return runUi.per.get(id);
}

async function refreshExpandedDetails() {
  if (S.view !== 'runs') return;
  // The running run's rows: from the live stream when it is fresh,
  // else from its detail (the list carries counts only).
  const want = new Set(runUi.expanded);
  for (const r of S.runs) if (r.status === 'running' && !liveFrameFor(r.id)) want.add(r.id);
  for (const id of want) {
    const r = S.runs.find(x => x.id === id);
    if (!r) { runUi.expanded.delete(id); continue; }
    const cached = S.runDetail.get(id);
    if (cached && cached.status === r.status && r.status !== 'running') continue;
    const res = await api(`/api/runs/${id}`, 'GET', null, { timeout: 15000 });
    if (res.ok && res.data) S.runDetail.set(id, res.data);
    else if (!cached) S.runDetail.set(id, { _error: res.error || 'could not load details' });
  }
}

// ---------------------------------------------------------------------------
// Session-state helpers.

const STATE_ORDER = ['failed', 'cancelled', 'active', 'connected', 'listening', 'pending', 'completed'];
function sessionState(p) {
  if (p.state === 'pending' && p.cancelled) return 'cancelled';
  return p.state || (p.planned && p.sent >= p.planned ? 'completed' : 'pending');
}
function stateCounts(rows) {
  const c = {};
  for (const p of rows) { const s = sessionState(p); c[s] = (c[s] || 0) + 1; }
  return c;
}
function sessionRowsFor(r) {
  if (r.status === 'running') {
    const f = liveFrameFor(r.id);
    if (f) return f.per_session || [];
  }
  if (r.per_source_progress && r.per_source_progress.length) return r.per_source_progress;
  const d = S.runDetail.get(r.id);
  return (d && d.per_source_progress) || [];
}

function stateBarHtml(r) {
  const rows = sessionRowsFor(r);
  const n = rows.length || r.sources || 0;
  if (!n) return '';
  const counts = r.source_states && Object.keys(r.source_states).length ? r.source_states : null;
  if (!rows.length && !counts) {
    const failed = r.sources_failed || 0;
    return `<p class="state-line"><b>${plural(n, 'session')}</b>${failed ? ` · <span class="s-failed-text">${failed} failed</span>` : ' · none failed'}</p>`;
  }
  const c = rows.length ? stateCounts(rows) : counts;
  const kinds = STATE_ORDER.filter(s => c[s]);
  if (r.status !== 'running' && kinds.length === 1) {
    return `<p class="state-line"><b>${plural(n, 'session')}</b> <span class="st-item"><span class="sw st-${kinds[0]}"></span>all ${kinds[0]}</span></p>`;
  }
  let bar = '<div class="state-bar" aria-hidden="true">';
  let legend = '';
  for (const s of STATE_ORDER) {
    if (!c[s]) continue;
    bar += `<span class="sb-seg st-${s}" style="flex:${c[s]}"></span>`;
    legend += `<span class="st-item"><span class="sw st-${s}"></span>${c[s]} ${s}</span>`;
  }
  bar += '</div>';
  return `<div class="state-summary">${bar}<p class="state-line"><b>${plural(n, 'session')}</b> ${legend}</p></div>`;
}

// ---------------------------------------------------------------------------
// Runs list.

// Title: run number and capture. Where the traffic goes is on the
// status line, in words that fit the run's state (a stopped slave run
// is not "listening").
function runTitle(r) {
  const name = libraryName(r.pcap_id, r.pcap);
  return `<span class="num">${runNum(r.id)}</span> <span class="name" title="library id ${esc(r.pcap_id || '—')}">${esc(name)}</span>`;
}

const STATUS_WORD = { running: 'Running', completed: 'Completed', partial: 'Partial', stopped: 'Stopped', failed: 'Failed' };

// One plain sentence: what the run does or did, to whom, and how long.
function runStatusLine(r) {
  const live = r.status === 'running';
  const n = r.sources || (r.benchmark && r.benchmark.sessions) || 0;
  let what;
  if (r.mode === 'benchmark') {
    const proto = esc(String(r.proto || 'iec104').toUpperCase().replace('IEC104', 'IEC 104'));
    if (r.role === 'slave') {
      const rtus = n ? plural(n, 'RTU') : 'RTUs';
      const port = r.target_port ? ` on port ${esc(r.target_port)}` : '';
      what = live ? `${proto} slave: ${rtus} listening${port} for the master` : `${proto} slave: simulated ${rtus}${port}`;
    } else {
      const ms = n ? plural(n, 'master session') : 'master sessions';
      what = `${proto} master: ${ms} ${live ? 'to' : 'against'} <code>${esc(r.target_ip)}${r.target_port ? ':' + esc(r.target_port) : ''}</code>`;
    }
  } else {
    what = `Raw L2 replay to <code>${esc(r.target_ip)}</code> at ${esc(r.speed)}×${r.top_speed ? ' (top speed)' : ''}${r.realtime ? ', SCHED_FIFO' : ''}`;
  }
  const when = live
    ? `started ${fmtClock(r.started_at)}${r.started_at ? ', running ' + fmtDuration(Date.now() - r.started_at * 1000) : ''}`
    : `started ${fmtClock(r.started_at)}${r.finished_at ? ', took ' + fmtDuration((r.finished_at - r.started_at) * 1000) : ''}`;
  const parts = [what, when];
  if (r.started_by) parts.push(`by ${esc(r.started_by)}`);
  if (r.rerun_of != null) parts.push(`re-run of <a href="#/runs/${esc(r.rerun_of)}">${runNum(r.rerun_of)}</a>`);
  const v = r.benchmark && r.benchmark.protocol_violations;
  if (v) parts.push(`<span class="bad">${plural(v, 'protocol violation')}</span>`);
  return parts.join(' · ');
}

function filteredRuns() {
  const q = runUi.filter.toLowerCase();
  return S.runs.filter(r => {
    if (isPendingDelete('run-' + r.id)) return false;
    if (runUi.status && r.status !== runUi.status) return false;
    if (!q) return true;
    const hay = `${r.id} ${runNum(r.id)} ${libraryName(r.pcap_id, r.pcap)} ${r.target_ip} ${r.status} ${r.role} ${r.proto}`.toLowerCase();
    return hay.includes(q);
  });
}

function renderRuns() {
  if (S.view !== 'runs') return;
  const all = S.runs.filter(r => !isPendingDelete('run-' + r.id));
  const running = all.filter(r => r.status === 'running').length;
  setText(el('runs-meta'), all.length ? `${all.length} total · ${running} running` : '—');
  const empty = el('runs-empty');
  empty.hidden = !S.runsLoaded || all.length > 0;
  if (!empty.hidden) {
    const have = S.library.length > 0;
    setHTML(empty, emptyStateHtml({
      step: have ? 2 : 1,
      title: 'No runs yet',
      body: have
        ? 'Pick a scenario in Configure: simulate RTUs to test a SCADA master, or act as the master to test an RTU. Runs show up here while they play, with a live diagram.'
        : 'Upload a capture in the Library first; then configure and start a run.',
      action: have ? '<a class="btn btn-primary" href="#/configure">Configure a run</a>' : '<a class="btn btn-primary" href="#/library">Upload a capture</a>',
    }));
  }
  el('runs-toolbar').hidden = all.length < 2;
  renderLiveStrip();
  const list = filteredRuns();
  const pages = Math.max(1, Math.ceil(list.length / RUNS_PER_PAGE));
  runUi.page = Math.min(runUi.page, pages - 1);
  const shown = list.slice(runUi.page * RUNS_PER_PAGE, (runUi.page + 1) * RUNS_PER_PAGE);
  reconcile(el('runs-list'), shown, r => r.id, renderRunCard, { tag: 'li', className: 'run' });
  let pager = pagerHtml('runs-page', runUi.page, pages, list.length, 'runs');
  if (all.length && !list.length) pager = '<p class="empty">No run matches the filter.</p>';
  if (olderRuns.more && runUi.page >= pages - 1) {
    pager += `<p class="older-runs"><button type="button" class="btn btn-secondary" data-act="runs-older" data-fk="runs-older"${olderRuns.busy ? ' disabled' : ''}>${olderRuns.busy ? 'Loading older runs…' : 'Load older runs'}</button></p>`;
  }
  setHTML(el('runs-pager'), pager);
}

function pagerHtml(act, page, pages, total, what, extra = '') {
  if (pages <= 1) return '';
  return `<nav class="pager-nav" aria-label="${esc(what)} pages">` +
    `<button type="button" class="btn btn-secondary" data-act="${act}" data-page="${page - 1}" ${extra}${page <= 0 ? ' disabled' : ''} data-fk="${act}-prev${extra ? '-' + extra.replace(/\D/g, '') : ''}">Previous</button>` +
    `<span>Page ${page + 1} of ${pages} · ${total.toLocaleString()} ${esc(what)}</span>` +
    `<button type="button" class="btn btn-secondary" data-act="${act}" data-page="${page + 1}" ${extra}${page >= pages - 1 ? ' disabled' : ''} data-fk="${act}-next${extra ? '-' + extra.replace(/\D/g, '') : ''}">Next</button></nav>`;
}

const RUN_PARTS = ['head', 'err', 'warn', 'progress', 'states', 'spark', 'analysis', 'actions', 'msg', 'sessions', 'detail'];
// Progress means something only with a plan: never "0% · 0 / 0".
function runProgress(r) {
  const total = r.planned || (r.report ? r.report.total_packets : 0) || (r.benchmark ? r.benchmark.total_messages_sent : 0);
  const cur = r.status === 'running' ? r.sent : (r.report ? r.report.total_packets : (r.benchmark ? r.benchmark.total_messages_sent : r.sent));
  return { total: total || 0, cur: cur || 0 };
}

// Latest stored analysis and the auto-analysis state of a run.
const AUTO_TEXT = { queued: 'Auto-analysis queued', running: 'Auto-analysis running…', done: 'Auto-analysis done', failed: 'Auto-analysis failed', skipped: 'Auto-analysis skipped' };
function analysisLink(runId, a) {
  const v = String(a.verdict || 'unknown');
  const score = a.score != null ? Number(a.score) : (a.score_pct != null ? Number(a.score_pct) : null);
  // Coloured by the verdict, never by the score (N14).
  return `<a class="an-link" href="#/analysis/${esc(runId)}/${esc(a.id)}">${verdictHtml(v)}` +
    `${score != null && isFinite(score) ? ` <b class="${verdictCls(v)}">${score.toFixed(1)}%</b>` : ''}` +
    ` <span class="an-link-id">analysis #${esc(a.id)}${a.source ? ', ' + esc(String(a.source).replace(/_/g, '-')) : ''}</span></a>`;
}
function analysisStateHtml(r) {
  if (r.mode !== 'benchmark') return '';
  const la = r.latest_analysis;
  const aa = r.auto_analysis;
  const bits = [];
  if (aa && aa.state && aa.state !== 'done') {
    const cls = aa.state === 'failed' ? 'bad' : (aa.state === 'skipped' ? 'muted' : 'busy');
    bits.push(`<span class="auto-st auto-${esc(aa.state)} ${cls}">${esc(AUTO_TEXT[aa.state] || aa.state)}${aa.error ? `: <span class="auto-err">${esc(aa.error)}</span>` : ''}</span>`);
  }
  if (la) bits.push(`<span class="an-latest">${aa && aa.state === 'done' && aa.analysis_id === la.id ? 'Auto-analysis' : 'Latest analysis'}: ${analysisLink(r.id, la)}</span>`);
  else if (!aa && r.status !== 'running') bits.push('<span class="muted">Not analysed yet</span>');
  return bits.length ? `<p class="an-state">${bits.join(' ')}</p>` : '';
}

function renderRunCard(li, r, isNew) {
  if (isNew) {
    li.innerHTML = RUN_PARTS.map(p => `<div class="run-${p}" data-part="${p}"${p === 'detail' ? ` id="run-detail-${r.id}"` : ''}></div>`).join('');
  }
  const part = p => li.querySelector(`[data-part="${p}"]`);
  li.className = `run run-st-${r.status}`;
  setHTML(part('head'),
    `<h3 class="run-title">${runTitle(r)}</h3><span class="status s-${esc(r.status)}">${esc(STATUS_WORD[r.status] || r.status)}</span>` +
    `<p class="submeta run-line">${runStatusLine(r)}</p>`);
  const expanded = runUi.expanded.has(r.id);
  const hint = r.error ? explainRunError(r.error) : '';
  setHTML(part('err'), r.error && !expanded
    ? `<p class="err-line"><span class="err-label">Error:</span> ${esc(r.error.length > 220 ? r.error.slice(0, 220) + '…' : r.error)}</p>` +
      (hint ? `<p class="hint-strong err-hint">${esc(hint)}</p>` : '') : '');

  // Run warnings (N15): capture failures, guard restore errors.
  const warns = ((r.benchmark && r.benchmark.warnings) || (r.report && r.report.warnings) || []);
  setHTML(part('warn'), warns.length
    ? `<div class="warn-box run-warnings"><b>${warns.length === 1 ? 'Warning' : `${warns.length} warnings`}:</b><ul>${warns.slice(0, 5).map(w => `<li>${esc(w)}</li>`).join('')}${warns.length > 5 ? `<li>… ${warns.length - 5} more in the details</li>` : ''}</ul></div>` : '');

  const { total, cur } = runProgress(r);
  const p = pct(cur, total);
  const unit = r.mode === 'benchmark' ? 'messages' : 'packets';
  setHTML(part('progress'), total > 0
    ? `<div class="pbar s-${esc(r.status)}"><span class="plabel" id="plabel-${r.id}">${r.status === 'running' ? 'Progress' : 'Sent'}</span>` +
      `<div class="ptrack" role="progressbar" aria-labelledby="plabel-${r.id}" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${p}"><div class="pfill" style="width:${p}%"></div></div>` +
      `<span class="pcount">${r.status !== 'running' && cur >= total ? `${fmtInt(cur)} ${unit}<span class="muted"> (plan ${fmtInt(total)})</span>` : `${p}% · ${fmtInt(cur)} / ${fmtInt(total)} ${unit}`}</span></div>`
    : (r.status === 'running' ? `<p class="hint pbar-wait">Waiting for the first ${r.mode === 'benchmark' && r.role === 'slave' ? 'master connection' : 'messages'}…</p>` : ''));

  setHTML(part('states'), stateBarHtml(r));

  const th = r.throughput_history || [];
  // While the live strip shows this run, its sparkline is not repeated.
  const strip = r.status === 'running' && liveFrameFor(r.id);
  setHTML(part('spark'), r.status === 'running' && th.length > 1 && !strip
    ? `<div class="sparkrow"><span class="lbl">Throughput</span>${sparklineSvg(th)}<span class="val">${fmtInt(th[th.length - 1])} pkt/s</span></div>` : finishedStatsHtml(r));
  setHTML(part('analysis'), analysisStateHtml(r));

  // One primary action, the details toggle, and everything else in a
  // menu. An open menu is not rebuilt under the user (it updates when
  // it closes).
  if (!menuIsOpenIn(part('actions'))) setHTML(part('actions'), runActionsHtml(r, expanded));
  const m = runUi.msg.get(r.id);
  setHTML(part('msg'), m ? `<p class="run-msg ${esc(m.cls)}" role="status">${m.html}</p>` : '');

  renderSessions(part('sessions'), r);
  renderDetail(part('detail'), r, expanded);
}

function runActionsHtml(r, expanded) {
  const acts = [];
  const live = r.status === 'running';
  const la = r.latest_analysis;
  if (live) {
    acts.push(`<button type="button" class="btn btn-danger" data-act="run-stop" data-id="${r.id}" data-fk="run-${r.id}-stop">Stop run</button>`);
    const rows = sessionRowsFor(r);
    const pending = rows.length
      ? rows.filter(x => x.state === 'pending' && !x.cancelled).length
      : ((r.source_states || {}).pending || 0);
    if (pending && (r.role === 'slave' || rows.some(x => x.listen_port > 0))) {
      acts.push(`<button type="button" class="btn btn-secondary" data-act="run-start-all" data-id="${r.id}" data-fk="run-${r.id}-startall">Start all pending (${pending})</button>`);
    }
  } else if (r.mode === 'benchmark' && la) {
    acts.push(`<a class="btn btn-primary" href="#/analysis/${r.id}/${esc(la.id)}" data-fk="run-${r.id}-primary">View analysis</a>`);
  } else if (r.mode === 'benchmark') {
    acts.push(`<a class="btn btn-primary" href="#/analysis/${r.id}" data-fk="run-${r.id}-primary">Analyze</a>`);
  }
  acts.push(`<button type="button" class="btn btn-secondary disclosure" data-act="run-toggle" data-id="${r.id}" data-fk="run-${r.id}-toggle" aria-expanded="${expanded}" aria-controls="run-detail-${r.id}">Details</button>`);
  const items = [];
  const mi = (act, label, extra = '') => `<button type="button" role="menuitem" tabindex="-1" class="menu-item" data-act="${act}" data-id="${r.id}" data-fk="run-${r.id}-card-${act.replace('run-', '')}"${extra}>${label}</button>`;
  if (!live) items.push(mi('run-rerun', 'Re-run…'));
  items.push(mi('run-load', 'Load into Configure'));
  if (r.mode === 'benchmark' && !live) items.push(mi('run-compare', 'Compare with…'));
  if (r.mode === 'benchmark' && !live && la) items.push(`<a role="menuitem" tabindex="-1" class="menu-item" href="#/analysis/${r.id}">New analysis…</a>`);
  if (r.has_capture) items.push(`<a role="menuitem" tabindex="-1" class="menu-item" href="/api/runs/${r.id}/download" download>Download capture</a>`);
  if (!live) items.push(`<button type="button" role="menuitem" tabindex="-1" class="menu-item danger" data-act="run-delete" data-id="${r.id}" data-fk="run-${r.id}-delete">Delete run</button>`);
  return `<div class="btn-row">${acts.join('')}${menuHtml(`run-menu-${r.id}`, `More actions for run ${r.id}`, items)}</div>`;
}

function setRunMsg(id, cls, html) {
  if (html) runUi.msg.set(id, { cls, html }); else runUi.msg.delete(id);
  renderRuns();
}

// Re-runs started here: their failure is reported on the original card.
const rerunWatch = new Map();   // new id -> original id

async function rerunRun(id) {
  setRunMsg(id, 'muted', 'Loading the run\'s settings…');
  const got = await fetchRunRequest(id);
  if (got.error) { setRunMsg(id, 'bad', `Cannot re-run: ${esc(got.error)}`); return; }
  const req = got.request;
  const what = [
    req.mode === 'raw' ? 'Raw L2 replay' : `Stateful ${req.proto_name || 'iec104'}, we act as ${req.role === 'slave' ? 'slaves' : 'master'}`,
    `Pcap: ${libraryName(req.pcap_id)}`,
    req.mode === 'benchmark' && req.role === 'slave' ? `Listening from port ${req.listen_port_base}` : `Target: ${req.target_ip}${req.mode === 'benchmark' ? ':' + req.target_port : ''}`,
  ];
  if (req.proto_config) what.push(`Protocol config: ${req.proto_config.length > 120 ? req.proto_config.slice(0, 120) + '…' : req.proto_config}`);
  let ok;
  if (req.force) {
    ok = await askDialog({
      title: `Re-run #${id} with protection overridden?`,
      body: [
        `Run #${id} overrode NIC and address protection. The override is never carried over, so confirm it again: the run may use the default-route NIC, the address this page is served on, bridge ports, and addresses held by other interfaces.`,
        'To re-run without the override, use “Load into Configure” instead.',
      ],
      list: what,
      confirm: 'Re-run with override',
      danger: true,
    });
  } else {
    ok = await askDialog({ title: `Re-run #${id}?`, body: 'Starts a new run with the same settings:', list: what, confirm: 'Start re-run' });
  }
  if (!ok) { setRunMsg(id, '', ''); return; }
  setRunMsg(id, 'muted', 'Starting the re-run…');
  const res = await api(`/api/runs/${id}/rerun${req.force ? '?force=true' : ''}`, 'POST', null, { timeout: 120000 });
  if (!res.ok) {
    let msg;
    if (res.code === 'run_active') {
      const d = res.data || {};
      msg = `Run #${esc(d.active_run_id)} is already active${d.client_ip ? ' (started by ' + esc(d.client_ip) + ')' : ''}. Only one run can be active at a time: <a href="#/runs/${esc(d.active_run_id)}">open it</a>, stop it or wait for it to finish.`;
    } else if (res.code === 'request_missing') {
      msg = `Run #${id} was recorded before run settings were stored, so it cannot be re-run.`;
    } else {
      const hint = explainRunError(res.error);
      msg = `The server refused the re-run: ${esc(res.error)}${hint ? ` <span class="hint-strong">${esc(hint)}</span>` : ''}`;
    }
    setRunMsg(id, 'bad', msg);
    notify(`Re-run of #${id} failed: ${res.error}`, 'error');
    return;
  }
  const nid = res.data.id;
  rerunWatch.set(nid, id);
  setRunMsg(id, 'ok', `Re-run started as <a href="#/runs/${esc(nid)}">${runNum(nid)}</a>.`);
  announce(`Re-run ${nid} of run ${id} started`);
  pollRunsSoon();
}

function updateRerunWatch() {
  for (const [nid, oid] of rerunWatch) {
    const r = S.runs.find(x => x.id === nid);
    if (!r || r.status === 'running') continue;
    rerunWatch.delete(nid);
    const link = `<a href="#/runs/${esc(nid)}">${runNum(nid)}</a>`;
    if (r.status === 'failed' || r.error) {
      const hint = explainRunError(r.error);
      runUi.msg.set(oid, { cls: 'bad', html: `Re-run ${link} ${esc(r.status)}: ${esc(r.error || 'no error text recorded')}${hint ? ` <span class="hint-strong">${esc(hint)}</span>` : ''}` });
      notify(`Re-run #${nid} ${r.status}: ${r.error || 'no error text'}${hint ? ' ' + hint : ''}`, 'error');
    } else {
      runUi.msg.set(oid, { cls: 'ok', html: `Re-run ${link} ${esc(r.status)}.` });
    }
    announce(`Re-run ${nid} ${r.status}`);
  }
}

// Baseline for "Compare with…": the run this one re-ran, else the newest
// earlier finished benchmark run of the same pcap and role, else any.
function suggestBaseline(id) {
  const r = S.runs.find(x => x.id === id);
  const ok = x => x && x.id !== id && x.mode === 'benchmark' && x.status !== 'running';
  if (r && r.rerun_of != null && ok(S.runs.find(x => x.id === r.rerun_of))) return r.rerun_of;
  const older = S.runs.filter(x => ok(x) && x.id < id);
  const same = older.find(x => r && x.pcap_id === r.pcap_id && x.role === r.role);
  const pick = same || older[0] || S.runs.find(ok);
  return pick ? pick.id : null;
}

// Refetch one run after an analysis event: its detail and its
// latest_analysis / auto_analysis in the list.
async function refetchRun(id) {
  const res = await api(`/api/runs/${id}`, 'GET', null, { timeout: 15000 });
  if (res.ok && res.data && typeof res.data === 'object') {
    if (runUi.expanded.has(id) || S.runDetail.has(id)) S.runDetail.set(id, res.data);
    const row = S.runs.find(x => x.id === id);
    if (row) {
      row.latest_analysis = res.data.latest_analysis ?? row.latest_analysis;
      row.auto_analysis = res.data.auto_analysis ?? row.auto_analysis;
    }
    emit('runs', S.runs);
  }
  pollRunsSoon();
}

// ---------------------------------------------------------------------------
// Per-session rows (F103, F119): collapsed behind a toggle (open by
// default while running), filter by text and state, sort, pages.

const slaveVerify = new Map();   // "run/idx" -> {cls, text}

function renderSessions(box, r) {
  const rows = sessionRowsFor(r);
  const u = ui(r.id);
  const isRunning = r.status === 'running';
  if (!rows.length || (!isRunning && !runUi.expanded.has(r.id))) {
    if (box._built) { box.innerHTML = ''; box._built = false; }
    return;
  }
  const open = u.sessions === undefined ? isRunning : u.sessions;
  if (!box._built) {
    box.innerHTML =
      `<button type="button" class="btn btn-text disclosure" data-act="sess-toggle" data-id="${r.id}" data-fk="sess-${r.id}-toggle" aria-expanded="false" aria-controls="sess-${r.id}"></button>` +
      `<div class="sessions" id="sess-${r.id}">` +
        '<div class="sess-toolbar">' +
          `<div class="field"><label for="sess-q-${r.id}">Find</label><input id="sess-q-${r.id}" type="search" data-sess="q" data-id="${r.id}" placeholder="IP" spellcheck="false" autocomplete="off"></div>` +
          `<div class="field"><label for="sess-state-${r.id}">State</label><select id="sess-state-${r.id}" data-sess="state" data-id="${r.id}"></select></div>` +
          `<div class="field"><label for="sess-sort-${r.id}">Sort</label><select id="sess-sort-${r.id}" data-sess="sort" data-id="${r.id}">` +
            '<option value="state">Problems first</option><option value="ip">IP</option><option value="sent">Most sent</option></select></div>' +
        '</div>' +
        '<div class="table-scroll"><table class="t sess-table"><thead></thead><tbody></tbody></table></div>' +
        '<div class="sess-pager"></div>' +
      '</div>';
    box._built = true;
  }
  const btn = box.querySelector('.disclosure');
  btn.setAttribute('aria-expanded', String(open));
  setText(btn, `${open ? 'Hide' : 'Show'} ${plural(rows.length, 'session')}`);
  const panel = box.querySelector('.sessions');
  panel.hidden = !open;
  if (!open) return;

  const counts = stateCounts(rows);
  const stateSel = box.querySelector('[data-sess="state"]');
  const opts = '<option value="">All states</option>' + STATE_ORDER.filter(s => counts[s]).map(s => `<option value="${s}">${s} (${counts[s]})</option>`).join('');
  if (stateSel._html !== opts) {
    const cur = u.state;
    stateSel.innerHTML = opts;
    stateSel._html = opts;
    stateSel.value = counts[cur] ? cur : '';
  }
  box.querySelector('[data-sess="sort"]').value = u.sort;

  const slaveMode = rows.some(x => x.listen_port > 0);
  const table = box.querySelector('table.sess-table');
  table.classList.toggle('slave-rows', slaveMode);
  table.classList.toggle('source-rows', !slaveMode);
  let list = rows.map((p, idx) => ({ p, idx, s: sessionState(p) }));
  if (u.state) list = list.filter(x => x.s === u.state);
  if (u.q) list = list.filter(x => `${x.p.src_ip || ''} ${x.p.src_mac || ''} ${x.p.listen_ip || ''}`.includes(u.q));
  const ipOf = x => ipToInt(x.p.src_ip || '0.0.0.0');
  if (u.sort === 'ip') list.sort((a, b) => ipOf(a) - ipOf(b));
  else if (u.sort === 'sent') list.sort((a, b) => (b.p.sent || 0) - (a.p.sent || 0));
  else list.sort((a, b) => (STATE_ORDER.indexOf(a.s) - STATE_ORDER.indexOf(b.s)) || (ipOf(a) - ipOf(b)));
  const pages = Math.max(1, Math.ceil(list.length / ROWS_PER_PAGE));
  u.page = Math.min(u.page, pages - 1);
  const pageRows = list.slice(u.page * ROWS_PER_PAGE, (u.page + 1) * ROWS_PER_PAGE);

  setHTML(box.querySelector('thead'), slaveMode
    ? '<tr><th scope="col">State</th><th scope="col">RTU</th><th scope="col">Listen address</th><th scope="col" class="num">Sent / planned</th><th scope="col">Actions</th></tr>'
    : '<tr><th scope="col">State</th><th scope="col">Source</th><th scope="col" class="num">Sent / planned</th><th scope="col" class="num">Received</th></tr>');
  let h = '';
  for (const { p, idx, s } of pageRows) h += slaveMode ? slaveRowHtml(r, p, idx, s) : sourceRowHtml(p, s);
  if (!pageRows.length) h = `<tr><td colspan="5" class="empty-cell">No session matches.</td></tr>`;
  setHTML(box.querySelector('tbody'), h);
  setHTML(box.querySelector('.sess-pager'), pagerHtml('sess-page', u.page, pages, list.length, 'sessions', `data-id="${r.id}"`));
}

function iterChip(p) {
  if (!(p.iter_current > 0 && (p.iter_total === 0 || p.iter_total > 1))) return '';
  return `<span class="iter">iteration ${p.iter_current}${p.iter_total ? ' of ' + p.iter_total : ' (until stopped)'}</span>`;
}

function progressCell(p, s) {
  const frac = p.planned ? Math.min(1, p.sent / p.planned) : 0;
  return `<span class="mini-track" aria-hidden="true"><span class="mini-fill st-${s}" style="width:${Math.round(frac * 100)}%"></span></span>` +
    `${fmtInt(p.sent || 0)} / ${fmtInt(p.planned || 0)} ${iterChip(p)}`;
}

// Per-session error (failed sessions), shown under the state.
const sessErr = p => (p.error ? `<span class="sess-err">${esc(p.error)}</span>` : '');

function sourceRowHtml(p, s) {
  return `<tr${p.error ? ' class="row-problem"' : ''}><td><span class="st st-${s}">${s}</span>${sessErr(p)}</td><td><code>${esc(p.src_ip || 'L2 ' + p.src_mac)}</code></td>` +
    `<td class="num">${progressCell(p, s)}</td><td class="num">${fmtInt(p.received || 0)}</td></tr>`;
}

function slaveRowHtml(r, p, idx, s) {
  const key = `${r.id}/${idx}`;
  const fk = `slave-${r.id}-${idx}`;
  const ip = p.listen_ip || '0.0.0.0';
  const live = r.status === 'running';
  let listen;
  if (live && p.state === 'pending' && !p.cancelled) {
    const v = slaveVerify.get(key);
    listen = `<span class="inline"><input class="slave-ip" type="text" value="${esc(ip)}" data-fk="${fk}-ip" data-run="${r.id}" data-idx="${idx}" aria-label="Listen IP for RTU ${esc(p.src_ip || idx)}" spellcheck="false" autocomplete="off">` +
      `<span class="port">:${esc(p.listen_port)}</span>` +
      `<button type="button" class="btn btn-text" data-act="slave-verify" data-run="${r.id}" data-idx="${idx}" data-fk="${fk}-verify">Verify</button></span>` +
      (v ? `<span class="verify ${v.cls}">${esc(v.text)}</span>` : '');
  } else {
    listen = `<code>${esc(ip)}:${esc(p.listen_port)}</code>`;
  }
  let act = '';
  if (live) {
    if (p.state === 'pending' && !p.cancelled) {
      act = `<button type="button" class="btn btn-secondary" data-act="slave-start" data-run="${r.id}" data-idx="${idx}" data-fk="${fk}-start">Start listening</button>` +
        `<button type="button" class="btn btn-text danger" data-act="slave-stop" data-run="${r.id}" data-idx="${idx}" data-fk="${fk}-abort">Abort</button>`;
    } else if (p.state === 'listening') {
      act = `<span class="hint">waiting for the master</span> <button type="button" class="btn btn-text danger" data-act="slave-stop" data-run="${r.id}" data-idx="${idx}" data-fk="${fk}-abort">Abort</button>`;
    } else if (p.state === 'connected' || p.state === 'active') {
      act = `<button type="button" class="btn btn-text danger" data-act="slave-stop" data-run="${r.id}" data-idx="${idx}" data-fk="${fk}-stop">Stop</button>`;
    }
  }
  return `<tr${p.error ? ' class="row-problem"' : ''}><td><span class="st st-${s}">${s}</span>${sessErr(p)}</td><td><code>${esc(p.src_ip || p.src_mac)}</code></td><td>${listen}</td>` +
    `<td class="num">${progressCell(p, s)}</td><td class="actions-cell">${act}</td></tr>`;
}

// Listen-IP edits are sent when the field loses focus or Enter is pressed.
document.addEventListener('change', async e => {
  const t = e.target;
  if (t.classList && t.classList.contains('slave-ip')) {
    const v = t.value.trim();
    if (!isIPv4(v)) { notify(`"${v}" is not an IPv4 address.`); return; }
    const res = await apiAction('Set listen IP', `/api/runs/${t.dataset.run}/slaves/${t.dataset.idx}`, 'PATCH', { listen_ip: v });
    if (res.ok) slaveVerify.delete(`${t.dataset.run}/${t.dataset.idx}`);
    pollRunsSoon();
  }
  if (t.dataset && t.dataset.sess) {
    const u = ui(Number(t.dataset.id));
    u[t.dataset.sess] = t.value;
    u.page = 0;
    renderRuns();
  }
});
document.addEventListener('input', e => {
  const t = e.target;
  if (t.dataset && t.dataset.sess === 'q') {
    const u = ui(Number(t.dataset.id));
    u.q = t.value.trim();
    u.page = 0;
    renderRuns();
  }
});
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.target.classList && e.target.classList.contains('slave-ip')) e.target.blur();
});

async function verifySlave(runId, idx) {
  const input = qs(`.slave-ip[data-run="${runId}"][data-idx="${idx}"]`);
  const ip = input ? input.value.trim() : '';
  const key = `${runId}/${idx}`;
  if (!isIPv4(ip)) { slaveVerify.set(key, { cls: 'bad', text: 'not an IPv4 address' }); renderRuns(); return; }
  await apiAction('Set listen IP', `/api/runs/${runId}/slaves/${idx}`, 'PATCH', { listen_ip: ip });
  slaveVerify.set(key, { cls: '', text: 'probing…' });
  renderRuns();
  const res = await api('/api/verify-ip', 'POST', { ip }, { timeout: 30000 });
  const d = res.data || {};
  let v;
  if (!res.ok || d.error) v = { cls: 'bad', text: res.error || d.error };
  else if (d.in_use) v = { cls: 'bad', text: `in use on ${d.iface}${d.mac ? ' (' + d.mac + ')' : ''}` };
  else if (ip === '0.0.0.0') v = { cls: 'ok', text: 'any interface' };
  else if (d.locally_assigned) v = { cls: 'ok', text: `already local on ${d.iface}` };
  else v = { cls: 'ok', text: `free on ${d.iface}; aliased when started` };
  slaveVerify.set(key, v);
  renderRuns();
}

// ---------------------------------------------------------------------------
// Detail panel (lazy: /api/runs/:id is fetched only while expanded).

function renderDetail(box, r, expanded) {
  box.hidden = !expanded;
  if (!expanded) { setHTML(box, ''); return; }
  const d = S.runDetail.get(r.id);
  if (!d) { setHTML(box, '<p class="hint">Loading details…</p>'); return; }
  if (d._error) { setHTML(box, `<div class="err-box">Could not load details: ${esc(d._error)}</div>`); return; }
  let h = '<div class="detail">';
  if (d.error) {
    const hint = explainRunError(d.error);
    h += `<div class="err-box"><p>${esc(d.error)}</p>${hint ? `<p class="hint-strong">${esc(hint)}</p>` : ''}</div>`;
  }
  h += '<dl class="kv">';
  h += `<dt>Pcap</dt><dd>${esc(libraryName(d.pcap_id, d.pcap))} <span class="hint">(${esc(d.pcap_id || basename(d.pcap))})</span></dd>`;
  h += `<dt>Target</dt><dd>${esc(d.target_ip)}${d.target_port ? ':' + esc(d.target_port) : ''}${d.target_mac ? ' · ' + esc(d.target_mac) : ''}</dd>`;
  h += `<dt>Mode</dt><dd>${d.mode === 'benchmark' ? `stateful ${esc(d.proto)}, ${esc(d.role)}` : 'raw L2'} · speed ${esc(d.speed)}×${d.top_speed ? ' (top)' : ''}${d.realtime ? ' · SCHED_FIFO' : ''}</dd>`;
  h += `<dt>Time</dt><dd>started ${fmtClock(d.started_at)}${d.finished_at ? ', finished ' + fmtClock(d.finished_at) : ''}${d.started_by ? ' · by ' + esc(d.started_by) : ''}</dd>`;
  if (d.rerun_of != null) h += `<dt>Re-run of</dt><dd><a href="#/runs/${esc(d.rerun_of)}">${runNum(d.rerun_of)}</a></dd>`;
  if (d.request && d.request.force) h += '<dt>Protection</dt><dd class="warn">overridden for this run (never carried over to a re-run)</dd>';
  if (d.proto_config) h += `<dt>Protocol config</dt><dd><code class="wrap">${esc(d.proto_config)}</code></dd>`;
  if (d.report) {
    h += `<dt>Sent</dt><dd>${fmtInt(d.report.total_packets)} packets · ${fmtBytes(d.report.total_bytes)}</dd>`;
    h += `<dt>Send errors</dt><dd>${fmtInt(d.report.total_errors)}</dd>`;
    if (d.report.capture_path) h += `<dt>Capture</dt><dd>${fmtInt(d.report.captured_packets)} frames · ${fmtBytes(d.report.captured_bytes)}</dd>`;
  }
  const b = d.benchmark;
  let violations = 0;
  if (b) {
    for (const s of b.per_session || []) violations += (s.protocol && s.protocol.protocol_violations) || 0;
    h += `<dt>Sessions</dt><dd>${fmtInt((b.per_session || []).length)}</dd>`;
    h += `<dt>Messages</dt><dd>${fmtInt(b.total_messages_sent)} sent · ${fmtInt(b.total_messages_received)} received</dd>`;
    h += `<dt>Throughput</dt><dd>${fmt(b.aggregate_throughput_msgs_per_sec)} msg/s</dd>`;
    h += `<dt>Ack latency</dt><dd>min ${fmtInt(b.aggregate_latency_min_us)} µs · p50 ${fmtInt(b.aggregate_latency_p50_us)} µs · p90 ${fmtInt(b.aggregate_latency_p90_us)} µs · p99 ${fmtInt(b.aggregate_latency_p99_us)} µs · max ${fmtInt(b.aggregate_latency_max_us)} µs</dd>`;
    h += `<dt>Protocol violations</dt><dd class="${violations ? 'bad' : 'ok'}">${fmtInt(violations)}</dd>`;
    h += commandFaultTotals(b.per_session || []);
    if (b.capture_path) h += `<dt>Capture</dt><dd>${fmtInt(b.captured_packets)} frames · ${fmtBytes(b.captured_bytes)}</dd>`;
  }
  h += '</dl>';

  if (d.report && d.report.per_source && d.report.per_source.length) {
    h += '<h4>Per-source timing</h4><div class="table-scroll"><table class="t"><thead><tr><th scope="col">Source IP</th><th scope="col">MAC</th><th scope="col">TAP</th><th scope="col">Kind</th>' +
      '<th scope="col" class="num">Sent</th><th scope="col" class="num">Bytes</th><th scope="col" class="num">Elapsed (ms)</th><th scope="col" class="num">Mean jitter (µs)</th><th scope="col" class="num">p99 jitter (µs)</th></tr></thead><tbody>';
    for (const s of d.report.per_source) {
      h += `<tr><td>${esc(s.src_ip || '—')}</td><td><code>${esc(s.src_mac)}</code></td><td><code>${esc(s.tap)}</code></td><td>${esc(s.kind)}</td>` +
        `<td class="num">${fmtInt(s.sent)}</td><td class="num">${fmtBytes(s.bytes)}</td><td class="num">${fmt(s.elapsed_ms)}</td><td class="num">${fmt(s.mean_jitter_us)}</td><td class="num">${fmt(s.p99_jitter_us)}</td></tr>`;
    }
    h += '</tbody></table></div>';
  }

  if (b && b.per_session && b.per_session.length) {
    h += benchSessionsHtml(r.id, b.per_session, d.proto);
    h += '<h4>Ack latency distribution</h4>';
    h += latencyChart(`lat-agg-${r.id}`, b.aggregate_latency_histogram, b.aggregate_latency_p50_us, b.aggregate_latency_p99_us);
  }

  if (d.has_capture) {
    h += '<h4>Inter-packet gap distribution</h4>';
    const g = gapCache.get(r.id);
    if (!g) { h += '<p class="hint">Loading…</p>'; fetchGapHistogram(r.id); }
    else if (g === 'loading') h += '<p class="hint">Loading…</p>';
    else if (g.error) h += `<div class="err-box">Gap histogram unavailable: ${esc(g.error)} <button type="button" class="btn btn-text" data-act="gap-retry" data-id="${r.id}" data-fk="gap-${r.id}-retry">Retry</button></div>`;
    else h += gapChart(`gap-${r.id}`, g);
  }
  h += '</div>';
  setHTML(box, h);
}

function benchSessionsHtml(runId, sessions, proto) {
  const u = ui(runId);
  const rows = sessions.map((s, i) => ({ s, i, v: (s.protocol && s.protocol.protocol_violations) || 0 }));
  rows.sort((a, b) => ((b.s.error ? 1 : 0) - (a.s.error ? 1 : 0)) || (b.v - a.v) || (ipToInt(a.s.src_ip) - ipToInt(b.s.src_ip)));
  const pages = Math.max(1, Math.ceil(rows.length / ROWS_PER_PAGE));
  u.benchPage = Math.min(u.benchPage, pages - 1);
  const page = rows.slice(u.benchPage * ROWS_PER_PAGE, (u.benchPage + 1) * ROWS_PER_PAGE);
  let h = '<h4>Per-session results</h4><p class="hint">Sessions with errors or protocol violations are listed first.</p>';
  h += '<div class="table-scroll"><table class="t"><thead><tr><th scope="col">Source IP</th><th scope="col" class="num">Sent</th><th scope="col" class="num">Received</th>' +
    '<th scope="col" class="num">Ack p50 (µs)</th><th scope="col" class="num">Ack p99 (µs)</th><th scope="col" class="num">Ack max (µs)</th><th scope="col" class="num">msg/s</th>' +
    '<th scope="col" class="num">Window stalls</th><th scope="col" class="num">Violations</th><th scope="col">Status</th><th scope="col"><span class="sr-only">More</span></th></tr></thead><tbody>';
  for (const { s, i, v } of page) {
    const pf = s.protocol || {};
    const flags = [];
    if ((pf.faults_injected || []).length) flags.push(`<span class="badge fault-badge" title="faults were injected on purpose">${plural(pf.faults_injected.length, 'fault')}</span>`);
    if ((pf.negative_confirmations || []).length) flags.push(`<span class="badge neg-badge">${fmtInt(pf.negative_confirmations.length)} negative</span>`);
    const status = (s.error ? '<span class="bad">error</span>' : (s.connected ? '<span class="ok">ok</span>' : 'not connected')) + (flags.length ? ' ' + flags.join(' ') : '');
    const open = u.open.has(i);
    h += `<tr${s.error || v ? ' class="row-problem"' : ''}><td><code>${esc(s.src_ip)}</code></td><td class="num">${fmtInt(s.messages_sent)}</td><td class="num">${fmtInt(s.messages_received)}</td>` +
      `<td class="num">${fmtInt(s.latency_p50_us)}</td><td class="num">${fmtInt(s.latency_p99_us)}</td><td class="num">${fmtInt(s.latency_max_us)}</td>` +
      `<td class="num">${fmt(s.throughput_msgs_per_sec)}</td><td class="num">${fmtInt(s.window_stalls)}</td>` +
      `<td class="num ${v ? 'bad' : ''}">${fmtInt(v)}</td><td>${status}</td>` +
      `<td><button type="button" class="btn btn-text" data-act="bench-row" data-id="${runId}" data-idx="${i}" data-fk="bench-${runId}-${i}" aria-expanded="${open}">${open ? 'Less' : 'More'}</button></td></tr>`;
    if (s.error) h += `<tr class="sub"><td colspan="11"><div class="err-box">${esc(s.error)}</div></td></tr>`;
    if (open) h += `<tr class="sub"><td colspan="11">${protoStatsHtml(s, proto)}</td></tr>`;
  }
  h += '</tbody></table></div>';
  h += pagerHtml('bench-page', u.benchPage, pages, rows.length, 'sessions', `data-id="${runId}"`);
  return h;
}

// Sum of the command and fault figures over every session, for the
// detail's key-value list.
function commandFaultTotals(sessions) {
  let cmds = 0, neg = 0, unans = 0, faults = 0, reacted = 0, withFaults = 0;
  for (const s of sessions) {
    const p = s.protocol || {};
    for (const c of p.commands || []) { cmds += c.commands || 0; neg += c.negative || 0; unans += c.unanswered || 0; }
    const f = (p.faults_injected || []).length;
    faults += f;
    if (f) withFaults++;
    const fr = p.fault_reaction;
    if (fr && (fr.peer_closed || fr.peer_reset || fr.peer_stopdt)) reacted++;
  }
  let h = '';
  if (cmds) h += `<dt>Commands</dt><dd>${fmtInt(cmds)} · ${neg ? `<span class="warn">${fmtInt(neg)} negative</span>` : '0 negative'}${unans ? ` · <span class="bad">${fmtInt(unans)} unanswered</span>` : ''}</dd>`;
  if (faults) h += `<dt>Injected faults</dt><dd class="warn">${fmtInt(faults)} on ${plural(withFaults, 'session')} · peer reacted (closed, reset or STOPDT) on ${fmtInt(reacted)}</dd>`;
  return h;
}

// Median and maximum of a sample array, the way the session reports
// them (upper median of the sorted samples).
function p50max(samples) {
  if (!samples || !samples.length) return null;
  const a = samples.slice().sort((x, y) => x - y);
  return { p50: a[Math.floor(a.length / 2)], max: a[a.length - 1], n: a.length };
}

const COT_TEXT = { 7: 'ActCon (negative)', 9: 'DeactCon (negative)', 44: 'unknown type', 45: 'unknown COT', 46: 'unknown common address', 47: 'unknown IOA' };

function typeName(proto, t) {
  const pr = (window.PROTOCOL_RENDERERS || {})[proto];
  return pr && typeof pr.tidName === 'function' ? `${pr.tidName(t)} [${t}]` : `type ${t}`;
}

function commandsHtml(p, proto) {
  const rows = p.commands || [];
  if (!rows.length) return '';
  const lat = x => (x ? `${usFmt(x.p50)} / ${usFmt(x.max)}` : '—');
  let h = '<h5>Commands</h5><div class="table-scroll"><table class="t cmd-table"><thead><tr><th scope="col">Type</th>' +
    '<th scope="col" class="num">Commands</th><th scope="col" class="num">ActCon</th><th scope="col" class="num">Negative</th>' +
    '<th scope="col" class="num">ActTerm</th><th scope="col" class="num">DeactCon</th><th scope="col" class="num">Unanswered</th>' +
    '<th scope="col" class="num">ActCon p50 / max</th><th scope="col" class="num">ActTerm p50 / max</th></tr></thead><tbody>';
  for (const c of rows) {
    const ac = p50max(c.actcon_us);
    const at = p50max(c.actterm_us);
    h += `<tr${c.negative || c.unanswered ? ' class="row-problem"' : ''}><td><code>${esc(typeName(proto, c.type_id))}</code></td>` +
      `<td class="num">${fmtInt(c.commands)}</td><td class="num">${fmtInt(c.act_con)}</td><td class="num${c.negative ? ' warn' : ''}">${fmtInt(c.negative)}</td>` +
      `<td class="num">${fmtInt(c.act_term)}</td><td class="num">${fmtInt(c.deact_con)}</td><td class="num${c.unanswered ? ' bad' : ''}">${fmtInt(c.unanswered)}</td>` +
      `<td class="num" title="${ac ? ac.n + ' samples' : ''}">${lat(ac)}</td><td class="num" title="${at ? at.n + ' samples' : ''}">${lat(at)}</td></tr>`;
  }
  h += '</tbody></table></div><p class="hint">Latencies run from the command to its first confirmation (ActCon, negative or DeactCon) and to its ActTerm, from the recorded samples.</p>';
  return h;
}

function negativesHtml(p, proto) {
  const n = p.negative_confirmations || [];
  if (!n.length) return '';
  const shown = n.slice(0, 50);
  let h = `<h5>Negative confirmations (${fmtInt(n.length)}${n.length > shown.length ? ', first ' + shown.length + ' listed' : ''})</h5>` +
    '<div class="table-scroll"><table class="t"><thead><tr><th scope="col" class="num">At (ms)</th><th scope="col">Type</th>' +
    '<th scope="col" class="num">CA</th><th scope="col" class="num">IOA</th><th scope="col">COT</th></tr></thead><tbody>';
  for (const x of shown) {
    h += `<tr><td class="num">+${fmtInt(x.at_ms)}</td><td><code>${esc(typeName(proto, x.type_id))}</code></td><td class="num">${fmtInt(x.ca)}</td>` +
      `<td class="num">${fmtInt(x.ioa)}</td><td>${esc(x.cot)}${COT_TEXT[x.cot] ? ' · ' + esc(COT_TEXT[x.cot]) : ''}</td></tr>`;
  }
  return h + '</tbody></table></div>';
}

function faultsInjectedHtml(p) {
  const f = p.faults_injected || [];
  const fr = p.fault_reaction;
  if (!f.length && !fr) return '';
  let h = `<h5>Injected faults (${fmtInt(f.length)})</h5>`;
  if (f.length) {
    h += '<div class="table-scroll"><table class="t"><thead><tr><th scope="col" class="num">At (ms)</th><th scope="col">Kind</th>' +
      '<th scope="col">What was done</th><th scope="col" class="num">Frames affected</th></tr></thead><tbody>';
    for (const x of f) {
      h += `<tr><td class="num">+${fmtInt(x.at_ms)}</td><td><code>${esc(x.kind)}</code></td><td>${esc(x.detail)}</td><td class="num">${fmtInt(x.frames_affected)}</td></tr>`;
    }
    h += '</tbody></table></div>';
  }
  if (fr) {
    const chips = [];
    if (fr.peer_closed) chips.push('closed the connection');
    if (fr.peer_reset) chips.push('reset the connection');
    if (fr.peer_stopdt) chips.push('sent STOPDT');
    h += '<div class="fault-reaction"><p><b>Peer reaction:</b> ' +
      (chips.length ? esc(chips.join(', ')) : 'no close, reset or STOPDT') +
      (fr.first_reaction_ms != null ? ` · first reaction ${fmtInt(fr.first_reaction_ms)} ms after the first fault` : '') + '</p>';
    if ((fr.protocol_errors || []).length) h += `<p>Protocol errors after the first fault: ${fr.protocol_errors.map(e => `<code>${esc(e)}</code>`).join(', ')}</p>`;
    if (fr.summary) h += `<p class="hint">${esc(fr.summary)}</p>`;
    h += '</div>';
  }
  return h;
}

function protoStatsHtml(s, proto) {
  const p = s.protocol;
  let h = '<dl class="kv compact">';
  h += `<dt>Bytes</dt><dd>${fmtBytes(s.bytes_written)} written · ${fmtBytes(s.bytes_read)} read</dd>`;
  h += `<dt>Elapsed</dt><dd>${fmtDuration(s.elapsed_ms)}</dd>`;
  h += `<dt>Unacked at end</dt><dd>${fmtInt(s.unacked_at_end)}</dd>`;
  if (p) {
    h += `<dt>Acks sent (S-frames)</dt><dd>${fmtInt(p.acks_sent)}</dd>`;
    h += `<dt>Keep-alives (TESTFR)</dt><dd>${fmtInt(p.keepalives_sent)}</dd>`;
    h += `<dt>Synthesized frames</dt><dd>${fmtInt(p.synthesized_frames)} (captured frames stripped: ${fmtInt(p.stripped_capture_frames)})</dd>`;
    if (p.command_response_count) {
      h += `<dt>Command response</dt><dd>${fmtInt(p.command_response_count)} commands · p50 ${fmtInt(p.command_response_p50_us)} µs · max ${fmtInt(p.command_response_max_us)} µs</dd>`;
    }
    h += `<dt>Idle serve</dt><dd>${fmtDuration(p.idle_serve_ms)}</dd>`;
    h += `<dt>Capture gaps</dt><dd>${fmtInt(p.capture_gaps)} · ${fmtInt(p.script_skipped_bytes)} bytes skipped · ${fmtInt(p.script_dropped_frames)} frames dropped</dd>`;
  }
  h += '</dl>';
  if (p && p.protocol_errors && p.protocol_errors.length) {
    h += `<p class="bad"><b>${fmtInt(p.protocol_violations)} protocol violation${p.protocol_violations === 1 ? '' : 's'}</b>${p.protocol_errors.length < p.protocol_violations ? ` (first ${p.protocol_errors.length} shown)` : ''}</p><ul class="violations">`;
    for (const e of p.protocol_errors) {
      h += `<li><span class="mono">+${fmtInt(e.at_ms)} ms</span> <code>${esc(e.kind)}</code>${e.fatal ? ' <span class="badge v-not_recommended">closed the link</span>' : ''} ${esc(e.detail)}</li>`;
    }
    h += '</ul>';
  } else if (!p) {
    h += '<p class="hint">No protocol counters were recorded for this session.</p>';
  }
  if (p) h += commandsHtml(p, proto) + negativesHtml(p, proto) + faultsInjectedHtml(p);
  return h;
}

// ---------------------------------------------------------------------------
// Actions.

actions({
  'run-toggle': b => {
    const id = Number(b.dataset.id);
    if (runUi.expanded.has(id)) runUi.expanded.delete(id);
    else runUi.expanded.add(id);
    renderRuns();
    pollRunsSoon();
  },
  'run-stop': async b => {
    b.disabled = true;
    const res = await apiAction(`Stop run #${b.dataset.id}`, `/api/runs/${b.dataset.id}/stop`, 'POST');
    if (res.ok) announce(`Stop requested for run ${b.dataset.id}`);
    pollRunsSoon();
  },
  'run-start-all': async b => {
    const res = await apiAction('Start all pending', `/api/runs/${b.dataset.id}/slaves/start_all`, 'POST');
    if (res.ok && res.data && typeof res.data.started === 'number') announce(`${res.data.started} sessions started`);
    pollRunsSoon();
  },
  // Finished runs are deleted with Undo instead of a confirmation: the
  // card disappears at once and the DELETE is sent when the toast ends.
  'run-delete': b => {
    const id = Number(b.dataset.id);
    const r = S.runs.find(x => x.id === id);
    if (!r || r.status === 'running') return;
    const card = qs(`#runs-list > li[data-key="${id}"]`);
    const next = card && (card.nextElementSibling || card.previousElementSibling);
    deferDelete({
      key: 'run-' + id,
      url: `/api/runs/${id}`,
      message: `Run #${id} deleted, with its capture.`,
      returnFocus: el('runs-filter'),
      hide: () => {
        renderRuns();
        const f = next && qs('[data-act="run-toggle"]', next);
        if (f) f.focus(); else el('h-runs').focus();
      },
      restore: () => { renderRuns(); },
      commit: async () => {
        const res = await apiAction(`Delete run #${id}`, `/api/runs/${id}`, 'DELETE');
        if (res.ok) {
          runUi.expanded.delete(id);
          S.runDetail.delete(id);
          S.runs = S.runs.filter(x => x.id !== id);
        }
        pollRunsSoon();
        renderRuns();
      },
    });
  },
  'slave-start': async b => {
    await apiAction('Start listening', `/api/runs/${b.dataset.run}/slaves/${b.dataset.idx}/start`, 'POST');
    pollRunsSoon();
  },
  'slave-stop': async b => {
    await apiAction('Stop session', `/api/runs/${b.dataset.run}/slaves/${b.dataset.idx}/stop`, 'POST');
    pollRunsSoon();
  },
  'slave-verify': b => verifySlave(b.dataset.run, b.dataset.idx),
  'sess-toggle': b => {
    const r = S.runs.find(x => x.id === Number(b.dataset.id));
    const u = ui(Number(b.dataset.id));
    const cur = u.sessions === undefined ? (r && r.status === 'running') : u.sessions;
    u.sessions = !cur;
    renderRuns();
  },
  'sess-page': b => { ui(Number(b.dataset.id)).page = Number(b.dataset.page); renderRuns(); },
  'bench-page': b => { ui(Number(b.dataset.id)).benchPage = Number(b.dataset.page); renderRuns(); },
  'bench-row': b => {
    const u = ui(Number(b.dataset.id));
    const i = Number(b.dataset.idx);
    if (u.open.has(i)) u.open.delete(i); else u.open.add(i);
    renderRuns();
  },
  'runs-page': b => { runUi.page = Number(b.dataset.page); renderRuns(); },
  'runs-older': () => loadOlderRuns(),
  'gap-retry': b => { gapCache.delete(Number(b.dataset.id)); renderRuns(); },
  'run-rerun': b => rerunRun(Number(b.dataset.id)),
  'run-load': b => loadRunIntoConfigure(Number(b.dataset.id)),
  'run-compare': b => {
    const id = Number(b.dataset.id);
    const a = suggestBaseline(id);
    location.hash = `#/compare/${a != null ? a : ''}/${id}`;
  },
});

// ---------------------------------------------------------------------------
// Gap histogram (F112): fetched once per run; a failure is cached and
// shown with a Retry button instead of being refetched every poll.

const gapCache = new Map();
async function fetchGapHistogram(id) {
  if (gapCache.has(id)) return;
  gapCache.set(id, 'loading');
  const res = await api(`/api/runs/${id}/gaps`, 'GET', null, { timeout: 60000 });
  gapCache.set(id, res.ok && res.data && Array.isArray(res.data.original) ? res.data : { error: res.error || 'bad reply' });
  renderRuns();
}

// ---------------------------------------------------------------------------
// Charts (SVG).

function sparklineSvg(samples) {
  const w = 600, h = 44, pad = 2;
  if (!samples || samples.length < 2) return '';
  const max = Math.max(1, ...samples);
  const step = (w - pad * 2) / (samples.length - 1);
  const pts = samples.map((v, i) => [pad + i * step, h - pad - (v / max) * (h - pad * 2)]);
  const path = pts.map((p, i) => (i === 0 ? 'M' : 'L') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
  const area = path + ` L ${w - pad} ${h - pad} L ${pad} ${h - pad} Z`;
  return `<svg class="chart-svg spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="Throughput over the last ${samples.length} seconds, peak ${max.toLocaleString()} packets per second">` +
    `<path d="${area}" fill="var(--accent-soft)"/><path d="${path}" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/></svg>`;
}

const chartData = new Map();   // uid -> tooltip data

function nsRange(lo, hi) {
  const f = ns => (ns < 1000 ? ns.toFixed(0) + ' ns' : ns < 1e6 ? (ns / 1000).toFixed(0) + ' µs' : ns < 1e9 ? (ns / 1e6).toFixed(0) + ' ms' : (ns / 1e9).toFixed(1) + ' s');
  return `${f(lo)} – ${f(hi)}`;
}
function usFmt(us) {
  if (us < 1000) return us.toFixed(0) + ' µs';
  if (us < 1e6) return (us / 1000).toFixed(1) + ' ms';
  return (us / 1e6).toFixed(2) + ' s';
}

function gapChart(uid, data) {
  const n = 20;
  const w = 680, h = 220, padL = 48, padR = 20, padT = 16, padB = 40;
  const iw = w - padL - padR, ih = h - padT - padB;
  const max = Math.max(1, ...data.original, ...data.captured);
  const bw = iw / n;
  let svg = `<svg class="chart-svg" viewBox="0 0 ${w} ${h}" role="img" aria-label="Inter-packet gap histogram, original pcap versus replayed capture">`;
  for (let g = 0; g <= 5; g++) {
    const y = padT + (g / 5) * ih;
    svg += `<line x1="${padL}" y1="${y}" x2="${w - padR}" y2="${y}" stroke="var(--rule-soft)"/>`;
    svg += `<text x="${padL - 6}" y="${y + 4}" font-size="11" text-anchor="end" fill="var(--dim)">${Math.round(max * (1 - g / 5))}</text>`;
  }
  for (let i = 0; i < n; i++) {
    const x = padL + i * bw;
    const oh = (data.original[i] / max) * ih;
    const ch = (data.captured[i] / max) * ih;
    svg += `<rect class="bucket-bg" x="${x}" y="${padT}" width="${bw}" height="${ih}" fill="transparent" data-idx="${i}" data-uid="${uid}"/>`;
    svg += `<rect x="${x + 2}" y="${padT + ih - oh}" width="${bw - 4}" height="${oh}" fill="var(--ink)" opacity="0.78"/>`;
    svg += `<rect x="${x + 5}" y="${padT + ih - ch}" width="${bw - 10}" height="${ch}" fill="var(--accent)" opacity="0.85"/>`;
  }
  svg += `<line x1="${padL}" y1="${padT + ih}" x2="${w - padR}" y2="${padT + ih}" stroke="var(--ink)"/>`;
  for (const t of [{ f: 0, l: '1 µs' }, { f: 3 / 7, l: '1 ms' }, { f: 4 / 7, l: '10 ms' }, { f: 6 / 7, l: '1 s' }, { f: 1, l: '10 s' }]) {
    const x = padL + t.f * iw;
    const anchor = t.f === 0 ? 'start' : (t.f === 1 ? 'end' : 'middle');
    svg += `<line x1="${x}" y1="${padT + ih}" x2="${x}" y2="${padT + ih + 4}" stroke="var(--dim)"/><text x="${x}" y="${padT + ih + 18}" font-size="11" fill="var(--dim)" text-anchor="${anchor}">${t.l}</text>`;
  }
  svg += '</svg>';
  chartData.set(uid, { kind: 'gap', data });
  return '<figure class="chart-wrap"><figcaption class="legend">' +
    '<span><span class="swatch sw-orig"></span>original pcap</span>' +
    '<span><span class="swatch sw-accent"></span>replayed capture</span></figcaption>' + svg + '</figure>';
}

function latencyChart(uid, hist, p50, p99) {
  if (!hist || !hist.total) return '<p class="hint">No ack-latency samples.</p>';
  const counts = hist.counts.slice();
  counts[0] += hist.underflow || 0;
  const binsMain = counts.length;
  if (hist.overflow) counts.push(hist.overflow);
  const n = counts.length;
  const w = 680, h = 200, padL = 48, padR = 20, padT = 18, padB = 36;
  const iw = w - padL - padR, ih = h - padT - padB;
  const logMin = hist.log10_min_us;
  const logMaxMain = hist.log10_max_us;
  const logMax = logMaxMain + (n - binsMain) * (logMaxMain - logMin) / binsMain;
  const max = Math.max(1, ...counts);
  const bw = iw / n;
  let svg = `<svg class="chart-svg" viewBox="0 0 ${w} ${h}" role="img" aria-label="Ack latency histogram: p50 ${p50} microseconds, p99 ${p99} microseconds">`;
  for (let g = 0; g <= 4; g++) {
    const y = padT + (g / 4) * ih;
    svg += `<line x1="${padL}" y1="${y}" x2="${w - padR}" y2="${y}" stroke="var(--rule-soft)"/><text x="${padL - 6}" y="${y + 4}" font-size="11" text-anchor="end" fill="var(--dim)">${Math.round(max * (1 - g / 4))}</text>`;
  }
  for (let i = 0; i < n; i++) {
    const x = padL + i * bw;
    const bh = (counts[i] / max) * ih;
    svg += `<rect class="bucket-bg" x="${x}" y="${padT}" width="${bw}" height="${ih}" fill="transparent" data-idx="${i}" data-uid="${uid}"/>`;
    svg += `<rect x="${x + 2}" y="${padT + ih - bh}" width="${bw - 4}" height="${bh}" fill="var(--blue)" opacity="0.85"/>`;
  }
  const marker = (v, color, label, row) => {
    if (!v) return '';
    const f = Math.max(0, Math.min(1, (Math.log10(Math.max(1, v)) - logMin) / (logMax - logMin)));
    const x = padL + f * iw;
    return `<line x1="${x}" y1="${padT}" x2="${x}" y2="${padT + ih}" stroke="${color}" stroke-width="1.5" stroke-dasharray="3,3"/><text x="${x + 4}" y="${padT + 12 + row * 14}" font-size="11" fill="${color}">${label} ${usFmt(v)}</text>`;
  };
  svg += marker(p50, 'var(--ok)', 'p50', 0) + marker(p99, 'var(--accent)', 'p99', 1);
  svg += `<line x1="${padL}" y1="${padT + ih}" x2="${w - padR}" y2="${padT + ih}" stroke="var(--ink)"/>`;
  const tick = l => (l < 3 ? `${Math.round(10 ** l)} µs` : l < 6 ? `${Math.round(10 ** (l - 3))} ms` : `${Math.round(10 ** (l - 6))} s`);
  const ticks = [];
  for (let l = Math.ceil(logMin); l <= logMaxMain; l++) ticks.push({ f: (l - logMin) / (logMax - logMin), l: tick(l) });
  if (n > binsMain) ticks.push({ f: 1, l: `>${tick(logMaxMain)}` });
  for (const t of ticks) {
    const x = padL + t.f * iw;
    const anchor = t.f === 0 ? 'start' : (t.f === 1 ? 'end' : 'middle');
    svg += `<line x1="${x}" y1="${padT + ih}" x2="${x}" y2="${padT + ih + 4}" stroke="var(--dim)"/><text x="${x}" y="${padT + ih + 18}" font-size="11" fill="var(--dim)" text-anchor="${anchor}">${t.l}</text>`;
  }
  svg += '</svg>';
  chartData.set(uid, { kind: 'lat', buckets: counts, logMin, logMax, overflowIdx: n > binsMain ? binsMain : -1 });
  return '<figure class="chart-wrap"><figcaption class="legend">' +
    '<span><span class="swatch sw-blue"></span>ack latency</span>' +
    '<span><span class="swatch sw-ok"></span>p50</span>' +
    '<span><span class="swatch sw-accent"></span>p99</span>' +
    `<span class="muted">${hist.total.toLocaleString()} messages (weighted)</span></figcaption>${svg}</figure>`;
}

document.addEventListener('mousemove', e => {
  const t = e.target;
  if (!t.classList || !t.classList.contains('bucket-bg')) return;
  const d = chartData.get(t.getAttribute('data-uid'));
  const i = parseInt(t.getAttribute('data-idx'), 10);
  if (!d) return;
  let html;
  if (d.kind === 'gap') {
    const lo = 10 ** (3 + (i / 20) * 7);
    const hi = 10 ** (3 + ((i + 1) / 20) * 7);
    html = `<b>${nsRange(lo, hi)}</b><br>original: ${d.data.original[i]}<br>replay: ${d.data.captured[i]}`;
  } else {
    const n = d.buckets.length;
    const lo = 10 ** (d.logMin + (i / n) * (d.logMax - d.logMin));
    const hi = 10 ** (d.logMin + ((i + 1) / n) * (d.logMax - d.logMin));
    html = i === d.overflowIdx ? `<b>≥ ${usFmt(lo)}</b><br>${d.buckets[i]} messages` : `<b>${usFmt(lo)} – ${usFmt(hi)}</b><br>${d.buckets[i]} messages`;
  }
  showTip(html, e.clientX + window.scrollX, e.clientY + window.scrollY);
});
document.addEventListener('mouseout', e => { if (e.target.classList && e.target.classList.contains('bucket-bg')) hideTip(); });

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Live dashboard strip: throughput sparkline (uplink and downlink),
// messages in flight, ack latency and the session-state bar, fed by
// the running run's WebSocket frames (see 50-diagram.js). The live ack
// latency comes from the sessions' log-scale histograms (four bins per
// decade), so it is an estimate; the finished run's card shows the
// exact percentiles.

const liveHist = { runId: null, up: [], down: [], lastAt: 0 };
const LIVE_HIST_N = 120;

function recordLiveFrame(frame) {
  if (liveHist.runId !== frame.run_id) { liveHist.runId = frame.run_id; liveHist.up = []; liveHist.down = []; liveHist.lastAt = 0; }
  const now = Date.now();
  if (now - liveHist.lastAt < 900) return;   // about one sample per second
  liveHist.lastAt = now;
  liveHist.up.push(frame.pps_sent || 0);
  liveHist.down.push(frame.pps_recv || 0);
  if (liveHist.up.length > LIVE_HIST_N) { liveHist.up.shift(); liveHist.down.shift(); }
}

function dualSparkSvg(up, down) {
  const w = 300, h = 44, pad = 2;
  const n = Math.max(up.length, 2);
  const max = Math.max(1, ...up, ...down);
  const pts = arr => arr.map((v, i) => `${(pad + (i / (n - 1)) * (w - 2 * pad)).toFixed(1)},${(h - pad - (v / max) * (h - 2 * pad)).toFixed(1)}`).join(' ');
  const last = up.length ? up[up.length - 1] : 0;
  return `<svg class="chart-svg ls-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="Throughput over the last ${up.length} seconds: now ${fmtInt(last)} messages per second sent, peak ${fmtInt(max)}">` +
    (up.length > 1 ? `<polyline points="${pts(down)}" fill="none" stroke="var(--blue)" stroke-width="1.5" vector-effect="non-scaling-stroke"/>` +
      `<polyline points="${pts(up)}" fill="none" stroke="var(--accent)" stroke-width="1.75" vector-effect="non-scaling-stroke"/>` : '') +
    '</svg>';
}

function stateBarFromRows(rows) {
  const c = stateCounts(rows);
  let bar = '<div class="state-bar" aria-hidden="true">';
  const words = [];
  for (const s of STATE_ORDER) {
    if (!c[s]) continue;
    bar += `<span class="sb-seg st-${s}" style="flex:${c[s]}"></span>`;
    words.push(`<span class="st-item"><span class="sw st-${s}"></span>${fmtInt(c[s])} ${s}</span>`);
  }
  return bar + `</div><p class="state-line">${words.join('')}</p>`;
}

// Live ack-latency tile: p50 / p99 over every acknowledgement so far.
function liveLatencyTile(running, f, tile) {
  const k = 'Ack latency p50 / p99';
  const lat = f && f.ack_latency;
  if (lat) {
    return tile(k, `<span class="ls-lat">${usFmt(lat.p50_us)} <span class="u">/</span> ${usFmt(lat.p99_us)}</span>`,
      `${fmtInt(lat.samples)} acks so far · estimate, ±1 bin`);
  }
  const mode = (f && f.mode) || running.mode;
  if (mode && mode !== 'benchmark') return tile(k, '—', 'raw replay has no acknowledgements', 'muted');
  return tile(k, '—', f ? 'waiting for the first acknowledgement' : 'connecting…', 'muted');
}

function renderLiveStrip() {
  const box = el('live-strip');
  const running = S.runs.find(r => r.status === 'running');
  const f = running ? liveFrameFor(running.id) : null;
  if (!running) { box.hidden = true; return; }
  box.hidden = false;
  const rows = f ? (f.per_session || []) : sessionRowsFor(running);
  const inflight = rows.reduce((a, p) => a + (p.unacked || 0), 0);
  const up = f ? (f.pps_sent || 0) : 0;
  const down = f ? (f.pps_recv || 0) : 0;
  const hist = liveHist.runId === running.id ? liveHist : { up: [], down: [] };
  const peak = hist.up.length ? Math.max(...hist.up) : 0;
  const tile = (k, v, sub, cls = '') => `<div class="ls-tile ${cls}"><span class="k">${k}</span><span class="v">${v}</span>${sub ? `<span class="sub">${sub}</span>` : ''}</div>`;
  let h = `<div class="ls-head"><span class="ls-live" aria-hidden="true"></span><b>${runNum(running.id)}</b> live · ${esc(libraryName(running.pcap_id, running.pcap))}` +
    `${f ? '' : ' <span class="hint">(connecting to the live stream…)</span>'}</div>`;
  h += '<div class="ls-tiles">';
  h += `<div class="ls-tile ls-tp"><span class="k">Throughput <span class="ls-key"><span class="lk-up"></span>sent <span class="lk-down"></span>received</span></span>` +
    `<span class="v">${fmtInt(up)} <span class="u">msg/s</span> <span class="ls-down">↓ ${fmtInt(down)}</span></span>${dualSparkSvg(hist.up, hist.down)}<span class="sub">peak ${fmtInt(peak)} msg/s, last ${hist.up.length} s</span></div>`;
  h += tile('In flight', fmtInt(inflight), 'sent, not yet acknowledged');
  h += liveLatencyTile(running, f, tile);
  h += `<div class="ls-tile ls-states"><span class="k">Sessions · ${fmtInt(rows.length || running.sources || 0)}</span>${rows.length ? stateBarFromRows(rows) : '<span class="sub">no session data yet</span>'}</div>`;
  h += '</div>';
  setHTML(el('ls-grid'), h);
}

// After the run: the final figures, including the ack-latency
// percentiles the sessions computed, on the run's card.
function finishedStatsHtml(r) {
  const b = r.benchmark;
  if (!b || r.status === 'running' || !b.total_messages_sent) return '';
  const lat = us => (us ? usFmt(us) : '—');
  return `<dl class="run-stats">` +
    `<div><dt>Throughput</dt><dd>${fmt(b.aggregate_throughput_msgs_per_sec)} msg/s</dd></div>` +
    `<div><dt>Ack p50</dt><dd>${lat(b.aggregate_latency_p50_us)}</dd></div>` +
    `<div><dt>Ack p99</dt><dd>${lat(b.aggregate_latency_p99_us)}</dd></div>` +
    (b.sessions_failed ? `<div><dt>Failed sessions</dt><dd class="bad">${fmtInt(b.sessions_failed)} of ${fmtInt(b.sessions)}</dd></div>` : '') +
    `<div><dt>Messages</dt><dd>${fmtInt(b.total_messages_sent)} sent · ${fmtInt(b.total_messages_received)} received</dd></div></dl>`;
}

function initRuns() {
  el('runs-filter').addEventListener('input', e => { runUi.filter = e.target.value.trim(); runUi.page = 0; renderRuns(); });
  el('runs-status').addEventListener('change', e => { runUi.status = e.target.value; runUi.page = 0; renderRuns(); });
  on('runs', updateRerunWatch);
  on('runs', renderRuns);
  // A card's actions skip updates while its menu is open; catch up.
  on('menu-closed', () => { if (S.view === 'runs') renderRuns(); });
  on('library', renderRuns);
  on('route', ({ view, arg }) => {
    if (view !== 'runs') return;
    if (arg && /^\d+$/.test(arg)) {
      const id = Number(arg);
      runUi.expanded.add(id);
      runUi.filter = '';
      runUi.status = '';
      el('runs-filter').value = '';
      el('runs-status').value = '';
      const idx = S.runs.findIndex(r => r.id === id);
      if (idx >= 0) runUi.page = Math.floor(idx / RUNS_PER_PAGE);
      _scrollTo = id;
    }
    renderRuns();
    pollRunsSoon();
  });
  on('runs', () => {
    if (_scrollTo == null) return;
    const n = qs(`#runs-list > li[data-key="${_scrollTo}"]`);
    if (n) { n.scrollIntoView({ block: 'start' }); _scrollTo = null; }
  });
}
let _scrollTo = null;
