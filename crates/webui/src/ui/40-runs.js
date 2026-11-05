// 40-runs.js — the single runs poller (slim /api/runs, full
// /api/runs/:id only for expanded runs), the runs list with keyed
// updates, run cards that scale to 200 sessions (state summary,
// filter, sort, pages), slave controls, the detail panel and its
// charts (throughput sparkline, ack-latency and gap histograms).
'use strict';

// ---------------------------------------------------------------------------
// Poller (F105, F118): one loop, survives outages with backoff, always
// reschedules, and reports its health to the status bar.

const poll = { timer: null, inflight: false, again: false, failures: 0 };

async function pollRuns() {
  if (poll.inflight) { poll.again = true; return; }
  poll.inflight = true;
  clearTimeout(poll.timer);
  let delay = 4000;
  try {
    const res = await api('/api/runs', 'GET', null, { timeout: 10000 });
    if (res.ok && Array.isArray(res.data)) {
      S.runs = res.data;
      S.runsLoaded = true;
      poll.failures = 0;
      await refreshExpandedDetails();
      setPollHealth(true);
      emit('runs', S.runs);
      const running = S.runs.some(r => r.status === 'running');
      delay = document.hidden ? 10000 : (running ? 1000 : 4000);
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

function pollRunsSoon() {
  clearTimeout(poll.timer);
  poll.timer = setTimeout(pollRuns, 150);
}

document.addEventListener('visibilitychange', () => { if (!document.hidden) pollRunsSoon(); });

// ---------------------------------------------------------------------------
// Per-run UI state.

const runUi = {
  expanded: new Set(),
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
  for (const id of runUi.expanded) {
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
  if (r.per_source_progress && r.per_source_progress.length) return r.per_source_progress;
  const d = S.runDetail.get(r.id);
  return (d && d.per_source_progress) || [];
}

function stateBarHtml(r) {
  const rows = sessionRowsFor(r);
  const n = rows.length || r.sources || 0;
  if (!n) return '';
  if (!rows.length) {
    const failed = r.sources_failed || 0;
    return `<p class="state-line"><b>${plural(n, 'session')}</b>${failed ? ` · <span class="s-failed-text">${failed} failed</span>` : ' · none failed'}</p>`;
  }
  const c = stateCounts(rows);
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

function runTitle(r) {
  const name = libraryName(r.pcap_id, r.pcap);
  const tgt = r.mode === 'benchmark' && r.role === 'slave' ? 'listening' : r.target_ip;
  return `<span class="num">${runNum(r.id)}</span> <span class="name" title="library id ${esc(r.pcap_id || '—')}">${esc(name)}</span> <span class="arrow" aria-hidden="true">→</span><span class="sr-only">to</span> ${esc(tgt)}`;
}

function runSubmeta(r) {
  const parts = [];
  if (r.mode === 'benchmark') {
    parts.push(`${esc(r.proto)} ${esc(r.role)}`);
    if (r.target_port) parts.push(r.role === 'slave' ? `listening on port ${r.target_port}` : `port ${r.target_port}`);
  } else {
    parts.push('raw L2');
    parts.push(`speed ${esc(r.speed)}×${r.top_speed ? ' (top)' : ''}`);
    if (r.realtime) parts.push('SCHED_FIFO');
  }
  parts.push(`started ${fmtClock(r.started_at)}${r.started_by ? ' by ' + esc(r.started_by) : ''}`);
  if (r.finished_at) parts.push(`took ${fmtDuration((r.finished_at - r.started_at) * 1000)}`);
  const v = r.benchmark && r.benchmark.protocol_violations;
  if (v) parts.push(`<span class="bad">${plural(v, 'protocol violation')}</span>`);
  return parts.join(' · ');
}

function filteredRuns() {
  const q = runUi.filter.toLowerCase();
  return S.runs.filter(r => {
    if (runUi.status && r.status !== runUi.status) return false;
    if (!q) return true;
    const hay = `${r.id} ${runNum(r.id)} ${libraryName(r.pcap_id, r.pcap)} ${r.target_ip} ${r.status} ${r.role} ${r.proto}`.toLowerCase();
    return hay.includes(q);
  });
}

function renderRuns() {
  if (S.view !== 'runs') return;
  const all = S.runs;
  const running = all.filter(r => r.status === 'running').length;
  setText(el('runs-meta'), all.length ? `${all.length} total · ${running} running` : '—');
  el('runs-empty').hidden = !S.runsLoaded || all.length > 0;
  el('runs-toolbar').hidden = all.length < 2;
  const list = filteredRuns();
  const pages = Math.max(1, Math.ceil(list.length / RUNS_PER_PAGE));
  runUi.page = Math.min(runUi.page, pages - 1);
  const shown = list.slice(runUi.page * RUNS_PER_PAGE, (runUi.page + 1) * RUNS_PER_PAGE);
  reconcile(el('runs-list'), shown, r => r.id, renderRunCard, { tag: 'li', className: 'run' });
  setHTML(el('runs-pager'), pagerHtml('runs-page', runUi.page, pages, list.length, 'runs'));
  if (all.length && !list.length) setHTML(el('runs-pager'), '<p class="empty">No run matches the filter.</p>');
}

function pagerHtml(act, page, pages, total, what, extra = '') {
  if (pages <= 1) return '';
  return `<nav class="pager-nav" aria-label="${esc(what)} pages">` +
    `<button type="button" class="btn btn-secondary" data-act="${act}" data-page="${page - 1}" ${extra}${page <= 0 ? ' disabled' : ''} data-fk="${act}-prev${extra ? '-' + extra.replace(/\D/g, '') : ''}">Previous</button>` +
    `<span>Page ${page + 1} of ${pages} · ${total.toLocaleString()} ${esc(what)}</span>` +
    `<button type="button" class="btn btn-secondary" data-act="${act}" data-page="${page + 1}" ${extra}${page >= pages - 1 ? ' disabled' : ''} data-fk="${act}-next${extra ? '-' + extra.replace(/\D/g, '') : ''}">Next</button></nav>`;
}

const RUN_PARTS = ['head', 'err', 'progress', 'states', 'spark', 'actions', 'sessions', 'detail'];

function renderRunCard(li, r, isNew) {
  if (isNew) {
    li.innerHTML = RUN_PARTS.map(p => `<div class="run-${p}" data-part="${p}"${p === 'detail' ? ` id="run-detail-${r.id}"` : ''}></div>`).join('');
  }
  const part = p => li.querySelector(`[data-part="${p}"]`);
  li.className = `run run-st-${r.status}`;
  setHTML(part('head'),
    `<h3 class="run-title">${runTitle(r)}</h3><span class="status s-${esc(r.status)}">${esc(r.status)}</span>` +
    `<p class="submeta">${runSubmeta(r)}</p>`);
  const expanded = runUi.expanded.has(r.id);
  setHTML(part('err'), r.error && !expanded
    ? `<p class="err-line"><span class="err-label">Error:</span> ${esc(r.error.length > 220 ? r.error.slice(0, 220) + '…' : r.error)}</p>` : '');

  const total = r.planned || (r.report ? r.report.total_packets : 0) || (r.benchmark ? r.benchmark.total_messages_sent : 0);
  const cur = r.status === 'running' ? r.sent : (r.report ? r.report.total_packets : (r.benchmark ? r.benchmark.total_messages_sent : r.sent));
  const p = total ? pct(cur, total) : (r.status === 'completed' ? 100 : 0);
  setHTML(part('progress'),
    `<div class="pbar s-${esc(r.status)}"><span class="plabel" id="plabel-${r.id}">Progress</span>` +
    `<div class="ptrack" role="progressbar" aria-labelledby="plabel-${r.id}" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${p}"><div class="pfill" style="width:${p}%"></div></div>` +
    `<span class="pcount">${p}% · ${fmtInt(cur || 0)} / ${fmtInt(total || 0)}${r.mode === 'benchmark' ? ' messages' : ' packets'}</span></div>`);

  setHTML(part('states'), stateBarHtml(r));

  const th = r.throughput_history || [];
  setHTML(part('spark'), r.status === 'running' && th.length > 1
    ? `<div class="sparkrow"><span class="lbl">Throughput</span>${sparklineSvg(th)}<span class="val">${fmtInt(th[th.length - 1])} pkt/s</span></div>` : '');

  const acts = [];
  if (r.status === 'running') {
    acts.push(`<button type="button" class="btn btn-danger" data-act="run-stop" data-id="${r.id}" data-fk="run-${r.id}-stop">Stop</button>`);
    const rows = r.per_source_progress || [];
    const pending = rows.filter(x => x.state === 'pending' && !x.cancelled).length;
    if (pending && rows.some(x => x.listen_port > 0)) {
      acts.push(`<button type="button" class="btn btn-secondary" data-act="run-start-all" data-id="${r.id}" data-fk="run-${r.id}-startall">Start all pending (${pending})</button>`);
    }
  }
  acts.push(`<button type="button" class="btn btn-secondary" data-act="run-toggle" data-id="${r.id}" data-fk="run-${r.id}-toggle" aria-expanded="${expanded}" aria-controls="run-detail-${r.id}">${expanded ? 'Hide details' : 'Details'}</button>`);
  if (r.has_capture) acts.push(`<a class="btn btn-secondary" href="/api/runs/${r.id}/download" download>Download capture</a>`);
  if (r.mode === 'benchmark' && r.status !== 'running') acts.push(`<a class="btn btn-secondary" href="#/analysis/${r.id}">Analyze</a>`);
  if (r.status !== 'running') acts.push(`<button type="button" class="btn btn-text danger" data-act="run-delete" data-id="${r.id}" data-fk="run-${r.id}-delete" aria-label="Delete run ${r.id}">Delete</button>`);
  setHTML(part('actions'), `<div class="btn-row">${acts.join('')}</div>`);

  renderSessions(part('sessions'), r);
  renderDetail(part('detail'), r, expanded);
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

function sourceRowHtml(p, s) {
  return `<tr><td><span class="st st-${s}">${s}</span></td><td><code>${esc(p.src_ip || 'L2 ' + p.src_mac)}</code></td>` +
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
  return `<tr><td><span class="st st-${s}">${s}</span></td><td><code>${esc(p.src_ip || p.src_mac)}</code></td><td>${listen}</td>` +
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
    h += benchSessionsHtml(r.id, b.per_session);
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

function benchSessionsHtml(runId, sessions) {
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
    const status = s.error ? '<span class="bad">error</span>' : (s.connected ? '<span class="ok">ok</span>' : 'not connected');
    const open = u.open.has(i);
    h += `<tr${s.error || v ? ' class="row-problem"' : ''}><td><code>${esc(s.src_ip)}</code></td><td class="num">${fmtInt(s.messages_sent)}</td><td class="num">${fmtInt(s.messages_received)}</td>` +
      `<td class="num">${fmtInt(s.latency_p50_us)}</td><td class="num">${fmtInt(s.latency_p99_us)}</td><td class="num">${fmtInt(s.latency_max_us)}</td>` +
      `<td class="num">${fmt(s.throughput_msgs_per_sec)}</td><td class="num">${fmtInt(s.window_stalls)}</td>` +
      `<td class="num ${v ? 'bad' : ''}">${fmtInt(v)}</td><td>${status}</td>` +
      `<td><button type="button" class="btn btn-text" data-act="bench-row" data-id="${runId}" data-idx="${i}" data-fk="bench-${runId}-${i}" aria-expanded="${open}">${open ? 'Less' : 'More'}</button></td></tr>`;
    if (s.error) h += `<tr class="sub"><td colspan="11"><div class="err-box">${esc(s.error)}</div></td></tr>`;
    if (open) h += `<tr class="sub"><td colspan="11">${protoStatsHtml(s)}</td></tr>`;
  }
  h += '</tbody></table></div>';
  h += pagerHtml('bench-page', u.benchPage, pages, rows.length, 'sessions', `data-id="${runId}"`);
  return h;
}

function protoStatsHtml(s) {
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
  'run-delete': async b => {
    const id = Number(b.dataset.id);
    const ok = await askDialog({
      title: `Delete run #${id}?`,
      body: 'This removes it from the history and deletes its captured pcap.',
      confirm: 'Delete run',
      danger: true,
    });
    if (!ok) return;
    const res = await apiAction(`Delete run #${id}`, `/api/runs/${id}`, 'DELETE');
    if (res.ok) {
      runUi.expanded.delete(id);
      S.runDetail.delete(id);
      announce(`Run ${id} deleted`);
    }
    pollRunsSoon();
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
  'gap-retry': b => { gapCache.delete(Number(b.dataset.id)); renderRuns(); },
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
    '<span><span class="swatch" style="background:var(--ink);opacity:0.78"></span>original pcap</span>' +
    '<span><span class="swatch" style="background:var(--accent)"></span>replayed capture</span></figcaption>' + svg + '</figure>';
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
  const marker = (v, color, label) => {
    if (!v) return '';
    const f = Math.max(0, Math.min(1, (Math.log10(Math.max(1, v)) - logMin) / (logMax - logMin)));
    const x = padL + f * iw;
    return `<line x1="${x}" y1="${padT}" x2="${x}" y2="${padT + ih}" stroke="${color}" stroke-width="1.5" stroke-dasharray="3,3"/><text x="${x + 4}" y="${padT + 12}" font-size="11" fill="${color}">${label} ${usFmt(v)}</text>`;
  };
  svg += marker(p50, 'var(--ok)', 'p50') + marker(p99, 'var(--accent)', 'p99');
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
    '<span><span class="swatch" style="background:var(--blue)"></span>ack latency</span>' +
    '<span><span class="swatch" style="background:var(--ok)"></span>p50</span>' +
    '<span><span class="swatch" style="background:var(--accent)"></span>p99</span>' +
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

function initRuns() {
  el('runs-filter').addEventListener('input', e => { runUi.filter = e.target.value.trim(); runUi.page = 0; renderRuns(); });
  el('runs-status').addEventListener('change', e => { runUi.status = e.target.value; runUi.page = 0; renderRuns(); });
  on('runs', renderRuns);
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
