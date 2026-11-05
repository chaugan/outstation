// 10-shell.js — app shell: hash router and navigation, the status bar
// (real connection state from poll + SSE health, active run), server
// health banner, the run-event stream (concurrent-run banner), and the
// shared protocol and NIC lists.
'use strict';

// ---------------------------------------------------------------------------
// Router. Routes: #/library, #/configure, #/runs, #/runs/<id>, #/analysis,
// #/analysis/<runId>. Reload keeps the view.

const VIEWS = ['library', 'configure', 'runs', 'analysis'];
const VIEW_TITLES = { library: 'Library', configure: 'Configure', runs: 'Runs', analysis: 'Analysis' };

function parseRoute() {
  const h = (location.hash || '').replace(/^#\/?/, '');
  const [view, arg] = h.split('/');
  return { view: VIEWS.includes(view) ? view : null, arg: arg || null };
}

function go(view, arg) {
  const want = '#/' + view + (arg != null ? '/' + arg : '');
  if (location.hash === want) applyRoute(true);
  else location.hash = want;
}

function applyRoute(userNav) {
  const r = parseRoute();
  const view = r.view || (S.view || 'library');
  const changed = view !== S.view;
  S.view = view;
  for (const v of VIEWS) {
    const sec = el('view-' + v);
    if (sec) sec.hidden = v !== view;
  }
  for (const a of qsa('.nav a')) {
    if (a.dataset.view === view) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  document.title = `${VIEW_TITLES[view]} · outstation`;
  emit('route', { view, arg: r.arg, changed });
  if (userNav && changed) {
    const h = el('h-' + view);
    if (h) h.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }
}

window.addEventListener('hashchange', () => applyRoute(true));

// ---------------------------------------------------------------------------
// Connection state, from two sources: the runs poller (health of plain
// HTTP) and the SSE stream. Shown as text, not only as a coloured dot.

const conn = {
  pollOk: null,       // null = no result yet
  pollFailures: 0,
  nextRetryAt: 0,
  lastOkAt: 0,
  sse: 'connecting',  // connecting | open | down | unsupported
};

function setPollHealth(ok, nextDelayMs) {
  if (ok) {
    conn.pollOk = true;
    conn.pollFailures = 0;
    conn.lastOkAt = Date.now();
  } else {
    conn.pollOk = false;
    conn.pollFailures++;
    conn.nextRetryAt = Date.now() + (nextDelayMs || 0);
  }
  renderConn();
}

function renderConn() {
  const node = el('conn');
  let state;
  let text;
  if (conn.pollOk === null) {
    state = 'connecting'; text = 'connecting…';
  } else if (!conn.pollOk) {
    const secs = Math.max(0, Math.round((conn.nextRetryAt - Date.now()) / 1000));
    state = conn.pollFailures >= 3 ? 'down' : 'stale';
    text = conn.pollFailures >= 3 ? `offline · retry in ${secs} s` : 'reconnecting…';
  } else if (conn.sse === 'open' || conn.sse === 'unsupported') {
    state = 'ok'; text = 'live';
  } else {
    state = 'stale'; text = 'live (polling; event stream reconnecting)';
  }
  if (node.dataset.state !== state) node.dataset.state = state;
  setText(el('conn-text'), text);
  node.title = conn.lastOkAt ? `last update ${new Date(conn.lastOkAt).toLocaleTimeString()}` : '';
}
setInterval(() => { if (conn.pollOk === false) renderConn(); }, 1000);

// Active-run chip and nav badge, from the runs list.
function renderActiveRun() {
  const chip = el('active-run');
  const badge = el('nav-running');
  const running = S.runs.filter(r => r.status === 'running');
  if (!running.length) {
    chip.hidden = true;
    badge.hidden = true;
    return;
  }
  const r = running[0];
  chip.hidden = false;
  chip.href = `#/runs/${r.id}`;
  const p = r.planned ? ` · ${pct(r.sent, r.planned)}%` : '';
  setText(chip, `${runNum(r.id)} running${p}`);
  badge.hidden = false;
  setText(badge, String(running.length));
  badge.setAttribute('aria-label', `${running.length} running`);
}
on('runs', renderActiveRun);

// ---------------------------------------------------------------------------
// Server status: version, health (degraded[]), capabilities.

async function loadStatus() {
  const res = await api('/api/status');
  if (!res.ok || !res.data || typeof res.data !== 'object') return;
  S.status = res.data;
  const v = 'v' + res.data.version;
  setText(el('version'), v);
  setText(el('foot-version'), v);
  const deg = res.data.degraded || [];
  const banner = el('degraded-banner');
  const text = deg.join(' · ');
  if (deg.length && banner.dataset.text !== text) {
    banner.dataset.text = text;
    setText(el('degraded-text'), text);
    banner.hidden = false;
  } else if (!deg.length) {
    banner.hidden = true;
    banner.dataset.text = '';
  }
  emit('status', S.status);
}

// ---------------------------------------------------------------------------
// Run events (SSE). Every event triggers a runs refresh; runs started or
// stopped by another client show the concurrent-run banner.

let _es = null;
function startRunEvents() {
  if (!window.EventSource) { conn.sse = 'unsupported'; renderConn(); return; }
  if (_es) return;
  const es = new EventSource('/api/events');
  _es = es;
  es.onopen = () => { conn.sse = 'open'; renderConn(); };
  es.onerror = () => {
    // EventSource reconnects by itself unless the server closed it
    // for good (readyState CLOSED); then start a new one later.
    conn.sse = 'down';
    renderConn();
    if (es.readyState === EventSource.CLOSED) {
      _es = null;
      setTimeout(startRunEvents, 5000);
    }
  };
  es.addEventListener('hello', ev => {
    let d;
    try { d = JSON.parse(ev.data); } catch (_) { return; }
    S.active = d.active || null;
    emit('active', S.active);
  });
  const onRunEvent = ev => {
    let d;
    try { d = JSON.parse(ev.data); } catch (_) { return; }
    S.active = ev.type === 'run_started' ? { run_id: d.run_id, client_ip: d.client_ip, started_at: d.time } : null;
    emit('run-event', { type: ev.type, data: d });
    if (typeof pollRunsSoon === 'function') pollRunsSoon();
    const mine = d.client_id && d.client_id === CLIENT_ID;
    if (mine || ev.type === 'run_finished') return;
    const t = d.time ? new Date(d.time * 1000).toLocaleTimeString() : 'just now';
    const verb = ev.type === 'run_started' ? 'was started' : 'was stopped';
    setText(el('run-banner-text'), `Run #${d.run_id} ${verb} by ${d.client_ip || 'another client'} at ${t}.`);
    el('run-banner-link').href = `#/runs/${d.run_id}`;
    el('run-banner').hidden = false;
    announce(`Run ${d.run_id} ${verb} by ${d.client_ip || 'another client'}`);
  };
  es.addEventListener('run_started', onRunEvent);
  es.addEventListener('run_stopped', onRunEvent);
  es.addEventListener('run_finished', onRunEvent);
}

// ---------------------------------------------------------------------------
// Shared lists: protocols and NICs.

async function loadProtocols() {
  const res = await api('/api/protocols');
  if (!res.ok || !Array.isArray(res.data)) {
    setText(el('foot-protocols'), 'unavailable');
    return;
  }
  S.protocols = res.data;
  setText(el('foot-protocols'), S.protocols.map(p => `${p.name} (${p.status})`).join(' · ') || '—');
  emit('protocols', S.protocols);
}

async function loadNics() {
  const res = await api('/api/nics');
  if (!res.ok || !Array.isArray(res.data)) {
    S.nics = [];
    emit('nics', S.nics);
    return;
  }
  S.nics = res.data.filter(n => !n.loopback && !n.bridge);
  emit('nics', S.nics);
}

// Why a NIC is protected (empty = not protected). Mirrors netctl's rules
// that the UI can see: default route, bridge port, and the address this
// page is served from.
function nicProtection(n) {
  const why = [];
  if (n.default_route) why.push('default route');
  if (n.bridge_port) why.push('bridge port');
  if (isIPv4(location.hostname) && (n.ipv4 || []).some(a => a.split('/')[0] === location.hostname)) {
    why.push('serves this page');
  }
  return why;
}

// Fill a <select> with NICs; protected ones are labelled as such.
function fillNicSelect(sel, placeholder) {
  if (!sel) return;
  const current = sel.value || sel.dataset.want || '';
  let h = `<option value="">${esc(placeholder)}</option>`;
  for (const n of S.nics) {
    const ip = (n.ipv4 || []).length ? ` · ${n.ipv4.join(', ')}` : '';
    const down = n.up ? '' : ' · down';
    const prot = nicProtection(n);
    const tag = prot.length ? ` · protected: ${prot.join(', ')}` : '';
    h += `<option value="${esc(n.name)}"${prot.length ? ' data-protected="1"' : ''}>${esc(n.name + ip + down + tag)}</option>`;
  }
  sel.innerHTML = h;
  if (current && S.nics.some(n => n.name === current)) sel.value = current;
  else if (current) sel.dataset.want = current;
}
