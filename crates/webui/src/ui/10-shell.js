// 10-shell.js — app shell: hash router and navigation, the status bar
// (real connection state from poll + SSE health, active run), server
// health banner, the run-event stream (concurrent-run banner), and the
// shared protocol and NIC lists.
'use strict';

// ---------------------------------------------------------------------------
// Router. Routes: #/library, #/configure, #/runs, #/runs/<id>, #/analysis,
// #/analysis/<runId>[/<analysisId>], #/compare[/<runA>/<runB>][?thresholds].
// Reload keeps the view. `args` holds every path segment after the
// view, `query` the part after "?".

const VIEWS = ['library', 'configure', 'runs', 'analysis', 'compare'];
const VIEW_TITLES = { library: 'Library', configure: 'Configure', runs: 'Runs', analysis: 'Analysis', compare: 'Compare' };

function parseRoute() {
  const h = (location.hash || '').replace(/^#\/?/, '');
  const qi = h.indexOf('?');
  const path = qi < 0 ? h : h.slice(0, qi);
  const parts = path.split('/');
  const view = parts[0];
  let query;
  try { query = new URLSearchParams(qi < 0 ? '' : h.slice(qi + 1)); } catch (_) { query = new URLSearchParams(); }
  return { view: VIEWS.includes(view) ? view : null, arg: parts[1] || null, args: parts.slice(1), query };
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
  emit('route', { view, arg: r.arg, args: r.args, query: r.query, changed });
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
// Server status: version, health (degraded_detail[] with codes, journal
// cleanup pending), capabilities, auto-analysis.

// What each degraded code means for the operator, and what to do.
const HEALTH_TEXT = {
  db_not_writable: ['Run history is not being saved', 'New runs, analyses and profiles are lost on restart. Check the state directory\'s permissions and free space.'],
  ephemeral: ['History kept in memory only', 'Runs, analyses and profiles are lost on restart.'],
  low_disk: ['Disk space is low', 'Uploads and replay captures may be refused; the oldest captures are evicted first.'],
  disk_unknown: ['Free disk space unknown', 'The server cannot guard against a full disk.'],
  missing_capabilities: ['Runs will fail at network setup', 'Start the server through the systemd unit, or grant those capabilities to the binary.'],
  capabilities_unknown: ['Network privileges unknown', 'Runs may fail at network setup.'],
  journal_unreadable: ['Host-state journal unreadable', 'The server cannot tell whether an earlier run left network changes behind.'],
  cleanup_pending: ['Host cleanup pending', ''],
  shutting_down: ['Server shutting down', 'New runs are refused.'],
};

function healthItems(st) {
  const detail = Array.isArray(st.degraded_detail) ? st.degraded_detail : null;
  const items = detail
    ? detail.map(d => ({ code: d.code, message: d.message }))
    : (st.degraded || []).map(m => ({ code: '', message: String(m) }));
  // Journal entries are shown even when no code reports them (a run is
  // active and owns them, or an older server without the code).
  const jp = st.journal_pending;
  const pending = jp ? (jp.guards || 0) + (jp.aliases || 0) : 0;
  if (pending && !items.some(i => i.code === 'cleanup_pending') && !(st.active_run)) {
    items.push({ code: 'cleanup_pending', message: `${pending} host-state journal entr${pending === 1 ? 'y' : 'ies'} (${jp.guards || 0} guard, ${jp.aliases || 0} alias)` });
  }
  return items;
}

function renderHealth(st) {
  const items = healthItems(st);
  const banner = el('degraded-banner');
  const chip = el('health-chip');
  const sig = JSON.stringify(items);
  if (!items.length) {
    banner.hidden = true;
    banner.dataset.sig = '';
    chip.hidden = true;
    return;
  }
  const html = '<ul class="health-list">' + items.map(i => {
    const t = HEALTH_TEXT[i.code];
    const title = t ? t[0] : 'Degraded';
    const msg = String(i.message || '').replace(/\.\s*$/, '');
    const advice = t && t[1] ? ` ${t[1]}` : '';
    return `<li data-code="${esc(i.code)}"><b>${esc(title)}.</b> ${esc(msg.charAt(0).toUpperCase() + msg.slice(1))}.${esc(advice)}</li>`;
  }).join('') + '</ul>';
  setHTML(el('degraded-text'), html);
  chip.hidden = false;
  const bad = items.some(i => ['db_not_writable', 'missing_capabilities', 'shutting_down', 'low_disk'].includes(i.code));
  chip.dataset.level = bad ? 'bad' : 'warn';
  setText(chip, `${items.length} health ${items.length === 1 ? 'issue' : 'issues'}`);
  // A new set of problems re-opens a dismissed banner.
  if (banner.dataset.sig !== sig) {
    banner.dataset.sig = sig;
    banner.hidden = false;
  }
}

async function loadStatus() {
  const res = await api('api/status');
  if (!res.ok || !res.data || typeof res.data !== 'object') return;
  S.status = res.data;
  const v = 'v' + res.data.version;
  setText(el('version'), v);
  setText(el('foot-version'), v);
  if (typeof res.data.auto_analyze === 'boolean') {
    setText(el('foot-auto'), res.data.auto_analyze ? 'on' : 'off');
  }
  renderHealth(res.data);
  emit('status', S.status);
}

actions({
  'show-health': () => {
    const b = el('degraded-banner');
    b.hidden = false;
    b.scrollIntoView({ block: 'nearest' });
    const t = qs('.health-list', b);
    if (t) { t.setAttribute('tabindex', '-1'); t.focus({ preventScroll: true }); }
  },
});

// ---------------------------------------------------------------------------
// Run events (SSE). Every event triggers a runs refresh; runs started or
// stopped by another client show the concurrent-run banner.

let _es = null;
function startRunEvents() {
  if (!window.EventSource) { conn.sse = 'unsupported'; renderConn(); return; }
  if (_es) return;
  const es = new EventSource('api/events');
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
  // Auto (and on-demand) analysis results: refetch that run, no banner.
  const onAnalysisEvent = ev => {
    let d;
    try { d = JSON.parse(ev.data); } catch (_) { return; }
    emit('analysis-event', { type: ev.type, data: d });
    if (typeof refetchRun === 'function' && d.run_id != null) refetchRun(Number(d.run_id));
  };
  es.addEventListener('analysis_finished', onAnalysisEvent);
  es.addEventListener('analysis_failed', onAnalysisEvent);
}

// ---------------------------------------------------------------------------
// Shared lists: protocols and NICs.

async function loadProtocols() {
  const res = await api('api/protocols');
  if (!res.ok || !Array.isArray(res.data)) {
    setText(el('foot-protocols'), 'unavailable');
    return;
  }
  S.protocols = res.data;
  setText(el('foot-protocols'), S.protocols.map(p => `${p.name} (${p.status})`).join(' · ') || '—');
  emit('protocols', S.protocols);
}

async function loadNics() {
  const res = await api('api/nics');
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

// ---------------------------------------------------------------------------
// Keyboard shortcuts: "g" then a letter switches view, "/" focuses the
// current view's filter, "?" opens the help. Never while typing in a
// field, with a modifier held, or while a dialog is open.

const GO_KEYS = { l: 'library', c: 'configure', r: 'runs', a: 'analysis', m: 'compare' };
// The filter "/" focuses, per view (the first visible one wins).
const VIEW_FILTERS = {
  library: ['#lib-filter'],
  configure: ['#rtu-filter', '#cfg-pcap'],
  runs: ['#runs-filter'],
  analysis: ['#an-ep-q', '#an-run'],
  compare: ['#cmp-q', '#cmp-a'],
};
let _gPending = 0;

function isTypingTarget(t) {
  if (!t || t === document.body) return false;
  if (t.isContentEditable) return true;
  const tag = t.tagName;
  if (tag === 'TEXTAREA' || tag === 'SELECT') return true;
  return tag === 'INPUT' && !['checkbox', 'radio', 'button', 'submit', 'reset', 'file', 'range', 'color'].includes(t.type);
}

function focusViewFilter() {
  for (const sel of VIEW_FILTERS[S.view] || []) {
    const n = qs(sel);
    if (n && n.getClientRects().length && !n.disabled) {
      for (let d = n.closest('details'); d; d = d.parentElement && d.parentElement.closest('details')) d.open = true;
      n.focus();
      if (n.select && n.type === 'search') n.select();
      return true;
    }
  }
  announce('This view has no filter right now');
  return false;
}

function showKbdHelp() {
  const d = el('kbd-dlg');
  if (!d || d.open) return;
  d._opener = document.activeElement;
  if (typeof d.showModal === 'function') d.showModal(); else d.setAttribute('open', '');
  el('kbd-close').focus();
}
function closeKbdHelp() {
  const d = el('kbd-dlg');
  if (!d || !d.open) return;
  d.close();
}

document.addEventListener('keydown', e => {
  if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey) return;
  if (isTypingTarget(e.target)) { _gPending = 0; return; }
  if (qs('dialog[open]')) return;
  const k = e.key;
  if (_gPending && Date.now() - _gPending < 1500) {
    _gPending = 0;
    const v = GO_KEYS[k.toLowerCase()];
    if (v) { e.preventDefault(); go(v); }
    return;
  }
  _gPending = 0;
  if (k === 'g') { _gPending = Date.now(); return; }
  if (k === '/') { e.preventDefault(); focusViewFilter(); return; }
  if (k === '?') { e.preventDefault(); showKbdHelp(); }
});

actions({ 'kbd-help': showKbdHelp });

function initShell() {
  applyTheme(false);
  const d = el('kbd-dlg');
  el('kbd-close').addEventListener('click', closeKbdHelp);
  d.addEventListener('close', () => { if (d._opener && d._opener.isConnected) d._opener.focus(); });
  d.addEventListener('click', e => { if (e.target === d) closeKbdHelp(); });
}
