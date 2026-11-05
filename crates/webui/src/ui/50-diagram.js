// 50-diagram.js — live hub-and-spoke traffic diagram for the running
// run. One WebSocket at a time (generation guard, F106); layout fitted
// to the canvas for up to a few hundred RTUs (F109); node shapes plus
// a legend with counts and a text table as alternatives to colour
// (F126); incremental, throttled updates instead of rebuilding every
// node and series on each 200 ms frame (F110).
'use strict';

const DIAGRAM_REFRESH_MS = 250;
const SPEED_BUCKETS = [
  { minPps: 1, period: 4.0, symbolSize: 4 },
  { minPps: 10, period: 2.0, symbolSize: 5 },
  { minPps: 100, period: 1.0, symbolSize: 6 },
  { minPps: 1000, period: 0.4, symbolSize: 7 },
];
const MAX_ANIMATED_STREAMS = 200;
const SESSION_GRACE_MS = 30000;
const BUCKET_STICKY_MS = 1500;
const LABELS_MAX_NODES = 40;

// State → colour + shape, so failed and active differ by more than hue.
// Colours are CSS tokens (both themes); the canvas gets them resolved.
const NODE_STYLE = {
  pending: { color: '--st-pending', border: '--dim', symbol: 'circle', label: 'pending' },
  cancelled: { color: '--st-cancelled', border: '--dim', symbol: 'roundRect', label: 'cancelled' },
  listening: { color: '--st-listening', border: '--ch-node-border', symbol: 'diamond', label: 'listening' },
  // Connected (handshake not done yet) is a hollow ring, active a
  // filled disc: they differ in shape, not only in shade (N25).
  connected: { color: '--surface', border: '--st-active', borderWidth: 2.5, symbol: 'circle', label: 'connected' },
  active: { color: '--st-active', border: '--ch-node-border', symbol: 'circle', label: 'active' },
  completed: { color: '--st-completed', border: '--ch-node-border', symbol: 'rect', label: 'completed' },
  failed: { color: '--st-failed', border: '--ch-node-border', symbol: 'triangle', label: 'failed' },
};
let _cssCache = { theme: null, map: new Map() };
function cssc(name) {
  const t = document.documentElement.dataset.theme || '';
  if (_cssCache.theme !== t) _cssCache = { theme: t, map: new Map() };
  if (!_cssCache.map.has(name)) _cssCache.map.set(name, getCssVar(name));
  return _cssCache.map.get(name);
}
const LEGEND_ORDER = ['active', 'connected', 'listening', 'pending', 'completed', 'failed', 'cancelled'];

const diag = {
  ws: null, runId: null, gen: 0, retry: 0, retryTimer: null,
  chart: null, layoutKey: '', layout: null, nodeSig: '', lineSig: '',
  latest: null, timer: null, lastRender: 0, grace: new Map(),
  target: '', tableAt: 0, finishedAt: 0,
};

function nodeStyle(state) { return NODE_STYLE[state] || NODE_STYLE.pending; }
function liveState(p) { return p.state === 'pending' && p.cancelled ? 'cancelled' : (p.state || 'pending'); }

// ---------------------------------------------------------------------------
// Connection management.

function syncDiagram() {
  const running = S.runs.find(r => r.status === 'running');
  const want = running && S.view === 'runs' && !document.hidden ? running : null;
  if (!want) {
    // Keep the last frame visible a few seconds after the run ends.
    if (diag.runId != null && Date.now() - diag.finishedAt > 4000) disconnectDiagram();
    if (!running && diag.runId == null) el('diagram-section').hidden = true;
    return;
  }
  diag.target = want.target_ip;
  connectDiagram(want.id);
}

function disconnectDiagram() {
  diag.gen++;
  clearTimeout(diag.retryTimer);
  if (diag.ws) { try { diag.ws.close(); } catch (_) { /* already closed */ } }
  diag.ws = null;
  diag.runId = null;
  el('diagram-section').hidden = true;
}

function connectDiagram(runId) {
  const ws = diag.ws;
  // In-flight guard: a CONNECTING socket counts as alive.
  if (diag.runId === runId && ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) return;
  if (diag.runId === runId && diag.retryTimer) return;   // a reconnect is scheduled
  if (diag.runId !== runId) {
    diag.grace.clear();   // no pps carried over from the previous run
    diag.layoutKey = '';
    diag.nodeSig = '';
    diag.lineSig = '';
    diag.retry = 0;
    diag.latest = null;
  }
  if (ws) { try { ws.close(); } catch (_) { /* already closed */ } }
  const gen = ++diag.gen;
  diag.runId = runId;
  el('diagram-section').hidden = false;
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const sock = new WebSocket(`${proto}//${location.host}/api/runs/${runId}/live`);
  diag.ws = sock;
  sock.onopen = () => { if (gen !== diag.gen) { sock.close(); return; } diag.retry = 0; };
  sock.onmessage = evt => {
    if (gen !== diag.gen) { sock.close(); return; }
    let frame;
    try { frame = JSON.parse(evt.data); } catch (_) { return; }
    diag.latest = frame;
    diag.latestAt = Date.now();
    if (frame.status && frame.status !== 'running') diag.finishedAt = Date.now();
    scheduleDiagramRender();
    onLiveFrame(frame);
  };
  sock.onclose = () => {
    if (gen !== diag.gen) return;
    diag.ws = null;
    const r = S.runs.find(x => x.id === runId);
    if (r && r.status === 'running' && S.view === 'runs') {
      // Unexpected close while the run is live: reconnect with backoff.
      const delay = Math.min(15000, 1000 * 2 ** Math.min(4, diag.retry++));
      diag.retryTimer = setTimeout(() => { diag.retryTimer = null; if (gen === diag.gen) connectDiagram(runId); }, delay);
    }
  };
}

// ---------------------------------------------------------------------------
// Rendering, throttled to DIAGRAM_REFRESH_MS and paused while hidden.

function scheduleDiagramRender() {
  if (diag.timer || document.hidden) return;
  const wait = Math.max(0, DIAGRAM_REFRESH_MS - (performance.now() - diag.lastRender));
  diag.timer = setTimeout(() => requestAnimationFrame(() => {
    diag.timer = null;
    diag.lastRender = performance.now();
    if (diag.latest) renderDiagram(diag.latest);
  }), wait);
}

function ensureChart() {
  if (typeof echarts === 'undefined') return null;
  const node = el('diagram-canvas');
  if (!node || node.clientWidth <= 0 || node.clientHeight <= 0) return null;
  if (diag.chart && diag.chart.getDom() === node) return diag.chart;
  diag.chart = echarts.init(node, chartTheme(), { renderer: 'canvas' });
  diag.layoutKey = '';
  const series = [{ id: 'spokes', type: 'lines', coordinateSystem: 'cartesian2d', zlevel: 1, silent: true, lineStyle: { color: cssc('--rule-strong'), width: 1, opacity: 0.45 }, data: [] }];
  for (const dir of ['up', 'down']) {
    const color = dir === 'up' ? cssc('--st-active') : cssc('--blue');
    SPEED_BUCKETS.forEach((b, bi) => series.push({
      id: `${dir}${bi}`, type: 'lines', coordinateSystem: 'cartesian2d', zlevel: 2 + bi, silent: true,
      effect: { show: true, period: b.period, trailLength: 0.35, color, symbolSize: b.symbolSize },
      lineStyle: { color, opacity: 0.22, width: 1 }, data: [],
    }));
  }
  series.push({
    id: 'nodes', type: 'graph', coordinateSystem: 'cartesian2d', zlevel: 10, roam: false,
    label: { show: false }, lineStyle: { width: 0, opacity: 0 }, emphasis: { scale: 1.6 }, data: [], links: [],
  });
  diag.chart.setOption({
    backgroundColor: 'transparent', animation: false,
    grid: { left: 0, right: 0, top: 0, bottom: 0 },
    xAxis: { type: 'value', show: false, min: 0, max: 1 },
    yAxis: { type: 'value', show: false, min: 0, max: 1, inverse: true },
    tooltip: {
      trigger: 'item', confine: true,
      formatter: p => {
        if (p.seriesId !== 'nodes') return '';
        if (p.dataIndex === 0) return `target ${esc(diag.target)}`;
        const s = ((diag.latest && diag.latest.per_session) || [])[p.dataIndex - 1];
        if (!s) return esc(p.name);
        return `<b>${esc(s.src_ip || p.name)}</b><br>${esc(liveState(s))}<br>sent ${fmtInt(s.sent)} · received ${fmtInt(s.received)}`;
      },
    },
    series,
  });
  return diag.chart;
}

// Concentric ellipses fitted to the canvas; ring capacity follows the
// ring's perimeter, so nodes never leave the canvas or overlap.
function computeLayout(n, W, H) {
  const labels = n <= LABELS_MAX_NODES;
  let size = n <= 4 ? 26 : n <= 30 ? 18 : n <= 80 ? 13 : 10;
  const mx = size / 2 + (labels ? 92 : 6);
  const my = size / 2 + (labels ? 12 : 6);
  const rxMax = Math.max(40, W / 2 - mx);
  const ryMax = Math.max(40, H / 2 - my);
  const perim = (a, b) => Math.PI * (3 * (a + b) - Math.sqrt((3 * a + b) * (a + 3 * b)));
  let rings = [];
  for (let attempt = 0; attempt < 6; attempt++) {
    // At least a node's width of air between neighbours (F109).
    const spacing = size * 2.1 + (labels ? 10 : 0);
    rings = [];
    let cap = 0;
    for (let k = 1; k <= 10 && cap < n; k++) {
      rings = [];
      cap = 0;
      for (let i = 0; i < k; i++) {
        const f = k === 1 ? 1 : 0.42 + (0.58 * i) / (k - 1);
        const c = Math.max(1, Math.floor(perim(rxMax * f, ryMax * f) / spacing));
        rings.push({ f, cap: c });
        cap += c;
      }
    }
    if (cap >= n) break;
    size = Math.max(6, size * 0.85);
  }
  const total = rings.reduce((a, r) => a + r.cap, 0);
  let left = n;
  const pos = [];
  rings.forEach((ring, i) => {
    const take = i === rings.length - 1 ? left : Math.min(left, Math.round((ring.cap / total) * n));
    left -= take;
    for (let j = 0; j < take; j++) {
      const a = (j / take) * Math.PI * 2 - Math.PI / 2 + (i % 2 ? Math.PI / Math.max(1, take) : 0);
      pos.push([W / 2 + Math.cos(a) * rxMax * ring.f, H / 2 + Math.sin(a) * ryMax * ring.f]);
    }
  });
  return { W, H, cx: W / 2, cy: H / 2, pos, size, labels };
}

function gracePps(idx, dir, cur) {
  const now = performance.now();
  let g = diag.grace.get(idx);
  if (!g) { g = { up: [0, 0], down: [0, 0], ub: [-1, 0], db: [-1, 0] }; diag.grace.set(idx, g); }
  const slot = g[dir];
  if (cur > 0) { slot[0] = now; slot[1] = cur; return cur; }
  return slot[0] && now - slot[0] < SESSION_GRACE_MS ? slot[1] : 0;
}
function stickyBucket(idx, dir, pps) {
  const now = performance.now();
  const g = diag.grace.get(idx);
  const slot = dir === 'up' ? g.ub : g.db;
  let want = -1;
  for (let i = SPEED_BUCKETS.length - 1; i >= 0; i--) if (pps >= SPEED_BUCKETS[i].minPps) { want = i; break; }
  if (slot[0] < 0 || want < 0 || now - slot[1] >= BUCKET_STICKY_MS) { slot[0] = want; slot[1] = now; }
  return slot[0];
}

function renderDiagram(frame) {
  const sessions = frame.per_session || [];
  renderDiagramText(frame, sessions);
  const chart = ensureChart();
  if (!chart) return;
  const dom = chart.getDom();
  const W = dom.clientWidth;
  const H = dom.clientHeight;
  const key = `${frame.run_id}|${sessions.length}|${W}x${H}`;
  const update = [];
  if (key !== diag.layoutKey) {
    chart.resize();
    diag.layoutKey = key;
    diag.layout = computeLayout(sessions.length, W, H);
    diag.nodeSig = '';
    diag.lineSig = '';
    chart.setOption({ xAxis: { max: W }, yAxis: { max: H } });
    const L = diag.layout;
    update.push({ id: 'spokes', data: L.pos.map(p => ({ coords: [p, [L.cx, L.cy]] })) });
  }
  const L = diag.layout;
  for (let i = 0; i < sessions.length; i++) {
    const s = liveState(sessions[i]);
    if (s === 'completed' || s === 'failed' || s === 'pending' || s === 'cancelled') diag.grace.delete(i);
  }
  const sig = sessions.map(liveState).join(',');
  if (sig !== diag.nodeSig) {
    diag.nodeSig = sig;
    const data = [{
      name: 'target', isTarget: true, value: [L.cx, L.cy], symbol: 'circle', symbolSize: 40,
      itemStyle: { color: cssc('--ink'), borderColor: cssc('--accent'), borderWidth: 3 },
      label: { show: true, position: 'bottom', color: cssc('--ink'), fontSize: 12, fontWeight: 600, formatter: `target ${diag.target || ''}` },
    }];
    sessions.forEach((p, i) => {
      const st = liveState(p);
      const ns = nodeStyle(st);
      data.push({
        name: p.src_ip || `session ${i}`, state: st, sent: p.sent, received: p.received,
        value: L.pos[i], symbol: ns.symbol, symbolSize: st === 'failed' ? L.size * 1.25 : L.size,
        itemStyle: { color: cssc(ns.color), borderColor: cssc(ns.border), borderWidth: ns.borderWidth || 1 },
        label: { show: L.labels, position: 'right', color: cssc('--ink'), fontSize: 11, formatter: '{b}' },
      });
    });
    update.push({ id: 'nodes', data });
  }
  // Animated streams, busiest first, capped.
  const up = SPEED_BUCKETS.map(() => []);
  const down = SPEED_BUCKETS.map(() => []);
  const ranked = sessions.map((p, i) => ({ p, i, t: (p.pps_sent || 0) + (p.pps_recv || 0) })).sort((a, b) => b.t - a.t);
  let animated = 0;
  let hidden = 0;
  const off = Math.max(4, L.size * 0.45);
  for (const { p, i } of ranked) {
    const alive = p.state === 'active' || p.state === 'connected';
    let u = gracePps(i, 'up', p.pps_sent || 0);
    let d = gracePps(i, 'down', p.pps_recv || 0);
    if (alive) { u = u || 1; d = d || 1; }
    const ub = stickyBucket(i, 'up', u);
    const db = stickyBucket(i, 'down', d);
    const need = (ub >= 0) + (db >= 0);
    if (!need) continue;
    if (animated + need > MAX_ANIMATED_STREAMS) { hidden++; continue; }
    const [x, y] = L.pos[i];
    const dx = L.cx - x;
    const dy = L.cy - y;
    const len = Math.max(1, Math.hypot(dx, dy));
    const px = (-dy / len) * off;
    const py = (dx / len) * off;
    if (ub >= 0) { up[ub].push(i); animated++; }
    if (db >= 0) { down[db].push(i); animated++; }
    p._ep = { up: [[x + px, y + py], [L.cx + px, L.cy + py]], down: [[L.cx - px, L.cy - py], [x - px, y - py]] };
  }
  const lineSig = up.map(a => a.join('.')).join('|') + '/' + down.map(a => a.join('.')).join('|');
  if (lineSig !== diag.lineSig) {
    diag.lineSig = lineSig;
    up.forEach((arr, bi) => update.push({ id: `up${bi}`, data: arr.map(i => ({ coords: sessions[i]._ep.up })) }));
    down.forEach((arr, bi) => update.push({ id: `down${bi}`, data: arr.map(i => ({ coords: sessions[i]._ep.down })) }));
  }
  if (update.length) chart.setOption({ series: update });
  diag.streams = { animated, hidden };
}

function renderDiagramText(frame, sessions) {
  const counts = {};
  for (const p of sessions) { const s = liveState(p); counts[s] = (counts[s] || 0) + 1; }
  const active = (counts.active || 0) + (counts.connected || 0);
  const st = diag.streams || { animated: 0, hidden: 0 };
  setText(el('diagram-title'), `Live traffic · run #${frame.run_id}`);
  setText(el('diagram-meta'), `${frame.status || '—'}${frame.role ? ' · ' + frame.role : ''}`);
  setHTML(el('diagram-stats'),
    `<div class="stat"><span class="k">Sent</span><span class="v accent">${fmtInt(frame.sent || 0)}</span></div>` +
    `<div class="stat"><span class="k">Uplink</span><span class="v accent">${fmtInt(frame.pps_sent || 0)} msg/s</span></div>` +
    `<div class="stat"><span class="k">Downlink</span><span class="v blue">${fmtInt(frame.pps_recv || 0)} msg/s</span></div>` +
    `<div class="stat"><span class="k">Active sessions</span><span class="v">${active} of ${sessions.length}</span></div>` +
    `<div class="stat"><span class="k">Animated streams</span><span class="v">${st.animated}${st.hidden ? ` (${st.hidden} not animated)` : ''}</span></div>`);
  const p = pct(frame.sent || 0, frame.planned || 0);
  // No plan yet (slaves waiting for the master): no "0% · 0 / 0".
  qs('#diagram-card .diagram-progress').hidden = !(frame.planned > 0);
  el('diagram-pfill').style.width = p + '%';
  setText(el('diagram-plabel'), `${p}% · ${fmtInt(frame.sent || 0)} / ${fmtInt(frame.planned || 0)}`);
  let lg = '';
  for (const s of LEGEND_ORDER) {
    if (!counts[s]) continue;
    lg += `<li><svg class="shape" viewBox="0 0 12 12" aria-hidden="true">${shapeSvg(s)}</svg>${counts[s]} ${s}</li>`;
  }
  setHTML(el('diagram-legend'), lg);
  const label = `Live traffic diagram for run ${frame.run_id}: ` + LEGEND_ORDER.filter(s => counts[s]).map(s => `${counts[s]} ${s}`).join(', ') + ` of ${sessions.length} sessions. The session table below lists every session.`;
  const canvas = el('diagram-canvas');
  if (canvas.getAttribute('aria-label') !== label) canvas.setAttribute('aria-label', label);
  // Text alternative, at most once per second and only while open.
  const wrap = el('diagram-table-wrap');
  if (wrap.open && performance.now() - diag.tableAt > 1000) {
    diag.tableAt = performance.now();
    const rows = sessions.map(p => `<tr><td><code>${esc(p.src_ip || '—')}</code></td><td><span class="st st-${liveState(p)}">${liveState(p)}</span></td>` +
      `<td class="num">${fmtInt(p.sent)}</td><td class="num">${fmtInt(p.received)}</td><td class="num">${fmtInt(p.pps_sent)}</td><td class="num">${fmtInt(p.pps_recv)}</td>` +
      `<td class="num">${p.ack_p50_us != null ? usFmt(p.ack_p50_us) : '—'}</td><td class="num">${p.ack_p99_us != null ? usFmt(p.ack_p99_us) : '—'}</td></tr>`).join('');
    setHTML(qs('#diagram-table tbody'), rows);
  }
}

function shapeSvg(state) {
  const s = nodeStyle(state);
  const f = `style="fill:var(${s.color});stroke:var(${s.border})" stroke-width="${s.borderWidth ? 2 : 1}"`;
  switch (s.symbol) {
    case 'diamond': return `<path d="M6 0.5 L11.5 6 L6 11.5 L0.5 6 Z" ${f}/>`;
    case 'rect': return `<rect x="1" y="1" width="10" height="10" ${f}/>`;
    case 'roundRect': return `<rect x="1" y="1" width="10" height="10" rx="3" ${f}/>`;
    case 'triangle': return `<path d="M6 0.5 L11.5 11 L0.5 11 Z" ${f}/>`;
    default: return `<circle cx="6" cy="6" r="${s.borderWidth ? 4.5 : 5}" ${f}/>`;
  }
}

actions({
  'diagram-fullscreen': b => toggleDiagramFullscreen(b),
});

function toggleDiagramFullscreen(b) {
  const card = el('diagram-card');
  const on = !card.classList.contains('fullscreen');
  card.classList.toggle('fullscreen', on);
  document.body.classList.toggle('no-scroll', on);
  const btn = b || el('diagram-fs-btn');
  btn.setAttribute('aria-pressed', String(on));
  setText(btn, on ? 'Exit full screen' : 'Full screen');
  diag.layoutKey = '';
  if (diag.chart) requestAnimationFrame(() => { diag.chart.resize(); if (diag.latest) renderDiagram(diag.latest); });
}

function initDiagram() {
  on('runs', syncDiagram);
  // New theme: rebuild the canvas with the new colours.
  on('theme', () => {
    if (diag.chart) { try { diag.chart.dispose(); } catch (_) { /* gone */ } diag.chart = null; }
    diag.layoutKey = '';
    diag.nodeSig = '';
    diag.lineSig = '';
    if (diag.latest) renderDiagram(diag.latest);
  });
  on('route', syncDiagram);
  document.addEventListener('visibilitychange', () => { if (document.hidden) disconnectDiagram(); else syncDiagram(); });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && el('diagram-card').classList.contains('fullscreen')) toggleDiagramFullscreen();
  });
  el('diagram-table-wrap').addEventListener('toggle', () => { diag.tableAt = 0; if (diag.latest) renderDiagramText(diag.latest, diag.latest.per_session || []); });
  let rt = null;
  window.addEventListener('resize', () => {
    clearTimeout(rt);
    rt = setTimeout(() => { if (diag.chart) { diag.layoutKey = ''; diag.chart.resize(); if (diag.latest) renderDiagram(diag.latest); } }, 150);
  });
}
