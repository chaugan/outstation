// 60-diagram.js — live traffic diagram
// Spliced into the served page by crates/webui/build.rs (classic script,
// shared global scope with the other ui/*.js files, loaded in file-name order).

// =========================================================================
//  live network diagram (echarts)
// =========================================================================
let diagramChart = null;
let diagramWs = null;
let diagramRunId = null;
let diagramFullscreen = false;
let diagramFs0Parent = null;  // where the canvas was before fullscreen
let diagramTargetLabel = '';
const DIAGRAM_REFRESH_MS = 250;

// Speed buckets for the animated particle streams. Each bucket gets
// its own ECharts `lines` series so we can vary the effect period
// (= particle traversal time) per bucket — ECharts doesn't support
// per-data-item effect overrides.
//
// minPps is inclusive. Pps below the lowest bucket → static line.
// `period` is seconds per particle traversal. Lower = faster.
const SPEED_BUCKETS = [
  { minPps: 1,    period: 4.0, symbolSize: 4 },
  { minPps: 10,   period: 2.0, symbolSize: 5 },
  { minPps: 100,  period: 1.0, symbolSize: 6 },
  { minPps: 1000, period: 0.4, symbolSize: 7 },
];
// Hard cap on simultaneously animated streams across both directions.
// Beyond this, sessions still appear as nodes + static lines but
// don't animate, so the browser doesn't get hammered when there are
// hundreds of high-pps sessions.
const MAX_ANIMATED_STREAMS = 200;

function pickSpeedBucket(pps) {
  if (pps <= 0) return -1;
  for (let i = SPEED_BUCKETS.length - 1; i >= 0; i--) {
    if (pps >= SPEED_BUCKETS[i].minPps) return i;
  }
  return -1;
}

function ensureDiagramChart() {
  if (typeof echarts === 'undefined') return null;
  const node = document.getElementById('diagram-canvas');
  if (!node) return null;
  if (diagramChart && diagramChart.getDom() === node) return diagramChart;
  if (diagramChart) {
    diagramChart.dispose();
  }
  diagramChart = echarts.init(node, null, { renderer: 'canvas' });

  // Build the series list dynamically:
  //   - 1 static-spoke line series
  //   - 1 series per speed bucket × 2 directions (8 total)
  //   - 1 graph series for the nodes
  const series = [];
  // Static spokes (back layer).
  series.push({
    type: 'lines',
    coordinateSystem: 'cartesian2d',
    polyline: false,
    zlevel: 1,
    lineStyle: { color: '#c9c9c4', width: 1, opacity: 0.5 },
    data: [],
  });
  // Up + down series per bucket.
  // We can't rely on `lineStyle.curveness` to separate the two
  // directions because ECharts effect particles travel the chord
  // (not the curved line), so curving the line still leaves the
  // particles on the same path. Instead `renderDiagramFrame` shifts
  // the up- and down-line ENDPOINTS perpendicularly by a few pixels
  // before pushing them in here, so they're truly parallel offset
  // straight lines that never overlap.
  for (const dir of ['up', 'down']) {
    const color = dir === 'up' ? '#c15a2b' : '#1f4a78';
    for (let bi = 0; bi < SPEED_BUCKETS.length; bi++) {
      const b = SPEED_BUCKETS[bi];
      series.push({
        type: 'lines',
        coordinateSystem: 'cartesian2d',
        polyline: false,
        zlevel: 2 + bi,
        effect: {
          show: true,
          period: b.period,
          trailLength: 0.35,
          color,
          symbolSize: b.symbolSize,
        },
        // Faint visible track so the user sees the geometry the
        // particles follow even between bursts.
        lineStyle: { color, opacity: 0.22, width: 1 },
        data: [],
      });
    }
  }
  // Nodes on top.
  series.push({
    type: 'graph',
    coordinateSystem: 'cartesian2d',
    zlevel: 10,
    symbolSize: 16,
    roam: false,
    label: { show: false },
    edgeSymbol: ['none', 'none'],
    lineStyle: { width: 0, opacity: 0 },
    emphasis: { focus: 'self' },
    data: [],
    links: [],
  });

  diagramChart.setOption({
    backgroundColor: 'transparent',
    // Kill the per-update transition. The particle effect stays
    // animated (it's driven by the lines.effect series, not by the
    // setOption transition), but data swaps don't fade-in.
    animation: false,
    animationDurationUpdate: 0,
    grid: { left: 0, right: 0, top: 0, bottom: 0, containLabel: false },
    xAxis: {
      type: 'value', show: false, min: 0, max: 1000,
      axisLine: { show: false }, splitLine: { show: false },
    },
    yAxis: {
      type: 'value', show: false, min: 0, max: 540, inverse: true,
      axisLine: { show: false }, splitLine: { show: false },
    },
    series,
  });
  return diagramChart;
}

// Index helpers: 0=static, 1..1+B=up buckets, 1+B..1+2B=down buckets,
// 1+2B=nodes.
function bucketSeriesIndex(direction, bucketIdx) {
  const B = SPEED_BUCKETS.length;
  if (direction === 'up') return 1 + bucketIdx;
  return 1 + B + bucketIdx;
}
function nodesSeriesIndex() {
  return 1 + 2 * SPEED_BUCKETS.length;
}
function staticSeriesIndex() {
  return 0;
}

/// Hub-and-spoke layout: target at the centre, RTUs distributed on
/// concentric rings around it. Up to ~60 nodes per ring.
/// Returns coordinates in the chart's logical 1000×540 space.
function diagramLayout(perSession) {
  const W = 1000;
  const H = 540;
  const cx = W / 2;
  const cy = H / 2;
  const nodes = [{
    id: 'target',
    isTarget: true,
    x: cx, y: cy,
    name: diagramTargetLabel || 'target',
  }];
  const n = perSession.length;
  if (n === 0) return { nodes, cx, cy, W, H };
  const baseR = 170;
  const ringSize = 60;
  for (let i = 0; i < n; i++) {
    const ring = Math.floor(i / ringSize);
    const inRing = Math.min(ringSize, n - ring * ringSize);
    const idxInRing = i - ring * ringSize;
    const ringR = baseR + ring * 50;
    const angle = (idxInRing / inRing) * Math.PI * 2 - Math.PI / 2;
    const x = cx + Math.cos(angle) * ringR;
    const y = cy + Math.sin(angle) * ringR;
    const ps = perSession[i];
    nodes.push({
      id: 's' + i,
      x, y,
      name: ps.src_ip || ('rtu ' + i),
      state: ps.state,
      sent: ps.sent,
      received: ps.received,
    });
  }
  return { nodes, cx, cy, W, H };
}

function nodeStyleForState(state, isTarget) {
  if (isTarget) {
    return { color: '#0e0e0c', borderColor: '#c15a2b', borderWidth: 3 };
  }
  switch (state) {
    case 'active':
    case 'connected':
      return { color: '#c15a2b', borderColor: '#0e0e0c', borderWidth: 1 };
    case 'listening':
      return { color: '#1f4a78', borderColor: '#0e0e0c', borderWidth: 1 };
    case 'completed':
      return { color: '#5a7a3f', borderColor: '#0e0e0c', borderWidth: 1 };
    case 'failed':
      return { color: '#922626', borderColor: '#0e0e0c', borderWidth: 1 };
    case 'pending':
    default:
      return { color: '#cfcfca', borderColor: '#6a6a65', borderWidth: 1 };
  }
}

// Per-session activity state. The fix is twofold:
//   1. Long grace window (30 s). The captured iec104.pcap has multi-
//      second gaps in the master→slave direction; without a long
//      grace the diagram would silence those quiet stretches even
//      though the session is still alive.
//   2. Sticky bucket (BUCKET_STICKY_MS = 1500 ms). Once a direction
//      lands in a bucket, it stays there for at least 1.5 s before
//      switching. This stops the line from flickering between
//      different `lines` series as instant pps oscillates above and
//      below bucket thresholds tick-to-tick.
//   3. Floor: while a session is in `active`/`connected` state we
//      treat the effective rate as MIN 1 pps (slowest bucket) so the
//      line is drawn continuously even between bursts.
const SESSION_GRACE_MS = 30000;
const BUCKET_STICKY_MS = 1500;
const sessionGrace = new Map(); // key: session_idx → state object

function ensureGraceEntry(idx) {
  let entry = sessionGrace.get(idx);
  if (!entry) {
    entry = {
      lastUpAt: 0, lastUpPps: 0,
      lastDownAt: 0, lastDownPps: 0,
      upBucket: -1, upBucketAt: 0,
      downBucket: -1, downBucketAt: 0,
    };
    sessionGrace.set(idx, entry);
  }
  return entry;
}

function gracePps(idx, dir, currentPps) {
  const now = performance.now();
  const entry = ensureGraceEntry(idx);
  if (currentPps > 0) {
    if (dir === 'up') { entry.lastUpAt = now; entry.lastUpPps = currentPps; }
    else              { entry.lastDownAt = now; entry.lastDownPps = currentPps; }
    return currentPps;
  }
  const lastAt  = dir === 'up' ? entry.lastUpAt  : entry.lastDownAt;
  const lastPps = dir === 'up' ? entry.lastUpPps : entry.lastDownPps;
  if (lastAt > 0 && now - lastAt < SESSION_GRACE_MS) {
    return lastPps;
  }
  return 0;
}

/// Sticky-bucket selector. Picks `pickSpeedBucket(pps)` but won't
/// change the previous choice within BUCKET_STICKY_MS. This stops
/// the line from migrating between series on every tick when the
/// instantaneous pps oscillates around a bucket threshold.
function stickyBucket(idx, dir, pps) {
  const now = performance.now();
  const entry = ensureGraceEntry(idx);
  const desired = pickSpeedBucket(pps);
  const lastBucket = dir === 'up' ? entry.upBucket : entry.downBucket;
  const lastAt     = dir === 'up' ? entry.upBucketAt : entry.downBucketAt;
  // Allow an immediate move if there was no previous bucket, or if
  // the sticky window has elapsed, or if we're moving to "off"
  // (-1 → drop the line, no animation churn to worry about).
  if (lastBucket < 0 || desired < 0 || now - lastAt >= BUCKET_STICKY_MS) {
    if (dir === 'up') { entry.upBucket = desired;   entry.upBucketAt = now; }
    else              { entry.downBucket = desired; entry.downBucketAt = now; }
    return desired;
  }
  return lastBucket;
}

function clearSessionGrace(idx) {
  sessionGrace.delete(idx);
}

function renderDiagramFrame(frame) {
  const chart = ensureDiagramChart();
  if (!chart) return;
  diagramTargetLabel = frame.target || diagramTargetLabel;
  const sessions = frame.per_session || [];
  const layout = diagramLayout(sessions);

  // Reset grace state for any session that has reached a terminal
  // state — we don't want the diagram to keep animating ghost flows
  // for a completed/failed session.
  for (let i = 0; i < sessions.length; i++) {
    const s = sessions[i].state;
    if (s === 'completed' || s === 'failed' || s === 'pending') {
      clearSessionGrace(i);
    }
  }

  const sessionCount = layout.nodes.length - 1;
  const nodeBaseSize = sessionCount <= 4 ? 28 : sessionCount <= 30 ? 18 : 12;

  // ---------- nodes ----------
  const nodeData = layout.nodes.map(n => {
    const style = nodeStyleForState(n.state, !!n.isTarget);
    const isTarget = !!n.isTarget;
    return {
      id: n.id,
      name: n.name,
      value: [n.x, n.y],
      symbolSize: isTarget ? 38 : nodeBaseSize,
      itemStyle: {
        color: style.color,
        borderColor: style.borderColor,
        borderWidth: style.borderWidth,
      },
      label: {
        show: true,
        position: isTarget ? 'inside' : 'right',
        color: isTarget ? '#faf7f1' : '#0e0e0c',
        fontFamily: 'ui-monospace, monospace',
        fontSize: isTarget ? 12 : 10,
        fontWeight: isTarget ? 600 : 500,
        formatter: isTarget ? 'TARGET' : '{b}',
      },
    };
  });

  // ---------- static spokes ----------
  const targetCoord = [layout.cx, layout.cy];
  const staticLines = [];
  for (const n of layout.nodes) {
    if (n.isTarget) continue;
    staticLines.push({ coords: [[n.x, n.y], targetCoord] });
  }

  // ---------- animated streams (per-session pps → bucket) ----------
  // Build empty bucket arrays.
  const upBuckets = SPEED_BUCKETS.map(() => []);
  const downBuckets = SPEED_BUCKETS.map(() => []);

  // Helper: compute two parallel sets of endpoints for a node↔target
  // line, offset perpendicular to the chord so up- and downlinks have
  // visually distinct tracks the particles can travel without
  // colliding.
  const PERP_OFFSET = 12; // logical units in the 1000×540 grid
  function parallelEndpoints(node) {
    const dx = targetCoord[0] - node.x;
    const dy = targetCoord[1] - node.y;
    const len = Math.max(1, Math.hypot(dx, dy));
    // Perpendicular unit vector.
    const px = -dy / len * PERP_OFFSET;
    const py =  dx / len * PERP_OFFSET;
    return {
      up:   [[node.x + px, node.y + py], [targetCoord[0] + px, targetCoord[1] + py]],
      down: [[targetCoord[0] - px, targetCoord[1] - py], [node.x - px, node.y - py]],
    };
  }

  // Sort sessions by combined pps descending so the busiest get
  // animated first when we hit the cap.
  const ranked = [];
  for (let i = 0; i < sessions.length; i++) {
    const ps = sessions[i];
    const node = layout.nodes[i + 1]; // +1 because target is index 0
    if (!node) continue;
    const totalPps = (ps.pps_sent || 0) + (ps.pps_recv || 0);
    ranked.push({ idx: i, ps, node, totalPps });
  }
  ranked.sort((a, b) => b.totalPps - a.totalPps);

  let animatedCount = 0;
  let truncatedSessions = 0;
  for (const r of ranked) {
    const ps = r.ps;
    const node = r.node;
    const isAlive = ps.state === 'active' || ps.state === 'connected';
    // Effective pps. Grace keeps the last-seen rate alive for 30 s
    // after activity stops. While the session is still in
    // active/connected state we apply a floor of 1 pps so the line
    // never blanks even during multi-second pcap gaps.
    let upPps = gracePps(r.idx, 'up', ps.pps_sent || 0);
    let downPps = gracePps(r.idx, 'down', ps.pps_recv || 0);
    if (isAlive) {
      if (upPps === 0) upPps = 1;
      if (downPps === 0) downPps = 1;
    }
    // Sticky bucket: once a direction lands in a bucket it stays
    // there for at least 1.5 s, which kills the every-tick flicker
    // from instant pps bouncing across thresholds.
    const upB = stickyBucket(r.idx, 'up', upPps);
    const downB = stickyBucket(r.idx, 'down', downPps);

    const need = (upB >= 0 ? 1 : 0) + (downB >= 0 ? 1 : 0);
    if (need === 0) continue;
    if (animatedCount + need > MAX_ANIMATED_STREAMS) {
      truncatedSessions++;
      continue;
    }
    const ep = parallelEndpoints(node);
    if (upB >= 0) {
      upBuckets[upB].push({ coords: ep.up });
      animatedCount++;
    }
    if (downB >= 0) {
      downBuckets[downB].push({ coords: ep.down });
      animatedCount++;
    }
  }

  // ---------- assemble setOption series payloads ----------
  // We must include EVERY series in the same order as ensureDiagramChart
  // built them, so ECharts maps payloads to the right slots.
  const series = [];
  series.push({ data: staticLines });
  for (let bi = 0; bi < SPEED_BUCKETS.length; bi++) {
    series.push({ data: upBuckets[bi] });
  }
  for (let bi = 0; bi < SPEED_BUCKETS.length; bi++) {
    series.push({ data: downBuckets[bi] });
  }
  series.push({ data: nodeData, links: [] });

  chart.setOption({ series });

  // Stash the truncation count + animation total so renderDiagramStats
  // can surface them in the meta panel.
  diagramStatsExtras = {
    animated: animatedCount,
    truncated: truncatedSessions,
    total_sessions: sessions.length,
  };
}

let diagramStatsExtras = { animated: 0, truncated: 0, total_sessions: 0 };

function diagramFmtCount(n) {
  if (n == null) return '—';
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'G';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return n.toString();
}

function renderDiagramStats(frame) {
  const stats = el('diagram-stats');
  if (!stats) return;
  const activeCount = (frame.per_session || []).filter(p =>
    p.state === 'active' || p.state === 'connected').length;
  const totalSessions = (frame.per_session || []).length;
  const truncated = diagramStatsExtras.truncated || 0;
  const animated = diagramStatsExtras.animated || 0;
  const truncMarkup = truncated > 0
    ? ` <span class="muted" style="font-size:10px">${truncated} HIDDEN</span>`
    : '';
  const streamColor = truncated > 0 ? 'warn' : 'ok';
  stats.innerHTML = `
    <div class="stat"><span class="k">RUN</span><span class="v">#${frame.run_id}</span></div>
    <div class="stat"><span class="k">MODE</span><span class="v">${esc(frame.role || frame.mode || 'raw')}</span></div>
    <div class="stat"><span class="k">SENT</span><span class="v accent">${diagramFmtCount(frame.sent || 0)}</span></div>
    <div class="stat"><span class="k">UPLINK pps</span><span class="v accent">${diagramFmtCount(frame.pps_sent || 0)}</span></div>
    <div class="stat"><span class="k">DOWNLINK pps</span><span class="v blue">${diagramFmtCount(frame.pps_recv || 0)}</span></div>
    <div class="stat"><span class="k">ACTIVE / STREAMS</span><span class="v ${streamColor}">${activeCount}/${totalSessions} &middot; ${animated}${truncMarkup}</span></div>
  `;
  // Progress bar
  const planned = frame.planned || 0;
  const sent = frame.sent || 0;
  const pct = planned > 0 ? Math.min(100, Math.round((sent / planned) * 100)) : 0;
  el('diagram-pfill').style.width = pct + '%';
  el('diagram-plabel').textContent = `${pct}% · ${diagramFmtCount(sent)} / ${diagramFmtCount(planned)}`;
  el('diagram-meta').textContent = frame.status ? `run #${frame.run_id} · ${frame.status}` : '—';
}

async function pickDiagramRun() {
  // Subscribe the live diagram to the most recent running run, if any.
  const res = await api('/api/runs?status=running');
  if (!res.ok) return null;
  const running = (res.data || [])[0];
  return running ? running.id : null;
}

async function maybeStartDiagram() {
  const id = await pickDiagramRun();
  if (id == null) {
    if (diagramWs) {
      try { diagramWs.close(); } catch {}
      diagramWs = null;
      diagramRunId = null;
    }
    el('diagram-section').style.display = 'none';
    return;
  }
  if (id === diagramRunId && diagramWs && diagramWs.readyState === WebSocket.OPEN) return;
  if (diagramWs) { try { diagramWs.close(); } catch {} }
  diagramRunId = id;
  el('diagram-section').style.display = '';
  // Pull the run's target label for the center node.
  try {
    const r = await api(`/api/runs/${id}`);
    if (r.ok) diagramTargetLabel = r.data.target_ip || 'target';
  } catch {}

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/api/runs/${id}/live`);
  diagramWs = ws;
  // Kick refreshRuns immediately so mountDiagramInRunningRow runs
  // before the first WS frame arrives, ensuring the canvas is
  // already mounted in the running row.
  refreshRuns();
  ws.onmessage = evt => {
    try {
      const frame = JSON.parse(evt.data);
      frame.target = diagramTargetLabel;
      renderDiagramFrame(frame);
      renderDiagramStats(frame);
      // Update the diagram header so the user can see exactly which
      // run the live traffic belongs to (matches the connector arrow
      // pointing at the run row below).
      const head = document.querySelector('#diagram-section .diagram-head h3');
      if (head) head.textContent = `LIVE TRAFFIC · RUN #${frame.run_id}`;
      if (frame.status && frame.status !== 'running') {
        // Final tick — keep the diagram visible for a moment then hide.
        setTimeout(() => {
          if (diagramRunId === frame.run_id) {
            el('diagram-section').style.display = 'none';
            diagramRunId = null;
            try { ws.close(); } catch {}
          }
        }, 4000);
      }
    } catch {}
  };
  ws.onclose = () => {
    if (diagramWs === ws) diagramWs = null;
  };
  ws.onerror = () => {
    if (diagramWs === ws) diagramWs = null;
  };
}

function toggleDiagramFullscreen() {
  const overlay = el('diagram-overlay');
  const card = el('diagram-card');
  const mount = el('diagram-overlay-mount');

  // Dispose the chart BEFORE moving the canvas. ECharts has an
  // internal requestAnimationFrame loop driving the effect particles
  // and it crashes if the canvas has 0×0 dims at any point during
  // the move. Tearing the chart down stops that loop; the next WS
  // frame re-initialises it on the now-correctly-sized canvas.
  if (diagramChart) {
    try { diagramChart.dispose(); } catch {}
    diagramChart = null;
  }

  if (!diagramFullscreen) {
    diagramFs0Parent = card.parentNode;
    mount.appendChild(card);
    overlay.style.display = '';
    diagramFullscreen = true;
  } else {
    diagramFs0Parent.appendChild(card);
    overlay.style.display = 'none';
    diagramFullscreen = false;
  }

  // The next renderDiagramFrame from the WS tick will call
  // ensureDiagramChart which inits a fresh ECharts instance on the
  // now-correctly-sized canvas. No manual resize needed.
}

window.addEventListener('resize', () => {
  if (!diagramChart) return;
  const dom = diagramChart.getDom();
  if (!dom || dom.clientWidth <= 0 || dom.clientHeight <= 0) return;
  diagramChart.resize();
});

// Periodically check whether a run is running and auto-start the
// diagram subscription. Polls /api/runs every 2s while the diagram is
// idle, drops out once a WS is connected.
setInterval(() => { maybeStartDiagram(); }, 2000);
