// 40-analysis.js — post-run fidelity analysis view
// Spliced into the served page by crates/webui/build.rs (classic script,
// shared global scope with the other ui/*.js files, loaded in file-name order).

// =========================================================================
//  analysis
// =========================================================================
let analysisFile = null;
let analysisReport = null;

const anDz = el('an-dropzone');
anDz.addEventListener('dragover', e => { e.preventDefault(); anDz.classList.add('drag'); });
anDz.addEventListener('dragleave', () => anDz.classList.remove('drag'));
anDz.addEventListener('drop', e => {
  e.preventDefault();
  anDz.classList.remove('drag');
  if (e.dataTransfer.files.length) setAnalysisFile(e.dataTransfer.files[0]);
});
el('an-file').addEventListener('change', e => {
  if (e.target.files.length) setAnalysisFile(e.target.files[0]);
});

function setAnalysisFile(f) {
  analysisFile = f;
  const st = el('an-upload-status');
  st.style.display = 'block';
  st.textContent = `${f.name} · ${(f.size/1024).toFixed(1)} kB`;
  st.style.color = 'var(--ok)';
  el('an-run-btn').disabled = false;
}

async function runAnalysis() {
  if (!analysisFile) return;
  const mode = document.querySelector('input[name="an-mode"]:checked')?.value || 'generic';
  const msg = el('an-msg');
  const btn = el('an-run-btn');
  btn.disabled = true;
  msg.textContent = 'analyzing…';
  msg.style.color = 'var(--dim)';

  const fd = new FormData();
  fd.append('file', analysisFile);
  fd.append('mode', mode);
  const tolRaw = parseFloat(el('an-cp56-tol')?.value);
  if (Number.isFinite(tolRaw) && tolRaw >= 0) {
    fd.append('cp56_tolerance_ms', String(tolRaw));
  }
  try {
    const r = await fetch('/api/analyze', { method: 'POST', body: fd });
    const text = await r.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { error: text }; }
    if (!r.ok) {
      msg.textContent = data.error || 'error';
      msg.style.color = 'var(--err)';
      btn.disabled = false;
      return;
    }
    analysisReport = data;
    renderAnalysis(data);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = el('an-download-json');
    a.href = url;
    a.download = `analysis_run${data.run_id}_${mode}.json`;
    a.style.display = 'inline';
    msg.textContent = '';
    btn.disabled = false;
  } catch (err) {
    msg.textContent = err.message || String(err);
    msg.style.color = 'var(--err)';
    btn.disabled = false;
  }
}

// Track ECharts instances rendered into the analysis card so we can
// dispose them on the next render and resize them on window resize.
// Exposed globally as `trackAnalysisChart` so IIFE-scoped per-protocol
// renderers (see crates/proto_*/static/*.js) can register their charts.
let _anCharts = [];
function _resetAnalysisCharts() {
  for (const c of _anCharts) { try { c.dispose(); } catch (_) {} }
  _anCharts = [];
}
window.trackAnalysisChart = (c) => { _anCharts.push(c); };
window.addEventListener('resize', () => {
  if (_anCharts.length === 0) return;
  if (window._anResizeT) clearTimeout(window._anResizeT);
  window._anResizeT = setTimeout(() => {
    for (const c of _anCharts) { try { c.resize(); } catch (_) {} }
  }, 150);
});

// NOTE: the IEC 104-specific analyzer renderers (type-id histograms,
// CP56 drift scatter/histogram/top-N, inter-frame gap comparison)
// moved to `crates/proto_iec104/static/iec104_ui.js` as part of step
// 6 of the multi-protocol refactor. They're spliced into this page
// at build time by `crates/webui/build.rs` and register themselves
// on `window.PROTOCOL_RENDERERS.iec104`. The dispatch happens in
// `renderSlaveDetail` / `initSlaveCharts` below.


// Read a CSS custom property from :root; safe fallback on older browsers.
function getCssVar(name) {
  try {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  } catch (_) { return ''; }
}

function slaveSlug(ip) {
  return String(ip).replace(/[^A-Za-z0-9]/g, '-');
}

function renderFleetHeader(r) {
  const f = r.fleet || {};
  let h = `<div class="an-summary">`;
  h += `  <div><span class="an-verdict ${esc(r.verdict)}">${esc(r.verdict.replace(/_/g,' '))}</span>`;
  h += `    <span class="an-score" style="margin-left:14px">${r.score_pct.toFixed(1)}%</span></div>`;
  h += `  <div class="reason">${esc(r.verdict_reason)}</div>`;
  h += `</div>`;
  h += `<div class="an-fleet-strip">`;
  h += `<span class="an-bucket"><b>${f.slave_count||0}</b> total</span>`;
  h += `<span class="an-bucket ok"><b>${f.fully_correct||0}</b> all-correct</span>`;
  h += `<span class="an-bucket warn"><b>${f.partial||0}</b> partial</span>`;
  h += `<span class="an-bucket bad"><b>${f.failed||0}</b> failed</span>`;
  h += `<span class="an-bucket muted"><b>${f.not_attempted||0}</b> silent</span>`;
  h += `</div>`;
  if (f.best || f.worst) {
    h += `<div class="an-fleet-extremes">`;
    if (f.worst) h += `<span>worst: <code>${esc(f.worst.slave_ip)}</code> @ <b>${f.worst.score_pct.toFixed(1)}%</b></span>`;
    if (f.best)  h += `<span>best: <code>${esc(f.best.slave_ip)}</code> @ <b>${f.best.score_pct.toFixed(1)}%</b></span>`;
    h += `</div>`;
  }
  return h;
}

function renderRunContext(r) {
  let h = `<div class="an-kv">`;
  h += `<div class="k">run</div><div class="v">#${r.run_id} · ${esc(r.role)} mode · ${esc(r.mode)} analysis</div>`;
  h += `<div class="k">source pcap</div><div class="v">${esc(r.original_pcap)}</div>`;
  h += `<div class="k">captured size</div><div class="v">${fmtBytes(r.captured_size_bytes)} · ${r.captured_total_packets.toLocaleString()} total pkts</div>`;
  if (r.master_ip_mapping) {
    const m = r.master_ip_mapping;
    let v = '';
    if (m.captured) v += `captured: <code>${esc(m.captured)}</code>`;
    if (m.live) v += (v ? ' · ' : '') + `live: <code>${esc(m.live)}</code>`;
    if (m.renamed) v += ` <span class="warn" title="The master IP differs between source and live capture. Per-slave matching anchors on slave IP, so this is informational unless replay-time rewriting is needed.">(renamed)</span>`;
    h += `<div class="k">master ip</div><div class="v">${v || '—'}</div>`;
  }
  h += `</div>`;
  return h;
}

function renderSlaveTable(r) {
  const slaves = r.slaves || [];
  if (slaves.length === 0) {
    return `<div class="muted" style="padding:8px 0">no slaves to report</div>`;
  }
  let h = `<div class="an-h">SLAVES (${slaves.length}) · click a row to expand</div>`;
  h += `<div class="an-slave-table">`;
  h += `<div class="an-slave-row an-slave-head">`;
  h += `<span></span><span>slave</span><span>packets</span><span>delivered</span><span>handshake</span><span>score</span><span>verdict</span>`;
  h += `</div>`;
  for (const s of slaves) {
    const slug = slaveSlug(s.slave_ip);
    const scoreCls = s.score_pct >= 99.999 ? 'ok' : (s.score_pct === 0 ? 'bad' : 'warn');
    const handshakeCls = s.startdt_handshake_ok ? 'ok' : (s.packets > 0 ? 'bad' : 'muted');
    const handshakeText = s.startdt_handshake_ok ? '✓' : (s.packets > 0 ? '✗' : '—');
    const delivOk = s.delivered_iframes === s.expected_iframes && s.expected_iframes > 0;
    const delivCls = delivOk ? 'ok' : (s.delivered_iframes === 0 ? 'bad' : 'warn');
    h += `<details class="an-slave-row" data-slave-ip="${esc(s.slave_ip)}" data-slug="${slug}">`;
    h += `<summary class="an-slave-sum">`;
    h += `<span class="an-tri">▸</span>`;
    h += `<span><code>${esc(s.slave_ip)}</code></span>`;
    h += `<span>${s.packets.toLocaleString()}</span>`;
    h += `<span class="${delivCls}">${s.delivered_iframes}/${s.expected_iframes}</span>`;
    h += `<span class="${handshakeCls}" style="text-align:center">${handshakeText}</span>`;
    h += `<span class="${scoreCls}"><b>${s.score_pct.toFixed(1)}%</b></span>`;
    h += `<span class="an-verdict ${esc(s.verdict)}">${esc(s.verdict.replace(/_/g,' '))}</span>`;
    h += `</summary>`;
    h += `<div class="an-slave-detail">`;
    const d = (r.details_by_ip || {})[s.slave_ip];
    if (d) {
      h += `<div class="muted" style="font-family:var(--mono);font-size:11px;margin-bottom:8px">${esc(s.verdict_reason || '')}</div>`;
      h += renderSlaveDetail(r.protocol, s.slave_ip, d);
    } else {
      h += `<div class="muted">no detail available for ${esc(s.slave_ip)}</div>`;
    }
    h += `</div>`;
    h += `</details>`;
  }
  h += `</div>`;
  return h;
}

function setupSlaveDetailExpand(r) {
  const out = el('an-result');
  out.querySelectorAll('details.an-slave-row').forEach(node => {
    node.addEventListener('toggle', () => {
      if (!node.open || node.dataset.chartsInit === '1') return;
      node.dataset.chartsInit = '1';
      const ip = node.dataset.slaveIp;
      const detail = (r.details_by_ip || {})[ip];
      if (!detail) return;
      const renderer = (window.PROTOCOL_RENDERERS || {})[r.protocol];
      if (renderer && typeof renderer.initSlaveCharts === 'function') {
        renderer.initSlaveCharts(node.dataset.slug, detail);
      }
    });
  });
}

// Generic fleet-timeline chart block. `key` is used both as DOM id
// suffix and as a lookup field on the report.
function renderFleetTimelineChartBlock(tl, opts) {
  if (!tl || !tl.samples || tl.samples.length === 0) return '';
  const iters = (tl.iteration_starts_ms || []).length;
  const iterNote = iters > 1
    ? ` &middot; ${iters} loop iterations annotated`
    : (iters === 1 ? ` &middot; single run` : '');
  const decNote = tl.decimated
    ? ` &middot; decimated from ${tl.total_samples.toLocaleString()} samples`
    : ` &middot; ${tl.total_samples.toLocaleString()} samples`;
  let h = `<div class="an-h">${opts.heading}</div>`;
  h += `<div class="an-chart-caption">${opts.caption}${iterNote}${decNote}</div>`;
  h += `<div class="an-chart-axes">${opts.axes}</div>`;
  h += `<div class="an-chart-axes" style="color:var(--ink-2);font-style:italic">${opts.legend}</div>`;
  h += `<div id="an-${opts.key}-chart" class="an-chart"></div>`;
  h += `<div id="an-${opts.key}-stats" class="an-chart-stats"></div>`;
  return h;
}

function renderFleetDriftChart(r) {
  return renderFleetTimelineChartBlock(r.fleet_drift_timeline, {
    key: 'fleet-drift',
    heading: 'FLEET CP56 DRIFT &middot; EVERY SAMPLE FROM EVERY SLAVE OVER TIME',
    caption: 'each dot is one CP56 sample. lines overlay per-time-bucket aggregates across the whole fleet',
    axes: 'X: wall-clock seconds since capture start &middot; Y: signed drift (ms)',
    legend: 'orange = mean per time bucket (the trend line — flat = constant offset / clock skew, slope = cumulative drift). green dashed = p95 upper bound, red dashed = p05 lower bound (envelope of variance per bucket).',
  });
}

function renderFleetPacingChart(r) {
  return renderFleetTimelineChartBlock(r.fleet_pacing_timeline, {
    key: 'fleet-pacing',
    heading: 'FLEET PACING DRIFT &middot; EVERY I-FRAME FROM EVERY SLAVE OVER TIME',
    caption: 'each dot is one I-frame, plotted at how many ms later the live replay sent it vs. the original capture pace. lines overlay per-time-bucket aggregates across the whole fleet',
    axes: 'X: wall-clock seconds since capture start &middot; Y: pacing drift (ms, +ve = late)',
    legend: 'orange = mean per time bucket. flat near zero = pacing held perfectly; upward slope = falling behind. green dashed = p95 (the slowest 5% of frames in each bucket), red dashed = p05 (the earliest 5%). step-down at iteration markers = each loop restarts from zero.',
  });
}

function initFleetTimelineChart(tl, key) {
  if (!tl || !tl.samples || tl.samples.length === 0) return;
  const node = document.getElementById('an-' + key + '-chart');
  if (!node) return;
  const chart = echarts.init(node, null, { renderer: 'canvas' });
  // Convert wall_ms → seconds for the axis label readability.
  const data = tl.samples.map(s => [s[0] / 1000, s[1]]);

  // Bucket the samples into ~100 time bins and compute mean / p05 / p95
  // per bin. The mean line is the main "is this drifting?" signal —
  // a flat line means the offset is constant (e.g. clock skew), a
  // slope or curve means cumulative drift over the run.
  const N_BINS = 100;
  let tMin = Infinity, tMax = -Infinity;
  for (const s of data) { if (s[0] < tMin) tMin = s[0]; if (s[0] > tMax) tMax = s[0]; }
  const binWidth = Math.max((tMax - tMin) / N_BINS, 1e-9);
  const bins = Array.from({ length: N_BINS }, () => []);
  for (const s of data) {
    let bi = Math.floor((s[0] - tMin) / binWidth);
    if (bi >= N_BINS) bi = N_BINS - 1;
    if (bi < 0) bi = 0;
    bins[bi].push(s[1]);
  }
  const meanLine = [];
  const p05Line = [];
  const p95Line = [];
  for (let i = 0; i < N_BINS; i++) {
    const arr = bins[i];
    if (arr.length === 0) continue;
    arr.sort((a, b) => a - b);
    const tCenter = tMin + (i + 0.5) * binWidth;
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    const p05 = arr[Math.floor(arr.length * 0.05)];
    const p95 = arr[Math.min(arr.length - 1, Math.floor(arr.length * 0.95))];
    meanLine.push([tCenter, mean]);
    p05Line.push([tCenter, p05]);
    p95Line.push([tCenter, p95]);
  }
  const drift_first = meanLine.length ? meanLine[0][1] : 0;
  const drift_last  = meanLine.length ? meanLine[meanLine.length - 1][1] : 0;
  const cumulative_change = drift_last - drift_first;

  // Iteration-boundary markers (only when > 1 detected).
  const iters = tl.iteration_starts_ms || [];
  const markLines = iters.length > 1 ? {
    silent: true,
    symbol: ['none', 'none'],
    lineStyle: { type: 'dashed', color: '#888', width: 1 },
    label: { color: '#888', fontFamily: 'var(--mono)', fontSize: 10, formatter: p => p.data.label },
    data: iters.map((ms, i) => ({
      xAxis: ms / 1000,
      label: { formatter: `iter ${i + 1}`, position: 'insideStartTop' }
    })),
  } : undefined;

  // Binary-search the nearest Y in a sorted [[x,y],...] series.
  const nearestY = (arr, t) => {
    if (!arr || arr.length === 0) return null;
    let lo = 0, hi = arr.length - 1;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (arr[mid][0] < t) lo = mid + 1; else hi = mid;
    }
    if (lo > 0 && Math.abs(arr[lo - 1][0] - t) < Math.abs(arr[lo][0] - t)) return arr[lo - 1][1];
    return arr[lo][1];
  };

  // Tooltip formatter that always shows every series' value at the
  // cursor X — even when the underlying bucketed line has no point
  // exactly there (axis-trigger alone would silently drop those).
  const tooltipFmt = (params) => {
    if (!params || params.length === 0) return '';
    const t = (params[0].axisValue !== undefined) ? params[0].axisValue : params[0].value[0];
    // Pull scatter sample from ECharts' params (it has it).
    const scatterEntry = params.find(p => p.seriesType === 'scatter');
    // Manual nearest-bucket lookup for the line series — they only
    // carry ~100 points so axis-trigger won't normally see them.
    const meanY = nearestY(meanLine, t);
    const p05Y  = nearestY(p05Line,  t);
    const p95Y  = nearestY(p95Line,  t);
    const swatch = (color) => `<span style="display:inline-block;width:10px;height:10px;background:${color};margin-right:6px;border-radius:2px;vertical-align:middle"></span>`;
    const dash = (color) => `<span style="display:inline-block;width:14px;height:0;border-top:1.5px dashed ${color};margin-right:4px;vertical-align:middle"></span>`;
    const solid = (color) => `<span style="display:inline-block;width:14px;height:0;border-top:2.5px solid ${color};margin-right:4px;vertical-align:middle"></span>`;
    let html = `<div style="font-family:var(--mono);font-size:12px;line-height:1.55">`;
    html += `<div style="font-weight:700;margin-bottom:4px">t = ${Number(t).toFixed(2)} s</div>`;
    if (scatterEntry && scatterEntry.value) {
      const y = scatterEntry.value[1];
      html += `<div>${swatch('#4a90e2')}sample: ${Number(y).toFixed(2)} ms</div>`;
    }
    if (meanY !== null) html += `<div>${solid('#d8741a')}mean: <b>${meanY.toFixed(2)} ms</b></div>`;
    if (p95Y !== null)  html += `<div>${dash('#3c8a4a')}p95 (upper):&nbsp; ${p95Y.toFixed(2)} ms</div>`;
    if (p05Y !== null)  html += `<div>${dash('#a4453c')}p05 (lower):&nbsp; ${p05Y.toFixed(2)} ms</div>`;
    html += `</div>`;
    return html;
  };

  chart.setOption({
    grid: { left: 64, right: 24, top: 48, bottom: 48 },
    tooltip: {
      trigger: 'axis',
      axisPointer: {
        type: 'cross',
        snap: true,
        label: {
          backgroundColor: '#333',
          color: '#fff',
          fontSize: 11,
          fontFamily: 'var(--mono)',
          formatter: (p) => {
            // axis label on the cross hair lines.
            const v = (typeof p.value === 'number') ? p.value : Number(p.value);
            const unit = p.axisDimension === 'x' ? 's' : 'ms';
            return `${v.toFixed(2)} ${unit}`;
          },
        },
      },
      backgroundColor: 'rgba(255,255,255,0.97)',
      borderColor: 'var(--rule)',
      borderWidth: 1,
      padding: [8, 12],
      extraCssText: 'box-shadow: 0 2px 8px rgba(0,0,0,0.15);',
      formatter: tooltipFmt,
    },
    legend: {
      top: 6, left: 8,
      textStyle: { fontFamily: 'var(--mono)', fontSize: 11, color: '#444' },
      itemWidth: 18,
      itemHeight: 8,
      itemGap: 14,
      // Names carry the line-style cue because ECharts default
      // legend icons don't render lineStyle.type (dashed vs solid).
      data: ['• samples', '── mean (per-bucket)', '┄┄ p95 upper', '┄┄ p05 lower'],
    },
    xAxis: {
      type: 'value',
      name: 'seconds since capture start',
      nameLocation: 'middle',
      nameGap: 30,
      nameTextStyle: { fontFamily: 'var(--mono)', fontSize: 10, color: '#777' },
    },
    yAxis: {
      type: 'value',
      name: 'ms',
      nameLocation: 'middle',
      nameGap: 48,
      nameTextStyle: { fontFamily: 'var(--mono)', fontSize: 10, color: '#777' },
    },
    dataZoom: [
      { type: 'inside', xAxisIndex: 0 },
      { type: 'inside', yAxisIndex: 0 },
    ],
    toolbox: {
      feature: { dataZoom: { yAxisIndex: 'none' }, restore: {} },
      right: 8,
      top: 6,
    },
    series: [
      {
        name: '• samples',
        type: 'scatter',
        symbolSize: 3,
        itemStyle: { color: '#4a90e2', opacity: 0.35 },
        data,
        large: true,
        largeThreshold: 1000,
        z: 1,
      },
      {
        name: '┄┄ p95 upper',
        type: 'line',
        data: p95Line,
        lineStyle: { color: '#3c8a4a', width: 1.2, type: 'dashed' },
        itemStyle: { color: '#3c8a4a' },
        showSymbol: false,
        smooth: true,
        z: 2,
      },
      {
        name: '┄┄ p05 lower',
        type: 'line',
        data: p05Line,
        lineStyle: { color: '#a4453c', width: 1.2, type: 'dashed' },
        itemStyle: { color: '#a4453c' },
        showSymbol: false,
        smooth: true,
        z: 3,
      },
      {
        name: '── mean (per-bucket)',
        type: 'line',
        data: meanLine,
        lineStyle: { color: '#d8741a', width: 2.5 },
        itemStyle: { color: '#d8741a' },
        showSymbol: false,
        smooth: true,
        markLine: markLines,
        z: 4,
      },
    ],
  });
  _anCharts.push(chart);

  // Stats summary line under the chart. Computed from the same
  // bucketed mean line we already built — no second pass.
  const statsNode = document.getElementById('an-' + key + '-stats');
  if (statsNode && meanLine.length >= 2) {
    const ys = data.map(s => s[1]);
    const ymean = ys.reduce((a, b) => a + b, 0) / ys.length;
    const ymin = Math.min(...ys);
    const ymax = Math.max(...ys);
    const cumStr = `${cumulative_change >= 0 ? '+' : ''}${cumulative_change.toFixed(2)} ms`;
    const cumCls = Math.abs(cumulative_change) < 5 ? 'ok'
                 : Math.abs(cumulative_change) < 50 ? 'warn'
                 : 'bad';
    statsNode.innerHTML =
      `<span><b>cumulative change</b> (last bucket mean − first bucket mean): <span class="${cumCls}">${cumStr}</span></span>` +
      `<span><b>overall mean</b>: ${ymean.toFixed(2)} ms</span>` +
      `<span><b>range</b>: ${ymin.toFixed(2)} ms &rarr; ${ymax.toFixed(2)} ms</span>`;
  }
}

function renderAnalysis(r) {
  _resetAnalysisCharts();
  const out = el('an-result');
  let h = `<div class="an-card">`;
  h += renderFleetHeader(r);
  // Per-protocol fleet-level extras (e.g. IEC 104 GI/CI rollup bars).
  // Optional renderer hook on `PROTOCOL_RENDERERS[proto].renderFleetExtras(r)`.
  const _fleetRenderer = (window.PROTOCOL_RENDERERS || {})[r.protocol];
  if (_fleetRenderer && typeof _fleetRenderer.renderFleetExtras === "function") {
    h += _fleetRenderer.renderFleetExtras(r);
  }
  h += renderFleetPacingChart(r);
  h += renderFleetDriftChart(r);
  h += renderRunContext(r);
  if (r.notes && r.notes.length) {
    h += `<div class="an-h">FLEET NOTES</div>`;
    for (const n of r.notes) h += `<div class="an-note">· ${esc(n)}</div>`;
  }
  h += renderSlaveTable(r);
  h += `</div>`;
  out.innerHTML = h;
  setTimeout(() => {
    initFleetTimelineChart(r.fleet_pacing_timeline, 'fleet-pacing');
    initFleetTimelineChart(r.fleet_drift_timeline,  'fleet-drift');
  }, 0);
  setupSlaveDetailExpand(r);
}

// Per-slave drill-down dispatcher. Looks up
// `window.PROTOCOL_RENDERERS[proto].renderSlaveDetail` and hands off;
// falls back to a minimal generic view (flow info + notes) when the
// selected protocol did not ship a renderer. The actual IEC 104
// renderer lives in `crates/proto_iec104/static/iec104_ui.js`.
function renderSlaveDetail(proto, slaveIp, d) {
  const renderer = (window.PROTOCOL_RENDERERS || {})[proto];
  if (renderer && typeof renderer.renderSlaveDetail === "function") {
    return renderer.renderSlaveDetail(slaveIp, d);
  }
  let h = `<div class="an-note">· no slave-detail renderer registered for protocol <code>${esc(proto || "?")}</code></div>`;
  if (d && d.tcp_flow) {
    h += `<div class="an-kv"><div class="k">tcp flow</div><div class="v">${esc(d.tcp_flow.client)} → ${esc(d.tcp_flow.server)} · ${d.tcp_flow.packets} pkts · <code>${esc(d.tcp_flow.state || "no state")}</code></div></div>`;
  }
  if (d && d.notes && d.notes.length) {
    h += `<div class="an-h">NOTES</div>`;
    for (const n of d.notes) h += `<div class="an-note">· ${esc(n)}</div>`;
  }
  return h;
}

