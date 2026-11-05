// 30-runs.js — runs list, slave rows, detail panel, charts
// Spliced into the served page by crates/webui/build.rs (classic script,
// shared global scope with the other ui/*.js files, loaded in file-name order).


async function startSlave(runId, idx) {
  await api(`/api/runs/${runId}/slaves/${idx}/start`, 'POST');
  refreshRuns();
}

function renderSlaveRow(r, p, idx) {
  const stateColor = {
    pending:    'var(--dim)',
    listening:  'var(--accent)',
    connected:  'var(--blue)',
    active:     'var(--accent)',
    completed:  'var(--ok)',
    failed:     'var(--err)',
  }[p.state] || 'var(--dim)';
  const stateLabel = (p.state || 'pending').toUpperCase();
  // Per-iteration progress: backend resets `sent` to 0 at the top of
  // every iteration, so this fraction tracks the CURRENT iteration only.
  // Clamp to 100% defensively in case a tick races past the reset.
  const frac = p.planned ? Math.min(1.0, p.sent / p.planned) : 0;
  const pct = Math.round(frac * 100);
  const nm = p.src_ip || p.src_mac;
  const rowId = `slave-${r.id}-${idx}`;
  // Iter counter chip: shown only when the run is multi-iteration
  // (iter_total > 1) or unbounded (iter_total === 0 with iter_current > 0).
  let iterChip = '';
  if (p.iter_current > 0 && (p.iter_total === 0 || p.iter_total > 1)) {
    const label = (p.iter_total === 0)
      ? `iter ${p.iter_current} (looping until stopped)`
      : `iter ${p.iter_current} / ${p.iter_total}`;
    iterChip = `<span class="slave-iter" style="font-family:var(--mono);font-size:11px;color:var(--dim);margin-right:8px">${label}</span>`;
  }

  // The IP input and verify button are only editable while PENDING.
  let ipField;
  if (p.state === 'pending') {
    const verifyStatus = (slaveVerifyStatus[`${r.id}/${idx}`] || '').trim();
    ipField = `
      <input class="slave-ip-input" id="${rowId}-ip" type="text" value="${esc(p.listen_ip || '0.0.0.0')}" spellcheck="false"
        onblur="patchSlaveIp(${r.id}, ${idx}, this.value)">
      <span class="slave-port-badge">:${p.listen_port}</span>
      <button class="slave-btn verify" onclick="verifySlaveIp(${r.id}, ${idx})">VERIFY</button>
      <span class="slave-verify" id="${rowId}-verify">${verifyStatus}</span>
    `;
  } else {
    ipField = `<span class="slave-port">${esc(p.listen_ip || '0.0.0.0')}:${p.listen_port}</span>`;
  }

  let right = '';
  if (p.state === 'pending') {
    if (p.cancelled) {
      right = `<span class="slave-count" style="color:var(--err)">cancelled</span>`;
    } else {
      right = `
        <button class="slave-btn start" onclick="startSlave(${r.id}, ${idx})">START LISTENING</button>
        <button class="slave-btn abort" onclick="stopSlave(${r.id}, ${idx})">ABORT</button>
      `;
    }
  } else if (p.state === 'listening') {
    right = `
      <span class="slave-wait">waiting for master…</span>
      <button class="slave-btn abort" onclick="stopSlave(${r.id}, ${idx})">ABORT</button>
    `;
  } else if (p.state === 'connected' || p.state === 'active') {
    right = `
      ${iterChip}<span class="slave-count">${p.sent.toLocaleString()} / ${p.planned.toLocaleString()}</span>
      <button class="slave-btn abort" onclick="stopSlave(${r.id}, ${idx})">STOP</button>
    `;
  } else if (p.state === 'completed') {
    right = `${iterChip}<span class="slave-count" style="color:var(--ok)">${p.sent.toLocaleString()} / ${p.planned.toLocaleString()}</span>`;
  } else if (p.state === 'failed') {
    right = `<span class="slave-count" style="color:var(--err)">failed</span>`;
  }

  let h = `<div class="slave-row">`;
  h += `  <div class="slave-meta">`;
  h += `    <span class="slave-state" style="color:${stateColor}">${stateLabel}</span>`;
  h += `    <span class="slave-rtu">rtu ${esc(nm)}</span>`;
  h += `    <span class="slave-ip-cell">${ipField}</span>`;
  h += `    <span class="slave-right">${right}</span>`;
  h += `  </div>`;
  if (p.state === 'active' || p.state === 'completed') {
    h += `  <div class="slave-bar"><div class="slave-fill ${p.state}" style="width:${pct}%"></div></div>`;
  }
  h += `</div>`;
  return h;
}

async function stopSlave(runId, idx) {
  await api(`/api/runs/${runId}/slaves/${idx}/stop`, 'POST');
  refreshRuns();
}

async function startAllSlaves(runId) {
  const res = await api(`/api/runs/${runId}/slaves/start_all`, 'POST');
  if (res.ok && res.data && typeof res.data.started === 'number') {
    // Optimistic refresh so the user sees the rows flip immediately.
  }
  refreshRuns();
}

async function patchSlaveIp(runId, idx, value) {
  const v = (value || '').trim();
  if (!v) return;
  await api(`/api/runs/${runId}/slaves/${idx}`, 'PATCH', { listen_ip: v });
  // clear the cached verify result for this slave, since the IP changed
  delete slaveVerifyStatus[`${runId}/${idx}`];
}

const slaveVerifyStatus = {};
async function verifySlaveIp(runId, idx) {
  const input = el(`slave-${runId}-${idx}-ip`);
  const statusEl = el(`slave-${runId}-${idx}-verify`);
  const ip = (input?.value || '').trim();
  if (!ip) return;
  // Patch first so the server knows the candidate IP (for consistency).
  await patchSlaveIp(runId, idx, ip);
  statusEl.textContent = 'probing…';
  statusEl.style.color = 'var(--dim)';
  const res = await api('/api/verify-ip', 'POST', { ip });
  const key = `${runId}/${idx}`;
  if (!res.ok) {
    slaveVerifyStatus[key] = 'error';
    statusEl.textContent = res.data.error || 'error';
    statusEl.style.color = 'var(--err)';
    return;
  }
  const d = res.data;
  if (d.error) {
    slaveVerifyStatus[key] = 'error';
    statusEl.textContent = d.error;
    statusEl.style.color = 'var(--err)';
  } else if (d.in_use) {
    const mac = d.mac ? ` (${d.mac})` : '';
    slaveVerifyStatus[key] = `in use${mac}`;
    statusEl.textContent = `in use on ${d.iface}${mac}`;
    statusEl.style.color = 'var(--err)';
  } else if (ip === '0.0.0.0') {
    slaveVerifyStatus[key] = 'any';
    statusEl.textContent = 'any interface';
    statusEl.style.color = 'var(--ok)';
  } else if (d.locally_assigned) {
    slaveVerifyStatus[key] = 'local';
    statusEl.textContent = `already local on ${d.iface}`;
    statusEl.style.color = 'var(--ok)';
  } else {
    slaveVerifyStatus[key] = 'free-alias';
    statusEl.textContent = `free on ${d.iface} — will auto-alias on start`;
    statusEl.style.color = 'var(--ok)';
  }
}

// =========================================================================
//  runs list
// =========================================================================
let currentDetailId = null;

async function refreshRuns() {
  // If the user is actively typing in a text input inside the runs
  // list, skip this tick — rewriting innerHTML would steal focus
  // mid-keystroke. We specifically check for INPUT/TEXTAREA; buttons
  // that happen to hold focus after a click should NOT block re-renders
  // (otherwise clicking START LISTENING would freeze the UI until blur).
  const runsNode = el('runs-list');
  const active = document.activeElement;
  if (runsNode && active && runsNode.contains(active)) {
    const tag = active.tagName;
    const isTextInput =
      (tag === 'INPUT' && (active.type === 'text' || active.type === 'number' || !active.type)) ||
      tag === 'TEXTAREA';
    if (isTextInput) return;
  }
  const res = await api('/api/runs');
  const out = el('runs-list');
  const meta = el('runs-meta');
  if (!res.ok) {
    out.innerHTML = '<div class="err-box">error fetching runs</div>';
    return;
  }
  const runs = res.data || [];
  // /api/runs is a slim summary; fetch the full record for the expanded run.
  if (currentDetailId != null && runs.some(r => r.id === currentDetailId)) {
    const d = await api(`/api/runs/${currentDetailId}`);
    if (d.ok) runDetailCache[currentDetailId] = d.data;
  }
  const running = runs.filter(r => r.status === 'running').length;
  meta.textContent = runs.length ? `${runs.length} total · ${running} running` : '—';
  if (!runs.length) {
    out.innerHTML = '<div class="lib-empty">no runs recorded</div>';
    return;
  }
  let h = '';
  for (const r of runs) {
    const frac = r.planned ? Math.min(1.0, r.sent / r.planned) : (r.report ? 1 : 0);
    const pct = Math.round(frac * 100);
    const cur = r.report ? r.report.total_packets : r.sent;
    const total = r.planned || (r.report ? r.report.total_packets : 0);
    const tgt = esc(r.target_ip);
    const name = `${esc(basename(r.pcap))} <span class="arrow">→</span> ${tgt}`;

    h += `<div class="run ${r.status}">`;
    h += `  <div class="head">`;
    h += `    <span class="num">RUN·${r.id.toString().padStart(4,'0')}</span>`;
    h += `    <span class="title">${name}</span>`;
    h += `    <span class="status ${r.status}">${r.status}</span>`;
    h += `  </div>`;

    const modeLabel = r.mode === 'benchmark' ? 'benchmark' : 'raw';
    h += `  <div class="submeta">`;
    h += `    <span><span class="k">mode</span> ${modeLabel}</span>`;
    h += `    <span><span class="k">speed</span> ${r.speed}×${r.top_speed ? ' top' : ''}</span>`;
    if (r.realtime) h += `    <span><span class="k">sched</span> fifo</span>`;
    h += `  </div>`;

    // main progress bar
    h += `  <div class="pbar ${r.status}">`;
    h += `    <div class="plabel">progress</div>`;
    h += `    <div class="pcount">${pct}% &middot; ${cur.toLocaleString()} / ${(total || 0).toLocaleString()}</div>`;
    h += `    <div class="ptrack"><div class="pfill" style="width:${pct}%"></div></div>`;
    h += `  </div>`;

    // per-source mini bars. Slave-benchmark sessions get a richer row
    // with state indicator + per-slave start button.
    if (r.per_source_progress && r.per_source_progress.length) {
      const isSlave = r.per_source_progress.some(p => p.listen_port > 0);
      if (isSlave) {
        // Fan-out controls for slave-mode. Only meaningful while the
        // run is still running and there are pending (uncancelled)
        // slots left to arm.
        if (r.status === 'running') {
          const pendingLeft = r.per_source_progress.filter(
            p => p.state === 'pending' && !p.cancelled
          ).length;
          if (pendingLeft > 0) {
            h += `<div class="slave-bulk-actions">`;
            h += `  <button class="slave-btn start-all" onclick="startAllSlaves(${r.id})">START ALL (${pendingLeft})</button>`;
            h += `</div>`;
          }
        }
        h += `<div class="slave-list">`;
        for (let i = 0; i < r.per_source_progress.length; i++) {
          h += renderSlaveRow(r, r.per_source_progress[i], i);
        }
        h += `</div>`;
      } else {
        h += `<div class="per-source-list">`;
        for (const p of r.per_source_progress) {
          const sf = p.planned ? (p.sent / p.planned) : 0;
          const spct = Math.round(sf * 100);
          const nm = p.src_ip || ('l2 ' + p.src_mac);
          h += `<div class="per-source-bar ${r.status}">`;
          h += `  <span class="nm">${esc(nm)}</span>`;
          h += `  <div class="mini-track"><div class="mini-fill" style="width:${spct}%"></div></div>`;
          h += `  <span class="cnt">${p.sent.toLocaleString()} / ${p.planned.toLocaleString()}</span>`;
          h += `</div>`;
        }
        h += `</div>`;
      }
    }

    if (r.throughput_history && r.throughput_history.length > 1) {
      const latest = r.throughput_history[r.throughput_history.length - 1] || 0;
      h += `<div class="sparkrow">`;
      h += `  <span class="lbl">THROUGHPUT</span>`;
      h += `  <span>${sparklineSvg(r.throughput_history, r.id)}</span>`;
      h += `  <span class="val">${latest.toLocaleString()} pps</span>`;
      h += `</div>`;
    }

    const actions = [];
    if (r.status === 'running') {
      actions.push(`<button class="stop" onclick="stopRun(${r.id})">STOP</button>`);
    }
    if (r.has_capture) {
      actions.push(`<a href="/api/runs/${r.id}/download" download>DOWNLOAD CAPTURE</a>`);
    }
    actions.push(`<button onclick="toggleDetail(${r.id})">${currentDetailId === r.id ? 'HIDE DETAILS' : 'DETAILS'}</button>`);
    if (r.status !== 'running') {
      actions.push(`<button class="stop" onclick="deleteRun(${r.id})">DELETE</button>`);
    }
    h += `<div class="actions-inline">${actions.join('')}</div>`;

    if (currentDetailId === r.id) {
      h += renderDetail(runDetailCache[r.id] || r);
    }
    h += `</div>`;
  }
  out.innerHTML = h;

  // Just toggle the (stable, never-moved) diagram section's display.
  syncDiagramVisibility();
}

// The diagram section is now a stable sibling of #runs-list — it is
// never moved in the DOM, so refreshRuns()'s innerHTML rewrite of
// the runs list leaves it untouched. JS just toggles its visibility.
function syncDiagramVisibility() {
  const section = el('diagram-section');
  if (!section) return;
  const hasRunning = !!document.querySelector('#runs-list .run.running');
  const wantDisplay = hasRunning ? '' : 'none';
  if (section.style.display !== wantDisplay) {
    section.style.display = wantDisplay;
    // When transitioning from hidden → visible, give the canvas one
    // resize so ECharts picks up the now-real container size.
    if (hasRunning) {
      requestAnimationFrame(() => {
        if (!diagramChart) return;
        const dom = diagramChart.getDom();
        if (dom && dom.clientWidth > 0 && dom.clientHeight > 0) {
          diagramChart.resize();
        }
      });
    }
  }
}

const runDetailCache = {};
function toggleDetail(id) {
  currentDetailId = currentDetailId === id ? null : id;
  refreshRuns();
}

// =========================================================================
//  detail panel
// =========================================================================
function renderDetail(r) {
  let h = `<div class="detail">`;
  if (r.error) {
    h += `<div class="err-box">${esc(r.error)}</div>`;
  }
  h += `<div class="kv">`;
  h += `<div class="k">pcap</div><div class="v">${esc(r.pcap)}</div>`;
  h += `<div class="k">target</div><div class="v">${esc(r.target_ip)}${r.target_mac ? ' &middot; ' + esc(r.target_mac) : ''}</div>`;
  h += `<div class="k">speed</div><div class="v">${r.speed}${r.top_speed ? ' (top)' : ''}${r.realtime ? ' · rt' : ''}</div>`;
  if (r.report) {
    h += `<div class="k">sent</div><div class="v">${r.report.total_packets.toLocaleString()} pkts &middot; ${fmtBytes(r.report.total_bytes)}</div>`;
    h += `<div class="k">errors</div><div class="v">${r.report.total_errors}</div>`;
    if (r.report.capture_path) {
      h += `<div class="k">capture</div><div class="v">${r.report.captured_packets} frames &middot; ${fmtBytes(r.report.captured_bytes)}</div>`;
    }
  }
  if (r.benchmark) {
    const b = r.benchmark;
    h += `<div class="k">sessions</div><div class="v">${(b.per_session || []).length}</div>`;
    h += `<div class="k">messages</div><div class="v">${b.total_messages_sent} sent &middot; ${b.total_messages_received} recv</div>`;
    h += `<div class="k">throughput</div><div class="v">${fmt(b.aggregate_throughput_msgs_per_sec)} msg/s</div>`;
    h += `<div class="k">latency (µs)</div><div class="v">min ${b.aggregate_latency_min_us} &middot; p50 ${b.aggregate_latency_p50_us} &middot; p90 ${b.aggregate_latency_p90_us} &middot; p99 ${b.aggregate_latency_p99_us} &middot; max ${b.aggregate_latency_max_us}</div>`;
  }
  h += `</div>`;

  // raw per-source table
  if (r.report && r.report.per_source && r.report.per_source.length) {
    h += `<h3>per-source timing</h3>`;
    h += `<table class="t"><tr><th>src ip</th><th>mac</th><th>tap</th><th>kind</th><th class="num">sent</th><th class="num">bytes</th><th class="num">elapsed ms</th><th class="num">mean µs</th><th class="num">p99 µs</th></tr>`;
    for (const s of r.report.per_source) {
      h += `<tr>`;
      h += `<td>${esc(s.src_ip || '—')}</td>`;
      h += `<td><code>${esc(s.src_mac)}</code></td>`;
      h += `<td><code>${esc(s.tap)}</code></td>`;
      h += `<td>${esc(s.kind)}</td>`;
      h += `<td class="num">${s.sent}</td>`;
      h += `<td class="num">${fmtBytes(s.bytes)}</td>`;
      h += `<td class="num">${fmt(s.elapsed_ms)}</td>`;
      h += `<td class="num">${fmt(s.mean_jitter_us)}</td>`;
      h += `<td class="num">${fmt(s.p99_jitter_us)}</td>`;
      h += `</tr>`;
    }
    h += `</table>`;
  }

  // benchmark sessions
  if (r.benchmark && r.benchmark.per_session && r.benchmark.per_session.length) {
    h += `<h3>per-session benchmark</h3>`;
    h += `<table class="t"><tr><th>src ip</th><th class="num">sent</th><th class="num">recv</th><th class="num">p50 µs</th><th class="num">p99 µs</th><th class="num">max µs</th><th class="num">msg/s</th><th class="num">stalls</th><th>status</th></tr>`;
    for (const s of r.benchmark.per_session) {
      const status = s.error ? `<span style="color:var(--err)">err</span>` : (s.connected ? '<span style="color:var(--ok)">ok</span>' : 'idle');
      h += `<tr>`;
      h += `<td>${esc(s.src_ip)}</td>`;
      h += `<td class="num">${s.messages_sent}</td>`;
      h += `<td class="num">${s.messages_received}</td>`;
      h += `<td class="num">${s.latency_p50_us}</td>`;
      h += `<td class="num">${s.latency_p99_us}</td>`;
      h += `<td class="num">${s.latency_max_us}</td>`;
      h += `<td class="num">${fmt(s.throughput_msgs_per_sec)}</td>`;
      h += `<td class="num">${s.window_stalls}</td>`;
      h += `<td>${status}</td>`;
      h += `</tr>`;
      if (s.error) {
        h += `<tr><td colspan="9"><div class="err-box">${esc(s.error)}</div></td></tr>`;
      }
    }
    h += `</table>`;

    h += `<h3>latency distribution</h3>`;
    h += latencyChart(`lat-agg-${r.id}`, r.benchmark.aggregate_latency_histogram, r.benchmark.aggregate_latency_p50_us, r.benchmark.aggregate_latency_p99_us);
  }

  // gap histogram
  if (r.has_capture) {
    h += `<h3>inter-packet gap distribution</h3>`;
    const cached = gapCache[r.id];
    if (cached && cached !== 'loading') {
      h += gapChart(`gap-${r.id}`, cached);
    } else {
      h += `<div class="chart-wrap" id="gap-${r.id}"><div class="muted" style="font-family:var(--mono);font-size:11px">loading…</div></div>`;
      fetchGapHistogram(r.id);
    }
  }
  h += `</div>`;
  return h;
}

// =========================================================================
//  charts
// =========================================================================

// sparkline — smooth SVG area chart for throughput history
function sparklineSvg(samples, uid) {
  const w = 600, h = 44, pad = 2;
  if (!samples || samples.length < 2) return '';
  const max = Math.max(1, ...samples);
  const step = (w - pad*2) / (samples.length - 1);
  const pts = samples.map((v, i) => {
    const x = pad + i * step;
    const y = h - pad - (v / max) * (h - pad*2);
    return [x, y];
  });
  const path = pts.map((p, i) => (i === 0 ? 'M' : 'L') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
  const area = path + ` L ${w - pad} ${h - pad} L ${pad} ${h - pad} Z`;
  return `
    <svg class="chart-svg" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="height:44px;width:100%">
      <path d="${area}" fill="var(--accent-soft)" />
      <path d="${path}" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>
    </svg>
  `;
}

// gap histogram — two overlaid series with interactive bars
function gapChart(uid, data) {
  const n = 20;
  const w = 680, h = 220;
  const padL = 44, padR = 20, padT = 16, padB = 38;
  const innerW = w - padL - padR;
  const innerH = h - padT - padB;
  const max = Math.max(1, ...data.original, ...data.captured);
  const bw = innerW / n;

  // log bucket boundaries for tooltips (1 µs → 10 s)
  const logMin = 3, logMax = 10; // 10^3 ns = 1µs, 10^10 ns = 10s
  const bucketLabel = i => {
    const lo = Math.pow(10, logMin + (i / n) * (logMax - logMin));
    const hi = Math.pow(10, logMin + ((i+1) / n) * (logMax - logMin));
    return nsRange(lo, hi);
  };

  let svg = `<svg class="chart-svg" viewBox="0 0 ${w} ${h}" style="height:220px">`;
  // y-axis gridlines (5)
  for (let g = 0; g <= 5; g++) {
    const y = padT + (g / 5) * innerH;
    const v = Math.round(max * (1 - g / 5));
    svg += `<line x1="${padL}" y1="${y}" x2="${w-padR}" y2="${y}" stroke="var(--rule-soft)" stroke-width="1"/>`;
    svg += `<text x="${padL-6}" y="${y+3}" font-size="9" text-anchor="end" fill="var(--dim)" font-family="var(--mono)">${v}</text>`;
  }
  // bars
  for (let i = 0; i < n; i++) {
    const x = padL + i * bw;
    const origH = (data.original[i] / max) * innerH;
    const capH = (data.captured[i] / max) * innerH;
    // background hover zone
    svg += `<rect class="bucket-bg" x="${x}" y="${padT}" width="${bw}" height="${innerH}" fill="transparent" data-idx="${i}" data-uid="${uid}"/>`;
    // original (ink) bar
    svg += `<rect x="${x+2}" y="${padT + innerH - origH}" width="${bw-4}" height="${origH}" fill="var(--ink)" opacity="0.78"/>`;
    // captured (accent) bar slightly narrower, offset
    svg += `<rect x="${x+5}" y="${padT + innerH - capH}" width="${bw-10}" height="${capH}" fill="var(--accent)" opacity="0.85"/>`;
  }
  // x axis
  svg += `<line x1="${padL}" y1="${padT + innerH}" x2="${w-padR}" y2="${padT + innerH}" stroke="var(--ink)" stroke-width="1"/>`;
  const xTicks = [
    { frac: 0,    label: '1 µs' },
    { frac: 3/7,  label: '1 ms' },
    { frac: 4/7,  label: '10 ms' },
    { frac: 6/7,  label: '1 s' },
    { frac: 1,    label: '10 s' },
  ];
  for (const t of xTicks) {
    const x = padL + t.frac * innerW;
    svg += `<line x1="${x}" y1="${padT + innerH}" x2="${x}" y2="${padT + innerH + 4}" stroke="var(--dim)" stroke-width="1"/>`;
    const anchor = t.frac === 0 ? 'start' : (t.frac === 1 ? 'end' : 'middle');
    svg += `<text x="${x}" y="${padT + innerH + 16}" font-size="10" fill="var(--dim)" text-anchor="${anchor}" font-family="var(--mono)">${t.label}</text>`;
  }
  svg += `</svg>`;

  // legend + data stash
  const origLabel = basename(data.original_path || 'original');
  const capLabel = basename(data.captured_path || 'replay');
  gapDataByUid[uid] = data;
  return `
    <div class="chart-wrap">
      <div class="legend">
        <span><span class="swatch" style="background:var(--ink);opacity:0.78"></span>original pcap</span>
        <span><span class="swatch" style="background:var(--accent);opacity:0.85"></span>replayed capture</span>
        <span class="muted" style="margin-left:auto">${esc(origLabel)} / ${esc(capLabel)}</span>
      </div>
      ${svg}
    </div>
  `;
}

// latency histogram — samples µs → 20 log buckets
function latencyChart(uid, hist, p50, p99) {
  // `hist` is the server's pre-binned, session-weighted histogram:
  // {log10_min_us, log10_max_us, counts[], underflow, overflow, total}.
  if (!hist || !hist.total) return '<div class="lib-empty">no samples</div>';
  const counts = hist.counts.slice();
  counts[0] += hist.underflow || 0;
  const binsMain = counts.length;
  if (hist.overflow) counts.push(hist.overflow);
  const n = counts.length;
  const w = 680, h = 200;
  const padL = 44, padR = 20, padT = 16, padB = 34;
  const innerW = w - padL - padR;
  const innerH = h - padT - padB;
  const logMin = hist.log10_min_us;
  // Extend the axis by one bin width when there is an overflow bar.
  const logMaxMain = hist.log10_max_us;
  const logMax = logMaxMain + (n - binsMain) * (logMaxMain - logMin) / binsMain;
  const buckets = counts;
  const max = Math.max(1, ...buckets);
  const bw = innerW / n;

  let svg = `<svg class="chart-svg" viewBox="0 0 ${w} ${h}" style="height:200px">`;
  for (let g = 0; g <= 4; g++) {
    const y = padT + (g / 4) * innerH;
    const v = Math.round(max * (1 - g / 4));
    svg += `<line x1="${padL}" y1="${y}" x2="${w-padR}" y2="${y}" stroke="var(--rule-soft)" stroke-width="1"/>`;
    svg += `<text x="${padL-6}" y="${y+3}" font-size="9" text-anchor="end" fill="var(--dim)" font-family="var(--mono)">${v}</text>`;
  }
  for (let i = 0; i < n; i++) {
    const x = padL + i * bw;
    const bh = (buckets[i] / max) * innerH;
    svg += `<rect class="bucket-bg" x="${x}" y="${padT}" width="${bw}" height="${innerH}" fill="transparent" data-idx="${i}" data-uid="${uid}"/>`;
    svg += `<rect x="${x+2}" y="${padT + innerH - bh}" width="${bw-4}" height="${bh}" fill="var(--blue)" opacity="0.85"/>`;
  }
  // p50 / p99 markers
  const markerAt = (v, color, label) => {
    if (!v) return '';
    const frac = Math.max(0, Math.min(1, (Math.log10(Math.max(1, v)) - logMin) / (logMax - logMin)));
    const x = padL + frac * innerW;
    return `<line x1="${x}" y1="${padT}" x2="${x}" y2="${padT+innerH}" stroke="${color}" stroke-width="1.5" stroke-dasharray="3,3"/>
            <text x="${x+4}" y="${padT+12}" font-size="10" fill="${color}" font-family="var(--mono)">${label} ${v}µs</text>`;
  };
  svg += markerAt(p50, 'var(--ok)', 'p50');
  svg += markerAt(p99, 'var(--accent)', 'p99');

  svg += `<line x1="${padL}" y1="${padT + innerH}" x2="${w-padR}" y2="${padT + innerH}" stroke="var(--ink)" stroke-width="1"/>`;
  const tickLabel = l => l < 3 ? `${Math.round(Math.pow(10, l))} µs` : (l < 6 ? `${Math.round(Math.pow(10, l - 3))} ms` : `${Math.round(Math.pow(10, l - 6))} s`);
  const xTicks = [];
  for (let l = Math.ceil(logMin); l <= logMaxMain; l++) {
    xTicks.push({ frac: (l - logMin) / (logMax - logMin), label: tickLabel(l) });
  }
  if (n > binsMain) xTicks.push({ frac: 1, label: `>${tickLabel(logMaxMain)}` });
  for (const t of xTicks) {
    const x = padL + t.frac * innerW;
    svg += `<line x1="${x}" y1="${padT + innerH}" x2="${x}" y2="${padT + innerH + 4}" stroke="var(--dim)" stroke-width="1"/>`;
    const anchor = t.frac === 0 ? 'start' : (t.frac === 1 ? 'end' : 'middle');
    svg += `<text x="${x}" y="${padT + innerH + 16}" font-size="10" fill="var(--dim)" text-anchor="${anchor}" font-family="var(--mono)">${t.label}</text>`;
  }
  svg += `</svg>`;

  latencyDataByUid[uid] = { buckets, logMin, logMax, overflowIdx: n > binsMain ? binsMain : -1 };
  return `
    <div class="chart-wrap">
      <div class="legend">
        <span><span class="swatch" style="background:var(--blue);opacity:0.85"></span>latency samples</span>
        <span><span class="swatch" style="background:var(--ok)"></span>p50</span>
        <span><span class="swatch" style="background:var(--accent)"></span>p99</span>
        <span class="muted" style="margin-left:auto">${hist.total.toLocaleString()} msgs (weighted)</span>
      </div>
      ${svg}
    </div>
  `;
}

// chart data stashes for tooltips
const gapDataByUid = {};
const latencyDataByUid = {};

function nsRange(loNs, hiNs) {
  const fmt1 = ns => {
    if (ns < 1000) return ns.toFixed(0) + ' ns';
    if (ns < 1e6)  return (ns/1000).toFixed(0) + ' µs';
    if (ns < 1e9)  return (ns/1e6).toFixed(0) + ' ms';
    return (ns/1e9).toFixed(1) + ' s';
  };
  return `${fmt1(loNs)} – ${fmt1(hiNs)}`;
}
function usRange(lo, hi) {
  const fmt1 = us => {
    if (us < 1000) return us.toFixed(0) + ' µs';
    if (us < 1e6)  return (us/1000).toFixed(1) + ' ms';
    return (us/1e6).toFixed(2) + ' s';
  };
  return `${fmt1(lo)} – ${fmt1(hi)}`;
}

// chart tooltip delegation
document.addEventListener('mousemove', e => {
  const t = e.target;
  if (!t.classList || !t.classList.contains('bucket-bg')) return;
  const uid = t.getAttribute('data-uid');
  const idx = parseInt(t.getAttribute('data-idx'));
  let html = '';
  if (gapDataByUid[uid]) {
    const d = gapDataByUid[uid];
    const n = 20;
    const lo = Math.pow(10, 3 + (idx / n) * 7);
    const hi = Math.pow(10, 3 + ((idx+1) / n) * 7);
    html = `<b>${nsRange(lo, hi)}</b><br>original: ${d.original[idx]}<br>replay: ${d.captured[idx]}`;
  } else if (latencyDataByUid[uid]) {
    const d = latencyDataByUid[uid];
    const n = d.buckets.length;
    const lo = Math.pow(10, d.logMin + (idx / n) * (d.logMax - d.logMin));
    const hi = Math.pow(10, d.logMin + ((idx+1) / n) * (d.logMax - d.logMin));
    html = idx === d.overflowIdx
      ? `<b>&ge; ${usRange(lo, lo).split(' – ')[0]}</b><br>${d.buckets[idx]} msgs`
      : `<b>${usRange(lo, hi)}</b><br>${d.buckets[idx]} msgs`;
  }
  if (html) showTip(html, e.clientX + window.scrollX, e.clientY + window.scrollY);
});
document.addEventListener('mouseout', e => {
  if (e.target.classList && e.target.classList.contains('bucket-bg')) hideTip();
});

// =========================================================================
//  gap histogram loader
// =========================================================================
const gapCache = {};
async function fetchGapHistogram(id) {
  if (gapCache[id] === 'loading' || gapCache[id]) return;
  gapCache[id] = 'loading';
  const res = await api(`/api/runs/${id}/gaps`);
  if (!res.ok) {
    gapCache[id] = null;
    const node = el(`gap-${id}`);
    if (node) node.innerHTML = `<div class="err-box">${esc(res.data.error || res.data)}</div>`;
    return;
  }
  gapCache[id] = res.data;
  // The next refreshRuns() tick will render from cache; also re-render now
  // if the current detail matches.
  if (currentDetailId === id) refreshRuns();
}

