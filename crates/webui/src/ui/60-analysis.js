// 60-analysis.js — post-run fidelity analysis: an explicit run picker
// that shows each run's status (F108, F093), the captured-pcap drop
// zone, the report with the new verdicts, run warnings and fleet
// counters, endpoint drill-downs rendered only when opened (F115),
// stored analyses of a run (with their source: manual, auto or
// on-demand), analysing a run's own replay capture, and a JSON download
// that does not leak blob URLs.
'use strict';

const an = { file: null, report: null, analysisId: null, details: new Map(), filter: '', verdict: '' };

const VERDICT_CLASS = {
  all_correct: 'ok', identical: 'ok', structurally_identical: 'ok', good_delivery: 'ok', stopped_clean: 'ok',
  partial: 'warn', partial_delivery: 'warn', degraded: 'warn', subset_script: 'warn', divergent_script: 'warn',
  stopped_before_delivery: 'warn', inconclusive: 'warn', unpaired: 'warn',
  failed: 'bad', run_failed: 'bad', never_connected: 'bad', no_delivery: 'bad', handshake_incomplete: 'bad',
  no_session: 'bad', missing_sessions: 'bad',
  not_attempted: 'muted', no_reference: 'muted', target_silent: 'muted', unknown: 'muted',
};
const verdictHtml = v => `<span class="verdict vd-${VERDICT_CLASS[v] || 'muted'}">${esc(String(v || 'unknown').replace(/_/g, ' '))}</span>`;
const scoreCls = s => (s >= 99.999 ? 'ok' : s <= 0 ? 'bad' : 'warn');
function slaveSlug(ip) { return String(ip).replace(/[^A-Za-z0-9]/g, '-'); }

// ---------------------------------------------------------------------------
// Run picker.

function analysableRuns() {
  return S.runs.filter(r => r.mode === 'benchmark');
}

function renderRunPicker() {
  const sel = el('an-run');
  const runs = analysableRuns();
  const want = sel.value || sel.dataset.want || '';
  let h = runs.length ? '' : '<option value="">No benchmark runs yet</option>';
  for (const r of runs) {
    const la = r.latest_analysis;
    const done = la ? ` · analysed: ${String(la.verdict).replace(/_/g, ' ')} ${Number(la.score).toFixed(1)}%` : '';
    const label = `${runNum(r.id)} · ${r.status} · ${r.role} · ${libraryName(r.pcap_id, r.pcap)} · ${fmtClock(r.started_at)}${done}`;
    h += `<option value="${r.id}"${r.status === 'running' ? ' disabled' : ''}>${esc(label)}${r.status === 'running' ? ' (still running)' : ''}</option>`;
  }
  if (sel._html !== h) {
    sel.innerHTML = h;
    sel._html = h;
  }
  const ok = id => runs.some(r => String(r.id) === String(id) && r.status !== 'running');
  if (ok(want)) sel.value = want;
  else {
    const best = runs.find(r => ['completed', 'partial', 'stopped'].includes(r.status)) || runs.find(r => r.status !== 'running');
    sel.value = best ? String(best.id) : '';
  }
  delete sel.dataset.want;
  renderRunInfo();
}

function selectedRun() {
  const id = Number(el('an-run').value);
  return S.runs.find(r => r.id === id) || null;
}

let _prevListFor = null;
function renderRunInfo() {
  const r = selectedRun();
  const box = el('an-run-info');
  if (!r) { setHTML(box, analysableRuns().length ? '' : 'Start a stateful (benchmark) run first; raw runs cannot be analysed.'); updateAnalyzeBtn(); return; }
  const b = r.benchmark;
  let h = `<span class="status s-${esc(r.status)}">${esc(r.status)}</span> ${esc(r.proto)} ${esc(r.role)}, ${r.sources ? plural(r.sources, 'session') : 'no sessions'}`;
  if (b) h += `, ${fmtInt(b.total_messages_sent)} messages sent`;
  if (r.status === 'failed' || (b && !b.total_messages_sent)) {
    h += `<span class="warn-line">This run ${r.status === 'failed' ? 'failed' : 'sent nothing'}${r.error ? ': ' + esc(r.error) : ''}. The analysis will say so instead of certifying delivery.</span>`;
  }
  const st = analysisStateHtml(r);
  if (st) h += `<span class="an-run-state">${st}</span>`;
  if (r.has_capture && r.status !== 'running') {
    h += `<span class="an-own">This run has its own replay capture: <button type="button" class="btn btn-text" data-act="an-own" data-id="${r.id}" data-fk="an-own-${r.id}"${an.ownBusy ? ' disabled' : ''}>${an.ownBusy ? 'Analysing…' : 'Analyze it (no upload needed)'}</button></span>`;
  }
  h += `<span class="prev-analyses" id="an-prev"></span>`;
  // A re-render empties the stored-analyses list: load it again.
  if (setHTML(box, h) || _prevListFor !== r.id) { _prevListFor = r.id; loadPrevAnalyses(r.id); }
  updateAnalyzeBtn();
}

async function loadPrevAnalyses(runId) {
  const res = await api(`/api/runs/${runId}/analyses`);
  const box = el('an-prev');
  if (!box || _prevListFor !== runId) return;
  if (!res.ok || !Array.isArray(res.data) || !res.data.length) { box.textContent = ''; return; }
  box.innerHTML = ' Stored analyses: ' + res.data.slice(0, 5).map(a =>
    `<button type="button" class="btn btn-text" data-act="an-open" data-id="${esc(a.id)}">#${esc(a.id)} ${esc(String(a.verdict).replace(/_/g, ' '))} ${Number(a.score_pct).toFixed(1)}% (${a.source ? esc(String(a.source).replace(/_/g, '-')) + ', ' : ''}${esc(fmtClock(a.created_at))})</button>`).join(' ');
}

function updateAnalyzeBtn() {
  el('an-run-btn').disabled = !(an.file && selectedRun());
}

// ---------------------------------------------------------------------------
// Running an analysis.

function setAnalysisFile(f) {
  an.file = f;
  setHTML(el('an-file-status'), `<p class="ok">Selected ${esc(f.name)} · ${fmtBytes(f.size)}</p>`, { force: true });
  updateAnalyzeBtn();
}

async function runAnalysis() {
  const r = selectedRun();
  if (!an.file || !r) return;
  const tolRaw = val('an-cp56-tol');
  const tol = Number(tolRaw);
  if (tolRaw === '' || !Number.isFinite(tol) || tol < 0) {
    fieldError('an-cp56-tol', 'Enter a tolerance of 0 ms or more.');
    el('an-cp56-tol').focus();
    return;
  }
  fieldError('an-cp56-tol', '');
  const mode = radio('an-mode') || 'generic';
  const btn = el('an-run-btn');
  btn.disabled = true;
  setText(el('an-msg'), `Analysing against ${runNum(r.id)}…`);
  setHTML(el('an-error'), '', { force: true });
  const fd = new FormData();
  fd.append('file', an.file);
  fd.append('mode', mode);
  fd.append('run_id', String(r.id));
  fd.append('cp56_tolerance_ms', String(tol));
  const res = await api(`/api/analyze?run_id=${r.id}`, 'POST', fd, { timeout: 0 });
  btn.disabled = false;
  updateAnalyzeBtn();
  if (!res.ok || !res.data || typeof res.data !== 'object') {
    setText(el('an-msg'), '');
    setHTML(el('an-error'), `<div class="err-box">Analysis against ${esc(runNum(r.id))} failed: ${esc(res.error || 'bad reply')}</div>`, { force: true });
    return;
  }
  setText(el('an-msg'), `Done: compared against ${runNum(res.data.run_id)}.`);
  announce('Analysis finished');
  showReport(res.data, res.data.analysis_id || null);
  _prevListFor = null;
  renderRunInfo();
}

// POST /api/runs/:id/analyze: analyse the run's own replay capture.
async function analyzeOwnCapture(runId) {
  if (an.ownBusy) return;
  an.ownBusy = true;
  renderRunInfo();
  setText(el('an-msg'), `Analysing the replay capture of ${runNum(runId)}…`);
  setHTML(el('an-error'), '', { force: true });
  const res = await api(`/api/runs/${runId}/analyze`, 'POST', null, { timeout: 0 });
  an.ownBusy = false;
  renderRunInfo();
  if (!res.ok || !res.data) {
    setText(el('an-msg'), '');
    setHTML(el('an-error'), `<div class="err-box">Analysis of ${esc(runNum(runId))} failed: ${esc(res.error || 'bad reply')}${analyzeErrorHint(res.code) ? `<p class="hint-strong">${esc(analyzeErrorHint(res.code))}</p>` : ''}</div>`, { force: true });
    return;
  }
  _prevListFor = null;
  renderRunInfo();
  pollRunsSoon();
  await openStoredAnalysis(res.data.analysis_id);
}

// Why POST /api/runs/:id/analyze was refused, in operator terms.
function analyzeErrorHint(code) {
  return {
    capture_missing: 'The run has no replay capture (slave-mode runs, and runs that failed before sending, have none). Upload a capture taken on the target side instead.',
    run_running: 'The run is still running; analyse it once it has finished.',
    not_benchmark: 'Only stateful (benchmark) runs can be analysed.',
    source_pcap_missing: 'The run\'s source pcap is no longer in the library, so there is nothing to compare the capture against. Upload it again.',
    busy: 'The server is already running as many analyses as it allows. Wait a moment and try again.',
  }[code] || '';
}

async function openStoredAnalysis(id) {
  setText(el('an-msg'), `Loading analysis #${id}…`);
  const res = await api(`/api/analyses/${encodeURIComponent(id)}`);
  if (!res.ok || !res.data) { setText(el('an-msg'), ''); notify(`Could not load analysis #${id}: ${res.error}`); return; }
  setText(el('an-msg'), `Showing stored analysis #${id}.`);
  showReport(res.data, Number(id));
}

function showReport(report, analysisId) {
  an.report = report;
  an.analysisId = analysisId;
  an.details = new Map(Object.entries(report.details_by_ip || {}));
  el('an-download-json').hidden = false;
  renderAnalysis();
}

// The JSON is built on click and the object URL revoked right after,
// so repeated analyses do not keep MB-sized blobs alive (F115).
function downloadReport() {
  if (!an.report) return;
  const blob = new Blob([JSON.stringify(an.report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `analysis_run${an.report.run_id}${an.analysisId ? '_' + an.analysisId : ''}.json`;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

actions({
  analyze: runAnalysis,
  'analysis-download': downloadReport,
  'an-open': b => openStoredAnalysis(b.dataset.id),
  'an-own': b => analyzeOwnCapture(Number(b.dataset.id)),
});

// ---------------------------------------------------------------------------
// Report rendering.

let _anCharts = [];
function _resetAnalysisCharts() {
  for (const c of _anCharts) { try { c.dispose(); } catch (_) { /* already gone */ } }
  _anCharts = [];
}
window.trackAnalysisChart = c => { _anCharts.push(c); };

function renderAnalysis() {
  const r = an.report;
  _resetAnalysisCharts();
  const f = r.fleet || {};
  const run = S.runs.find(x => x.id === r.run_id);
  let h = '<div class="card an-card">';
  h += `<h3 class="card-title">Result for ${runNum(r.run_id)}</h3>`;
  h += `<p class="meta-line">Compared against ${runNum(r.run_id)} (${esc(run ? libraryName(run.pcap_id, run.pcap) : basename(r.original_pcap))}, ${esc(r.role)} role${run && run.target_port ? ', port ' + esc(run.target_port) : ''}, ${esc(r.mode)} mode)` +
    `${r.run_selection ? ` · run chosen ${r.run_selection === 'explicit' ? 'explicitly' : 'as the latest finished run'}` : ''}` +
    `${r.run_status ? ` · run status <span class="status s-${esc(r.run_status)}">${esc(r.run_status)}</span>` : ''}</p>`;
  if (r.run_warning) h += `<div class="err-box" role="alert"><b>Run warning:</b> ${esc(r.run_warning)}</div>`;
  const warns = (r.warnings || []).filter(w => !(r.run_warning && String(w).includes(r.run_warning)));
  if (warns.length) h += '<div class="warn-box"><ul>' + warns.map(w => `<li>${esc(w)}</li>`).join('') + '</ul></div>';
  h += `<div class="an-summary">${verdictHtml(r.verdict)}<span class="an-score ${scoreCls(r.score_pct)}">${Number(r.score_pct).toFixed(1)}%</span>`;
  if (f.frame_weighted_score_pct != null) h += `<span class="hint">frame-weighted ${Number(f.frame_weighted_score_pct).toFixed(1)}%</span>`;
  h += `<p class="reason">${esc(r.verdict_reason)}</p></div>`;
  const bucket = (n, label, cls) => `<li class="an-bucket ${cls}"><b>${fmtInt(n || 0)}</b> ${label}</li>`;
  h += '<ul class="an-fleet-strip" aria-label="Endpoint outcomes">' +
    bucket(f.slave_count, 'total', '') + bucket(f.fully_correct, 'all correct', 'ok') + bucket(f.partial, 'partial', 'warn') +
    bucket(f.failed, 'failed', 'bad') + bucket(f.not_attempted, 'silent', 'muted');
  if (f.never_connected != null) h += bucket(f.never_connected, 'never connected', 'bad');
  if (f.unpaired != null) h += bucket(f.unpaired, 'unpaired', 'warn');
  if (f.inconclusive != null) h += bucket(f.inconclusive, 'inconclusive', 'muted');
  if (f.reconnects != null) h += bucket(f.reconnects, 'reconnects', f.reconnects ? 'warn' : '');
  h += '</ul>';
  if (f.best || f.worst) {
    h += '<p class="meta-line">';
    if (f.worst) h += `Worst <code>${esc(f.worst.slave_ip)}</code> at <b>${Number(f.worst.score_pct).toFixed(1)}%</b>. `;
    if (f.best) h += `Best <code>${esc(f.best.slave_ip)}</code> at <b>${Number(f.best.score_pct).toFixed(1)}%</b>.`;
    h += '</p>';
  }
  const pr = (window.PROTOCOL_RENDERERS || {})[r.protocol];
  if (pr && typeof pr.renderFleetExtras === 'function' && an.details.size) h += pr.renderFleetExtras(r);
  h += fleetChartBlock(r.fleet_pacing_timeline, 'fleet-pacing', 'Fleet pacing drift', 'Each dot is one I-frame, plotted at how many ms later the replay sent it than the original pace. Orange: mean per time bucket (flat near zero = pacing held). Dashed: p95 and p05.', 'X: seconds since capture start · Y: pacing drift in ms, positive = late');
  h += fleetChartBlock(r.fleet_drift_timeline, 'fleet-drift', 'Fleet CP56 drift', 'Each dot is one CP56 sample. Orange: mean per time bucket (flat = constant offset, slope = cumulative drift). Dashed: p95 and p05.', 'X: seconds since capture start · Y: signed drift in ms');
  h += '<dl class="kv">';
  h += `<dt>Source pcap</dt><dd>${esc(run ? libraryName(run.pcap_id, r.original_pcap) : basename(r.original_pcap))}</dd>`;
  h += `<dt>Captured file</dt><dd>${fmtBytes(r.captured_size_bytes)} · ${fmtInt(r.captured_total_packets)} packets</dd>`;
  if (r.master_ip_mapping) {
    const m = r.master_ip_mapping;
    h += `<dt>Master IP</dt><dd>${m.captured ? 'captured <code>' + esc(m.captured) + '</code>' : ''}${m.live ? ' · live <code>' + esc(m.live) + '</code>' : ''}${m.renamed ? ' (renamed)' : ''}</dd>`;
  }
  h += '</dl>';
  if (r.notes && r.notes.length) h += '<h4>Notes</h4><ul class="notes">' + r.notes.map(n => `<li>${esc(n)}</li>`).join('') + '</ul>';
  h += endpointTableShell(r);
  h += '</div>';
  setHTML(el('an-result'), h, { force: true });
  renderEndpointRows();
  setTimeout(() => {
    initFleetTimelineChart(r.fleet_pacing_timeline, 'fleet-pacing');
    initFleetTimelineChart(r.fleet_drift_timeline, 'fleet-drift');
  }, 0);
}

function fleetChartBlock(tl, key, heading, legend, axes) {
  if (!tl || !tl.samples || !tl.samples.length) return '';
  const iters = (tl.iteration_starts_ms || []).length;
  const note = (iters > 1 ? ` · ${iters} loop iterations marked` : '') +
    (tl.decimated ? ` · decimated from ${fmtInt(tl.total_samples)} samples` : ` · ${fmtInt(tl.total_samples)} samples`);
  return `<figure class="an-figure"><figcaption><h4>${esc(heading)}</h4><p class="hint">${esc(legend)}${esc(note)}</p><p class="hint">${esc(axes)}</p></figcaption>` +
    `<div id="an-${key}-chart" class="an-chart" role="img" aria-label="${esc(heading)} chart"></div><div id="an-${key}-stats" class="an-chart-stats"></div></figure>`;
}

function endpointTableShell(r) {
  const n = (r.slaves || []).length;
  if (!n) return '<p class="hint">No endpoints to report.</p>';
  const verdicts = Array.from(new Set(r.slaves.map(s => s.verdict)));
  return `<h4>Endpoints (${n})</h4>` +
    '<div class="sess-toolbar">' +
      `<div class="field"><label for="an-ep-q">Find</label><input id="an-ep-q" type="search" placeholder="IP" value="${esc(an.filter)}" spellcheck="false" autocomplete="off"></div>` +
      `<div class="field"><label for="an-ep-verdict">Verdict</label><select id="an-ep-verdict"><option value="">All</option>${verdicts.map(v => `<option value="${esc(v)}"${an.verdict === v ? ' selected' : ''}>${esc(v.replace(/_/g, ' '))}</option>`).join('')}</select></div>` +
    '</div>' +
    '<p class="hint">Open a row for its detail; it is loaded when opened.</p>' +
    '<div class="an-slave-table" role="list"><div class="an-slave-row an-slave-head" aria-hidden="true"><span></span><span>Endpoint</span><span>Packets</span><span>Delivered</span><span>Handshake</span><span>Score</span><span>Verdict</span></div>' +
    '<div id="an-ep-rows"></div></div>';
}

function renderEndpointRows() {
  const box = el('an-ep-rows');
  if (!box) return;
  const r = an.report;
  const q = an.filter;
  const rows = (r.slaves || []).filter(s => (!q || s.slave_ip.includes(q)) && (!an.verdict || s.verdict === an.verdict))
    .sort((a, b) => a.score_pct - b.score_pct || ipToInt(a.slave_ip) - ipToInt(b.slave_ip));
  let h = '';
  for (const s of rows) {
    const deliv = s.delivered_iframes === s.expected_iframes && s.expected_iframes > 0 ? 'ok' : (s.delivered_iframes === 0 ? 'bad' : 'warn');
    const hs = s.startdt_handshake_ok ? ['ok', '✓', 'completed'] : (s.packets > 0 ? ['bad', '✗', 'missing'] : ['muted', '—', 'no traffic']);
    h += `<details class="an-slave-row" role="listitem" data-ip="${esc(s.slave_ip)}"><summary class="an-slave-sum">` +
      '<span class="an-tri" aria-hidden="true">▸</span>' +
      `<span><code>${esc(s.slave_ip)}</code>${s.sessions > 1 ? ` <span class="hint">${s.sessions} sessions</span>` : ''}</span>` +
      `<span>${fmtInt(s.packets)}<span class="sr-only"> packets</span></span>` +
      `<span class="${deliv}">${fmtInt(s.delivered_iframes)}/${fmtInt(s.expected_iframes)}<span class="sr-only"> delivered</span></span>` +
      `<span class="${hs[0]}"><span aria-hidden="true">${hs[1]}</span><span class="sr-only">handshake ${hs[2]}</span></span>` +
      `<span class="${scoreCls(s.score_pct)}"><b>${Number(s.score_pct).toFixed(1)}%</b></span>` +
      `<span>${verdictHtml(s.verdict)}</span></summary><div class="an-slave-detail"></div></details>`;
  }
  if (!rows.length) h = '<p class="empty">No endpoint matches.</p>';
  box.innerHTML = h;
}

document.addEventListener('input', e => { if (e.target.id === 'an-ep-q') { an.filter = e.target.value.trim(); renderEndpointRows(); } });
document.addEventListener('change', e => { if (e.target.id === 'an-ep-verdict') { an.verdict = e.target.value; renderEndpointRows(); } });

// Drill-down HTML is built only when a row is opened (F115). Details
// come from the analyze reply when present, else from the stored
// analysis (GET /api/analyses/:id/endpoints/:ip).
document.addEventListener('toggle', async e => {
  const node = e.target;
  if (!node.classList || !node.classList.contains('an-slave-row') || !node.open || node.dataset.loaded) return;
  node.dataset.loaded = '1';
  const ip = node.dataset.ip;
  const box = node.querySelector('.an-slave-detail');
  const s = (an.report.slaves || []).find(x => x.slave_ip === ip) || {};
  let d = an.details.get(ip);
  if (!d && an.analysisId != null) {
    box.textContent = 'Loading…';
    const res = await api(`/api/analyses/${an.analysisId}/endpoints/${encodeURIComponent(ip)}`);
    if (!res.ok) { box.innerHTML = `<div class="err-box">Could not load the detail: ${esc(res.error)}</div>`; delete node.dataset.loaded; return; }
    d = res.data;
    an.details.set(ip, d);
  }
  if (!d) { box.innerHTML = '<p class="hint">No detail available for this endpoint.</p>'; return; }
  box.innerHTML = `<p class="hint">${esc(s.verdict_reason || d.verdict_reason || '')}</p>` + sessionsHtml(d) + renderSlaveDetail(an.report.protocol, ip, d);
  const pr = (window.PROTOCOL_RENDERERS || {})[an.report.protocol];
  if (pr && typeof pr.initSlaveCharts === 'function') pr.initSlaveCharts(slaveSlug(ip), d);
}, true);

function sessionsHtml(d) {
  const ss = d.sessions || [];
  if (ss.length <= 1) return '';
  let h = `<h5>TCP sessions (${ss.length}${d.sessions_total > ss.length ? ' of ' + d.sessions_total : ''})</h5><div class="table-scroll"><table class="t"><thead><tr>` +
    '<th scope="col">#</th><th scope="col">Flow</th><th scope="col" class="num">Start (ms)</th><th scope="col" class="num">Delivered</th><th scope="col" class="num">Score</th><th scope="col">Verdict</th></tr></thead><tbody>';
  for (const x of ss) {
    h += `<tr><td>${esc(x.index)}</td><td><code>${esc(x.flow && x.flow.client)} → ${esc(x.flow && x.flow.server)}</code></td><td class="num">${fmt(x.first_ts_ms)}</td>` +
      `<td class="num">${fmtInt(x.delivered)}/${fmtInt(x.expected)}</td><td class="num">${Number(x.score_pct).toFixed(1)}%</td><td>${verdictHtml(x.verdict)}</td></tr>`;
  }
  return h + '</tbody></table></div>';
}

// Per-endpoint drill-down dispatcher: the protocol's renderer if one is
// registered (crates/proto_*/static/*.js), else a minimal generic view.
function renderSlaveDetail(proto, slaveIp, d) {
  const pr = (window.PROTOCOL_RENDERERS || {})[proto];
  if (pr && typeof pr.renderSlaveDetail === 'function') return pr.renderSlaveDetail(slaveIp, d);
  let h = `<p class="hint">No detail renderer is registered for protocol <code>${esc(proto || '?')}</code>.</p>`;
  if (d && d.tcp_flow) h += `<dl class="kv"><dt>TCP flow</dt><dd>${esc(d.tcp_flow.client)} → ${esc(d.tcp_flow.server)} · ${esc(d.tcp_flow.packets)} packets</dd></dl>`;
  if (d && d.notes && d.notes.length) h += '<ul class="notes">' + d.notes.map(n => `<li>${esc(n)}</li>`).join('') + '</ul>';
  return h;
}

function initAnalysis() {
  wireDropzone(el('an-dropzone'), files => setAnalysisFile(files[0]));
  el('an-run').addEventListener('change', () => { _prevListFor = null; renderRunInfo(); });
  on('runs', () => { if (S.view === 'analysis') renderRunPicker(); });
  on('library', () => { if (S.view === 'analysis') renderRunPicker(); });
  on('route', ({ view, arg, args }) => {
    if (view !== 'analysis') return;
    if (arg && /^\d+$/.test(arg)) { el('an-run').dataset.want = arg; el('an-run').value = ''; }
    renderRunPicker();
    // #/analysis/<run>/<analysis>: open that stored analysis.
    const aid = args && args[1];
    if (aid && /^\d+$/.test(aid) && an.analysisId !== Number(aid)) openStoredAnalysis(aid);
  });
  on('analysis-event', ({ data }) => {
    if (S.view !== 'analysis') return;
    const r = selectedRun();
    if (r && Number(data.run_id) === r.id) { _prevListFor = null; renderRunInfo(); }
  });
  let rt = null;
  window.addEventListener('resize', () => {
    if (!_anCharts.length) return;
    clearTimeout(rt);
    rt = setTimeout(() => { for (const c of _anCharts) { try { c.resize(); } catch (_) { /* disposed */ } } }, 150);
  });
}

// ---------------------------------------------------------------------------
// Fleet timeline chart (ECharts): scatter of every sample plus per-bucket
// mean / p05 / p95 lines and iteration markers.

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
    label: { color: '#888', fontSize: 11, formatter: p => p.data.label },
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
          formatter: (p) => {
            // axis label on the cross hair lines.
            const v = (typeof p.value === 'number') ? p.value : Number(p.value);
            const unit = p.axisDimension === 'x' ? 's' : 'ms';
            return `${v.toFixed(2)} ${unit}`;
          },
        },
      },
      backgroundColor: 'rgba(255,255,255,0.97)',
      borderColor: '#d8d7d0',
      borderWidth: 1,
      padding: [8, 12],
      extraCssText: 'box-shadow: 0 2px 8px rgba(0,0,0,0.15);',
      formatter: tooltipFmt,
    },
    legend: {
      top: 6, left: 8,
      textStyle: { fontSize: 11, color: '#444' },
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
      nameTextStyle: { fontSize: 11, color: '#777' },
    },
    yAxis: {
      type: 'value',
      name: 'ms',
      nameLocation: 'middle',
      nameGap: 48,
      nameTextStyle: { fontSize: 11, color: '#777' },
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
