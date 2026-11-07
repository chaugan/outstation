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
  // stopped_clean is clean only up to a stop: never shown as a plain pass.
  all_correct: 'ok', identical: 'ok', structurally_identical: 'ok', good_delivery: 'ok', stopped_clean: 'warn',
  partial: 'warn', partial_delivery: 'warn', degraded: 'warn', subset_script: 'warn', divergent_script: 'warn',
  stopped_before_delivery: 'warn', inconclusive: 'warn', unpaired: 'warn',
  failed: 'bad', run_failed: 'bad', never_connected: 'bad', no_delivery: 'bad', handshake_incomplete: 'bad',
  no_session: 'bad', missing_sessions: 'bad',
  not_attempted: 'muted', no_reference: 'muted', target_silent: 'muted', unknown: 'muted',
};
const verdictHtml = v => `<span class="verdict vd-${VERDICT_CLASS[v] || 'muted'}">${esc(String(v || 'unknown').replace(/_/g, ' '))}</span>`;
// Colour follows the verdict or outcome, never the score: a degraded or
// failing endpoint can score 100 on content and must not look green (N14).
const verdictCls = v => VERDICT_CLASS[v] || 'muted';
function outcomeCls(outcome, verdict) {
  if (outcome === 'pass') return verdict === 'stopped_clean' ? 'warn' : 'ok';
  if (outcome === 'fail') return verdictCls(verdict) === 'ok' ? 'bad' : (verdictCls(verdict) === 'muted' ? 'bad' : verdictCls(verdict));
  return 'muted';
}
function slaveSlug(ip) { return String(ip).replace(/[^A-Za-z0-9]/g, '-'); }

// ---------------------------------------------------------------------------
// Run picker.

function analysableRuns() {
  return S.runs.filter(r => r.mode === 'benchmark');
}

function renderAnEmpty() {
  const none = S.runsLoaded && !analysableRuns().length;
  const box = el('an-empty');
  box.hidden = !none;
  el('an-input').hidden = none;
  if (none) {
    const have = S.library.length > 0;
    setHTML(box, emptyStateHtml({
      step: have ? (S.runs.length ? 3 : 2) : 1,
      title: 'Nothing to analyse yet',
      body: 'An analysis compares a stateful (benchmark) run with what arrived at the target: delivery, content, handshake, GI/CI answers and timing, per endpoint. Finished runs with a replay capture are analysed by themselves.',
      action: have ? '<a class="btn btn-primary" href="#/configure">Configure a run</a>' : '<a class="btn btn-primary" href="#/library">Upload a capture</a>',
    }));
  }
}

function renderRunPicker() {
  renderAnEmpty();
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
  const res = await api(`api/runs/${runId}/analyses`);
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
  const res = await api(`api/analyze?run_id=${r.id}`, 'POST', fd, { timeout: 0 });
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
  const res = await api(`api/runs/${runId}/analyze`, 'POST', null, { timeout: 0 });
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
    capture_unavailable: 'The run\'s capture failed (see the run\'s warnings), so analysing it would report frames as missing that were sent. Upload a capture taken on the target side instead.',
    capture_missing: 'The run has no replay capture (slave-mode runs, and runs that failed before sending, have none). Upload a capture taken on the target side instead.',
    run_running: 'The run is still running; analyse it once it has finished.',
    not_benchmark: 'Only stateful (benchmark) runs can be analysed.',
    source_pcap_missing: 'The run\'s source pcap is no longer in the library, so there is nothing to compare the capture against. Upload it again.',
    busy: 'The server is already running as many analyses as it allows. Wait a moment and try again.',
  }[code] || '';
}

async function openStoredAnalysis(id) {
  setText(el('an-msg'), `Loading analysis #${id}…`);
  const res = await api(`api/analyses/${encodeURIComponent(id)}`);
  if (!res.ok || !res.data) { setText(el('an-msg'), ''); notify(`Could not load analysis #${id}: ${res.error}`); return; }
  setText(el('an-msg'), `Showing stored analysis #${id}.`);
  showReport(res.data, Number(id));
}

function showReport(report, analysisId) {
  an.report = report;
  an.analysisId = analysisId;
  an.details = new Map(Object.entries(report.details_by_ip || {}));
  an.filter = '';
  an.verdict = '';
  // The result takes the screen; the input card folds into one line.
  el('an-input').open = false;
  setText(el('an-input-sum'), `showing ${runNum(report.run_id)}${analysisId != null ? ', analysis #' + analysisId : ''}; open to analyse another capture`);
  renderAnalysis();
}

// Theme change: charts are canvases with resolved colours, so the
// report is rebuilt; open sections and endpoint rows stay open.
function rerenderAnalysisForTheme() {
  if (!an.report || !el('an-result').firstChild) return;
  const openSecs = qsa('#an-result details.an-sec[open]').map(d => d.id);
  const openRows = qsa('#an-result .an-slave-row[open]').map(d => d.dataset.ip);
  const y = window.scrollY;
  renderAnalysis();
  for (const id of openSecs) { const d = el(id); if (d) d.open = true; }
  for (const ip of openRows) { const d = qs(`.an-slave-row[data-ip="${CSS.escape(ip)}"]`); if (d) d.open = true; }
  window.scrollTo(0, y);
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
  const slaves = r.slaves || [];
  const vc = verdictCls(r.verdict);
  let h = '<div class="an-report">';

  // 1. Verdict hero: the answer first.
  h += `<section class="card an-hero tone-${vc}" aria-labelledby="an-hero-title">`;
  h += `<div class="an-hero-top"><h3 class="an-hero-title" id="an-hero-title">Result for ${runNum(r.run_id)}</h3>`;
  h += '<div class="btn-row an-export">';
  if (an.analysisId != null) {
    // Self-contained, printable HTML export of the stored analysis (F131).
    const rep = `api/analyses/${encodeURIComponent(an.analysisId)}/report.html`;
    h += `<a class="btn btn-secondary" id="an-report-html" href="${rep}?download=1" download>Download HTML report</a>` +
      `<a class="btn btn-text" href="${rep}" target="_blank" rel="noopener">Printable report</a>`;
  }
  h += '<button type="button" class="btn btn-text" data-act="analysis-download">JSON</button></div></div>';
  h += `<div class="an-summary">${verdictHtml(r.verdict)}<span class="an-score ${vc}">${Number(r.score_pct).toFixed(1)}%</span>`;
  if (f.frame_weighted_score_pct != null) h += `<span class="hint">frame-weighted ${Number(f.frame_weighted_score_pct).toFixed(1)}%</span>`;
  h += `<p class="reason">${esc(r.verdict_reason)}</p></div>`;
  const facts = [];
  const judged = f.slave_count != null ? f.slave_count : slaves.length;
  facts.push(`<b>${fmtInt(f.fully_correct || 0)}</b> of ${fmtInt(judged)} endpoints all correct`);
  if (f.worst && slaves.length > 1 && (Number(f.worst.score_pct) < 99.95 || (f.fully_correct || 0) < judged)) facts.push(`worst <code>${esc(f.worst.slave_ip)}</code> ${Number(f.worst.score_pct).toFixed(1)}%`);
  const capName = run ? libraryName(run.pcap_id, run.pcap) : basename(r.original_pcap);
  facts.push(`${capName ? esc(capName) + ', ' : ''}${esc(r.role)} role, ${esc(r.mode)} mode`);
  if (r.run_status) facts.push(`run <span class="status s-${esc(r.run_status)}">${esc(r.run_status)}</span>`);
  h += `<p class="an-facts">${facts.join(' · ')}</p>`;
  if (r.run_warning) h += `<div class="err-box" role="alert"><b>Run warning:</b> ${esc(r.run_warning)}</div>`;
  const warns = (r.warnings || []).filter(w => !(r.run_warning && String(w).includes(r.run_warning)));
  if (warns.length) h += '<div class="warn-box"><ul>' + warns.map(w => `<li>${esc(w)}</li>`).join('') + '</ul></div>';
  h += '</section>';

  // 2. Overview: heatmap of every endpoint, and the dimension summary.
  h += '<div class="an-overview">';
  h += heatmapHtml(slaves);
  h += dimensionsHtml(r);
  h += '</div>';

  // 3. Detail sections, collapsed.
  const sec = (id, title, body, extra = '') => `<details class="card an-sec" id="an-sec-${id}"${extra}><summary><h4>${title}</h4></summary><div class="an-sec-body">${body}</div></details>`;
  h += sec('endpoints', `Endpoint table <span class="opt">${fmtInt(slaves.length)} endpoints, worst first; open a row for its drill-down</span>`, endpointTableShell(r));
  const timing = fleetChartBlock(r.fleet_pacing_timeline, 'fleet-pacing', 'Fleet pacing drift', 'Each dot is one I-frame, plotted at how many ms later the replay sent it than the original pace. Orange: mean per time bucket (flat near zero = pacing held). Dashed: p95 and p05.', 'X: seconds since capture start · Y: pacing drift in ms, positive = late') +
    fleetChartBlock(r.fleet_drift_timeline, 'fleet-drift', 'Fleet CP56 drift', 'Each dot is one CP56 sample. Orange: mean per time bucket (flat = constant offset, slope = cumulative drift). Dashed: p95 and p05.', 'X: seconds since capture start · Y: signed drift in ms');
  if (timing) h += sec('timing', 'Fleet timing <span class="opt">pacing and CP56 drift charts</span>', timing);
  const pr = (window.PROTOCOL_RENDERERS || {})[r.protocol];
  const extras = pr && typeof pr.renderFleetExtras === 'function' && (an.details.size || r.fleet_gi_ci_audit) ? pr.renderFleetExtras(r) : '';
  if (extras) h += sec('gici', 'Interrogation audit <span class="opt">GI and CI across the fleet</span>', extras);
  let info = '<dl class="kv">';
  info += `<dt>Compared against</dt><dd>${runNum(r.run_id)}${run && run.target_port ? ', port ' + esc(run.target_port) : ''}${r.run_selection ? ` · run chosen ${r.run_selection === 'explicit' ? 'explicitly' : 'as the latest finished run'}` : ''}</dd>`;
  info += `<dt>Source pcap</dt><dd>${esc(run ? libraryName(run.pcap_id, r.original_pcap) : basename(r.original_pcap))}</dd>`;
  info += `<dt>Captured file</dt><dd>${fmtBytes(r.captured_size_bytes)} · ${fmtInt(r.captured_total_packets)} packets</dd>`;
  if (r.master_ip_mapping) {
    const m = r.master_ip_mapping;
    info += `<dt>Master IP</dt><dd>${m.captured ? 'captured <code>' + esc(m.captured) + '</code>' : ''}${m.live ? ' · live <code>' + esc(m.live) + '</code>' : ''}${m.renamed ? ' (renamed)' : ''}</dd>`;
  }
  if (f.best) info += `<dt>Best endpoint</dt><dd><code>${esc(f.best.slave_ip)}</code> ${Number(f.best.score_pct).toFixed(1)}%</dd>`;
  info += '</dl>';
  if (r.notes && r.notes.length) info += '<h5>Analyser notes</h5><ul class="notes">' + r.notes.map(n => `<li>${esc(n)}</li>`).join('') + '</ul>';
  h += sec('info', 'Capture and run <span class="opt">files, addresses and analyser notes</span>', info);
  h += '</div>';
  setHTML(el('an-result'), h, { force: true });
  renderEndpointRows();
}

// ---------------------------------------------------------------------------
// Heatmap: one tile per endpoint in IP order, coloured (and patterned,
// so colour is not the only cue) by outcome. Tiles are buttons with a
// roving tabindex: Tab enters the map once, arrow keys move, Home/End
// jump, Enter or Space opens that endpoint in the table below. The
// legend counts and the endpoint table are the text alternative.

const TONE_WORD = { ok: 'pass', warn: 'warning', bad: 'fail', muted: 'not judged' };
const TONE_MARK = { ok: '✓', warn: '!', bad: '✗', muted: '·' };

function heatmapHtml(slaves) {
  if (!slaves.length) return '<section class="card an-heat"><h4>Endpoints</h4><p class="hint">No endpoints to report.</p></section>';
  const rows = slaves.slice().sort((a, b) => ipToInt(a.slave_ip) - ipToInt(b.slave_ip));
  const counts = { ok: 0, warn: 0, bad: 0, muted: 0 };
  let tiles = '';
  rows.forEach((s, i) => {
    const t = outcomeCls(s.outcome, s.verdict);
    counts[t]++;
    const label = `${s.slave_ip}: ${String(s.verdict || 'unknown').replace(/_/g, ' ')}, ${Number(s.score_pct).toFixed(1)}%, ${TONE_WORD[t]}`;
    tiles += `<button type="button" class="hm-t t-${t}" data-ip="${esc(s.slave_ip)}" tabindex="${i === 0 ? 0 : -1}" aria-label="${esc(label)}" title="${esc(label)}"></button>`;
  });
  const legend = ['ok', 'warn', 'bad', 'muted'].filter(t => counts[t]).map(t =>
    `<li><span class="hm-sw t-${t}" aria-hidden="true"></span><b>${fmtInt(counts[t])}</b> ${TONE_WORD[t]}</li>`).join('');
  const summary = ['ok', 'warn', 'bad', 'muted'].filter(t => counts[t]).map(t => `${counts[t]} ${TONE_WORD[t]}`).join(', ');
  return `<section class="card an-heat" aria-labelledby="an-heat-title"><div class="an-heat-head"><h4 id="an-heat-title">Endpoints <span class="opt">${fmtInt(rows.length)}, in IP order</span></h4>` +
    `<ul class="hm-legend" aria-label="Outcome counts">${legend}</ul></div>` +
    `<div class="hm ${rows.length <= 60 ? 'hm-l' : rows.length <= 400 ? 'hm-m' : 'hm-s'}" id="an-hm" role="group" aria-label="Endpoint map, ${rows.length} endpoints: ${esc(summary)}. Arrow keys move between endpoints; Enter opens one in the endpoint table." aria-describedby="an-hm-hint">${tiles}</div>` +
    `<p class="hint" id="an-hm-hint">Select a tile to open that endpoint. ${rows.length > 1 ? 'Arrow keys move between tiles.' : ''}</p></section>`;
}

function hmColumns(box) {
  const cols = getComputedStyle(box).gridTemplateColumns.split(' ').filter(Boolean).length;
  return Math.max(1, cols);
}

document.addEventListener('keydown', e => {
  const t = e.target;
  if (!t.classList || !t.classList.contains('hm-t')) return;
  const box = t.parentElement;
  const tiles = Array.from(box.children);
  const i = tiles.indexOf(t);
  const cols = hmColumns(box);
  let n = -1;
  switch (e.key) {
    case 'ArrowRight': n = Math.min(tiles.length - 1, i + 1); break;
    case 'ArrowLeft': n = Math.max(0, i - 1); break;
    case 'ArrowDown': n = Math.min(tiles.length - 1, i + cols); break;
    case 'ArrowUp': n = i - cols >= 0 ? i - cols : i; break;
    case 'Home': n = e.ctrlKey ? 0 : i - (i % cols); break;
    case 'End': n = e.ctrlKey ? tiles.length - 1 : Math.min(tiles.length - 1, i - (i % cols) + cols - 1); break;
    case 'PageDown': n = Math.min(tiles.length - 1, i + cols * 5); break;
    case 'PageUp': n = Math.max(0, i - cols * 5); break;
    default: return;
  }
  e.preventDefault();
  if (n >= 0 && n !== i) {
    t.tabIndex = -1;
    tiles[n].tabIndex = 0;
    tiles[n].focus();
  }
});
document.addEventListener('click', e => {
  const t = e.target.closest && e.target.closest('.hm-t');
  if (!t) return;
  for (const x of t.parentElement.children) x.tabIndex = x === t ? 0 : -1;
  openEndpoint(t.dataset.ip);
});

// Open one endpoint's drill-down in the table: open the section, clear
// a filter that hides it, open its row and move focus there.
function openEndpoint(ip) {
  const secEl = el('an-sec-endpoints');
  if (!secEl) return;
  secEl.open = true;
  let row = qs(`.an-slave-row[data-ip="${CSS.escape(ip)}"]`);
  if (!row) {
    an.filter = '';
    an.verdict = '';
    const q = el('an-ep-q');
    const v = el('an-ep-verdict');
    if (q) q.value = '';
    if (v) v.value = '';
    renderEndpointRows();
    row = qs(`.an-slave-row[data-ip="${CSS.escape(ip)}"]`);
  }
  if (!row) return;
  row.open = true;
  const sum = qs('summary', row);
  row.scrollIntoView({ block: 'start', behavior: 'auto' });
  if (sum) sum.focus({ preventScroll: true });
  announce(`Endpoint ${ip} opened`);
}

// ---------------------------------------------------------------------------
// Dimension summary from the report's summary data (no endpoint detail
// is needed): how many endpoints pass each check.

function pctile(arr, f) {
  if (!arr.length) return 0;
  const a = arr.slice().sort((x, y) => x - y);
  return a[Math.min(a.length - 1, Math.floor(f * a.length))];
}

function dimensionsHtml(r) {
  const slaves = r.slaves || [];
  const f = r.fleet || {};
  const n = slaves.length;
  const rows = [];
  // {label, pass, of, tone, value, note}
  const add = o => rows.push(o);
  if (n) {
    const connected = slaves.filter(s => (s.sessions || 0) > 0 || s.packets > 0).length;
    add({ label: 'Connected', pass: connected, of: n, note: f.never_connected ? `${fmtInt(f.never_connected)} never connected` : 'every endpoint connected' });
    const hs = slaves.filter(s => s.startdt_handshake_ok).length;
    add({ label: 'STARTDT handshake', pass: hs, of: connected || n, note: hs === connected ? 'completed everywhere it connected' : `${fmtInt(connected - hs)} missing` });
    const withExp = slaves.filter(s => s.expected_iframes > 0);
    const full = withExp.filter(s => s.delivered_iframes >= s.expected_iframes).length;
    const exp = withExp.reduce((a, s) => a + s.expected_iframes, 0);
    const del = withExp.reduce((a, s) => a + Math.min(s.delivered_iframes, s.expected_iframes), 0);
    add({ label: 'Delivery', pass: full, of: withExp.length || n, note: `${fmtInt(del)} of ${fmtInt(exp)} messages delivered${exp ? ` (${(100 * del / exp).toFixed(1)}%)` : ''}` });
    const exact = slaves.filter(s => Number(s.score_pct) >= 99.95).length;
    add({ label: 'Content', pass: exact, of: n, note: `mean score ${Number(f.aggregate_score_pct != null ? f.aggregate_score_pct : r.score_pct).toFixed(1)}%` });
    const outcomePass = slaves.filter(s => outcomeCls(s.outcome, s.verdict) === 'ok').length;
    add({ label: 'Verdict', pass: outcomePass, of: n, note: 'every dimension of the endpoint passed' });
  }
  const g = r.fleet_gi_ci_audit;
  if (g && ((g.gi_total || 0) + (g.ci_total || 0)) > 0) {
    const tot = (g.gi_total || 0) + (g.ci_total || 0);
    const ok = (g.gi_compliant || 0) + (g.ci_compliant || 0);
    add({ label: 'GI / CI answers', pass: ok, of: tot, unit: 'events', note: `${fmtInt(g.gi_total || 0)} GI, ${fmtInt(g.ci_total || 0)} CI requests` });
  }
  if (f.reconnects != null) add({ label: 'Reconnects', value: fmtInt(f.reconnects), tone: f.reconnects ? 'warn' : 'ok', note: f.reconnects ? 'extra TCP sessions beyond the expected count' : 'no extra TCP sessions' });
  const tl = (t, label, what) => {
    if (!t || !t.samples || !t.samples.length) return;
    const ys = t.samples.map(x => Number(x[1])).filter(Number.isFinite);
    const p50 = pctile(ys, 0.5);
    const p95 = pctile(ys.map(Math.abs), 0.95);
    add({ label, value: `${p50 >= 0 ? '+' : ''}${p50.toFixed(1)} ms`, tone: 'muted', note: `median ${what}; 95% within ±${p95.toFixed(1)} ms` });
  };
  tl(r.fleet_pacing_timeline, 'Pacing', 'lateness against the captured pace');
  tl(r.fleet_drift_timeline, 'CP56 time tags', 'stamp minus wire time');
  let h = '<section class="card an-dimsum" aria-labelledby="an-dimsum-title"><h4 id="an-dimsum-title">Dimensions</h4>';
  if (!rows.length) return h + '<p class="hint">Nothing to summarise.</p></section>';
  h += '<ul class="dim-list">';
  for (const d of rows) {
    let tone = d.tone;
    let val = d.value;
    let bar = '';
    if (d.of != null) {
      const frac = d.of ? d.pass / d.of : 0;
      tone = tone || (d.of === 0 ? 'muted' : frac >= 1 ? 'ok' : (d.pass === 0 ? 'bad' : 'warn'));
      val = `${fmtInt(d.pass)}<span class="of"> / ${fmtInt(d.of)}</span>`;
      // Passing share in green, the rest in the row's tone.
      bar = `<span class="dim-bar" aria-hidden="true"><span class="seg-pass" style="flex:${d.pass}"></span><span class="seg-rest t-${tone === 'ok' ? 'muted' : tone}" style="flex:${Math.max(0, d.of - d.pass)}"></span></span>`;
    }
    const sr = d.of != null ? `<span class="sr-only">${TONE_WORD[tone] || ''}: ${d.pass} of ${d.of} ${d.unit || 'endpoints'}</span>` : '';
    h += `<li class="dim-row tone-${tone}"><span class="dim-mark ${tone}" aria-hidden="true">${TONE_MARK[tone] || ''}</span>` +
      `<span class="dim-label">${esc(d.label)}</span>${bar || '<span class="dim-bar dim-bar-none" aria-hidden="true"></span>'}<span class="dim-val ${tone}"${d.of != null ? ' aria-hidden="true"' : ''}>${val}</span>${sr}` +
      `<span class="dim-note">${esc(d.note || '')}</span></li>`;
  }
  return h + '</ul></section>';
}

function fleetChartBlock(tl, key, heading, legend, axes) {
  if (!tl || !tl.samples || !tl.samples.length) return '';
  const iters = (tl.iteration_starts_ms || []).length;
  const note = (iters > 1 ? ` · ${iters} loop iterations marked` : '') +
    (tl.decimated ? ` · decimated from ${fmtInt(tl.total_samples)} samples` : ` · ${fmtInt(tl.total_samples)} samples`);
  // Key numbers for assistive tech (F126): the chart itself is a canvas.
  const ys = tl.samples.map(s => Number(s[1])).filter(Number.isFinite).sort((a, b) => a - b);
  const q = f => ys.length ? ys[Math.min(ys.length - 1, Math.floor(f * ys.length))] : 0;
  const maxAbs = ys.length ? Math.max(Math.abs(ys[0]), Math.abs(ys[ys.length - 1])) : 0;
  const label = `${heading}: ${fmtInt(tl.total_samples || ys.length)} samples, median ${q(0.5).toFixed(1)} ms, ` +
    `5th to 95th percentile ${q(0.05).toFixed(1)} to ${q(0.95).toFixed(1)} ms, largest ${maxAbs.toFixed(1)} ms.`;
  return `<figure class="an-figure"><figcaption id="an-${key}-cap"><h4>${esc(heading)}</h4><p class="hint">${esc(legend)}${esc(note)}</p><p class="hint" id="an-${key}-axes">${esc(axes)}</p></figcaption>` +
    `<div id="an-${key}-chart" class="an-chart" role="img" aria-label="${esc(label)}" aria-describedby="an-${key}-cap"></div><div id="an-${key}-stats" class="an-chart-stats"></div></figure>`;
}

function endpointTableShell(r) {
  const n = (r.slaves || []).length;
  if (!n) return '<p class="hint">No endpoints to report.</p>';
  const verdicts = Array.from(new Set(r.slaves.map(s => s.verdict)));
  return '<div class="sess-toolbar">' +
      `<div class="field"><label for="an-ep-q">Find</label><input id="an-ep-q" type="search" placeholder="IP" value="${esc(an.filter)}" spellcheck="false" autocomplete="off"></div>` +
      `<div class="field"><label for="an-ep-verdict">Verdict</label><select id="an-ep-verdict"><option value="">All</option>${verdicts.map(v => `<option value="${esc(v)}"${an.verdict === v ? ' selected' : ''}>${esc(v.replace(/_/g, ' '))}</option>`).join('')}</select></div>` +
    '</div>' +
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
      `<span class="${outcomeCls(s.outcome, s.verdict)}"><b>${Number(s.score_pct).toFixed(1)}%</b><span class="sr-only"> (${esc(s.outcome || 'unknown')})</span></span>` +
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
// Fleet charts are built when their section is first opened (a closed
// <details> has no size to draw into).
document.addEventListener('toggle', e => {
  const node = e.target;
  if (node.id !== 'an-sec-timing' || !node.open || node.dataset.charts || !an.report) return;
  node.dataset.charts = '1';
  initFleetTimelineChart(an.report.fleet_pacing_timeline, 'fleet-pacing');
  initFleetTimelineChart(an.report.fleet_drift_timeline, 'fleet-drift');
}, true);

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
    const res = await api(`api/analyses/${an.analysisId}/endpoints/${encodeURIComponent(ip)}`);
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
  on('theme', rerenderAnalysisForTheme);
  // Capture names come from the library; it may load after the report.
  on('library', () => { if (S.view === 'analysis' && !isBusyIn(el('an-result'))) rerenderAnalysisForTheme(); });
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
  const chart = echarts.init(node, chartTheme(), { renderer: 'canvas' });
  const C = n => getCssVar(n);
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
    lineStyle: { type: 'dashed', color: C('--dim'), width: 1 },
    label: { color: C('--dim'), fontSize: 11, formatter: p => p.data.label },
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
    let html = '<div class="tt">';
    html += `<div class="tt-head">t = ${Number(t).toFixed(2)} s</div>`;
    if (scatterEntry && scatterEntry.value) {
      const y = scatterEntry.value[1];
      html += `<div><span class="tt-sw tt-sample"></span>sample: ${Number(y).toFixed(2)} ms</div>`;
    }
    if (meanY !== null) html += `<div><span class="tt-line tt-mean"></span>mean: <b>${meanY.toFixed(2)} ms</b></div>`;
    if (p95Y !== null)  html += `<div><span class="tt-line tt-dash tt-p95"></span>p95 (upper):&nbsp; ${p95Y.toFixed(2)} ms</div>`;
    if (p05Y !== null)  html += `<div><span class="tt-line tt-dash tt-p05"></span>p05 (lower):&nbsp; ${p05Y.toFixed(2)} ms</div>`;
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
          backgroundColor: C('--ink'),
          color: C('--on-ink'),
          fontSize: 11,
          formatter: (p) => {
            // axis label on the cross hair lines.
            const v = (typeof p.value === 'number') ? p.value : Number(p.value);
            const unit = p.axisDimension === 'x' ? 's' : 'ms';
            return `${v.toFixed(2)} ${unit}`;
          },
        },
      },
      borderWidth: 1,
      padding: [8, 12],
      formatter: tooltipFmt,
    },
    legend: {
      top: 6, left: 8,
      textStyle: { fontSize: 11 },
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
      nameTextStyle: { fontSize: 11 },
    },
    yAxis: {
      type: 'value',
      name: 'ms',
      nameLocation: 'middle',
      nameGap: 48,
      nameTextStyle: { fontSize: 11 },
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
        itemStyle: { color: C('--ch-sample'), opacity: 0.35 },
        data,
        large: true,
        largeThreshold: 1000,
        z: 1,
      },
      {
        name: '┄┄ p95 upper',
        type: 'line',
        data: p95Line,
        lineStyle: { color: C('--ch-p95'), width: 1.2, type: 'dashed' },
        itemStyle: { color: C('--ch-p95') },
        showSymbol: false,
        smooth: true,
        z: 2,
      },
      {
        name: '┄┄ p05 lower',
        type: 'line',
        data: p05Line,
        lineStyle: { color: C('--ch-p05'), width: 1.2, type: 'dashed' },
        itemStyle: { color: C('--ch-p05') },
        showSymbol: false,
        smooth: true,
        z: 3,
      },
      {
        name: '── mean (per-bucket)',
        type: 'line',
        data: meanLine,
        lineStyle: { color: C('--ch-mean'), width: 2.5 },
        itemStyle: { color: C('--ch-mean') },
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
