// 70-compare.js — run-to-run comparison (#/compare/<A>/<B>?thresholds):
// two benchmark-run pickers, regression thresholds mapped to the query
// parameters of GET /api/runs/:a/compare/:b, the fleet summary with
// deltas, a sortable and filterable per-RTU table with regressions
// highlighted, the only-in-A/B lists and the regressions list. A run
// without a stored analysis (409 analysis_missing) can be analysed from
// here (POST /api/runs/:id/analyze), after which the comparison is
// retried by itself. The selection lives in the URL hash, so a
// comparison can be shared as a link.
'use strict';

// Threshold query parameters: [key, label, server default, unit hint].
const CMP_TH = [
  ['score_drop', 'Score drop (points)', 1, 'A fall in score of more than this many percentage points.'],
  ['delivered_drop', 'Delivered drop (points)', 1, 'A fall in delivered I-frames of more than this many percentage points.'],
  ['p50_increase_pct', 'p50 latency rise (%)', 20, 'A relative rise of the median ack latency above this.'],
  ['p99_increase_pct', 'p99 latency rise (%)', 20, 'A relative rise of the p99 ack latency above this.'],
  ['latency_min_us', 'Latency noise floor (µs)', 1000, 'Latency rises smaller than this are never flagged.'],
  ['throughput_drop_pct', 'Throughput drop (%)', 10, 'A relative fall of the fleet throughput above this.'],
];
const CMP_ROWS_PER_PAGE = 50;

const cmp = {
  a: null, b: null, th: {}, data: null, seq: 0,
  busy: new Set(),           // run ids being analysed
  sort: 'problems', dir: 1, q: '', onlyReg: false, onlyChanged: false, page: 0,
};

const cmpRunOk = r => r && r.mode === 'benchmark';

// ---------------------------------------------------------------------------
// Form, pickers, hash.

function renderCmpThresholds() {
  const grid = el('cmp-th-grid');
  if (grid.childElementCount) return;
  grid.innerHTML = CMP_TH.map(([k, label, dflt, hint]) =>
    `<div class="field"><label for="cmp-th-${k}">${esc(label)}</label>` +
    `<input id="cmp-th-${k}" type="number" min="0" step="any" placeholder="${dflt}" data-th="${k}" aria-describedby="cmp-th-${k}-hint cmp-th-${k}-err">` +
    `<p class="hint" id="cmp-th-${k}-hint">${esc(hint)}</p><p class="field-err" id="cmp-th-${k}-err"></p></div>`).join('');
}

function fillCmpThresholds() {
  for (const [k] of CMP_TH) {
    const n = el('cmp-th-' + k);
    if (n) n.value = cmp.th[k] ?? '';
  }
  const set = Object.keys(cmp.th).length;
  setText(el('cmp-th-sum'), set ? `${plural(set, 'threshold')} changed from the defaults` : 'server defaults');
  if (set) el('cmp-th').open = true;
}

function readCmpThresholds() {
  const th = {};
  let bad = null;
  for (const [k, label] of CMP_TH) {
    const raw = val('cmp-th-' + k);
    let msg = '';
    if (raw !== '') {
      const v = Number(raw);
      if (!Number.isFinite(v) || v < 0) msg = `${label.replace(/ \(.*\)$/, '')} must be a number of 0 or more.`;
      else th[k] = raw;
    }
    fieldError('cmp-th-' + k, msg);
    if (msg && !bad) bad = 'cmp-th-' + k;
  }
  return { th, bad };
}

function cmpRunLabel(r) {
  const la = r.latest_analysis;
  const an = la ? `analysed: ${String(la.verdict).replace(/_/g, ' ')} ${Number(la.score).toFixed(1)}%` : 'not analysed';
  return `${runNum(r.id)} · ${r.status} · ${r.role} · ${libraryName(r.pcap_id, r.pcap)} · ${fmtClock(r.started_at)} · ${an}`;
}

function renderCmpPickers() {
  const runs = S.runs.filter(cmpRunOk);
  for (const side of ['a', 'b']) {
    const sel = el('cmp-' + side);
    const want = cmp[side] == null ? '' : String(cmp[side]);
    let h = `<option value="">${runs.length ? 'Select a run…' : (S.runsLoaded ? 'No benchmark runs yet' : 'Loading runs…')}</option>`;
    for (const r of runs) {
      const running = r.status === 'running';
      h += `<option value="${r.id}"${running ? ' disabled' : ''}>${esc(cmpRunLabel(r))}${running ? ' (still running)' : ''}</option>`;
    }
    // A run from a shared link that this list does not have (deleted,
    // or not a benchmark run): keep it visible so the error makes sense.
    if (want && S.runsLoaded && !runs.some(r => String(r.id) === want)) h += `<option value="${esc(want)}">${esc(runNum(want))} (not a benchmark run in this server's history)</option>`;
    if (setHTML(sel, h) || sel.value !== want) sel.value = want;
  }
}

function cmpHash() {
  const q = new URLSearchParams();
  for (const [k] of CMP_TH) if (cmp.th[k] != null && cmp.th[k] !== '') q.set(k, cmp.th[k]);
  const qs2 = q.toString();
  return `#/compare/${cmp.a ?? ''}/${cmp.b ?? ''}${qs2 ? '?' + qs2 : ''}`;
}

// Keep the address bar in step with the form without a navigation.
function syncCmpHash() {
  const h = cmpHash();
  if (location.hash !== h) {
    try { history.replaceState(null, '', h); } catch (_) { /* sandboxed: keep the old hash */ }
  }
}

function onCmpRoute({ args, query }) {
  renderCmpThresholds();
  const num = x => (x && /^\d+$/.test(x) ? Number(x) : null);
  const a = num(args && args[0]);
  const b = num(args && args[1]);
  const th = {};
  for (const [k] of CMP_TH) {
    const v = query && query.get(k);
    if (v != null && v !== '') th[k] = v;
  }
  const same = a === cmp.a && b === cmp.b && JSON.stringify(th) === JSON.stringify(cmp.th);
  cmp.a = a;
  cmp.b = b;
  cmp.th = th;
  fillCmpThresholds();
  renderCmpPickers();
  if (a != null && b != null) {
    if (!same || !cmp.data) runCompare();
  } else {
    cmp.data = null;
    setHTML(el('cmp-result'), '', { force: true });
    setCmpError('');
    setText(el('cmp-msg'), a == null && b == null ? 'Pick a baseline run (A) and a candidate run (B).' : `Pick the ${a == null ? 'baseline run (A)' : 'candidate run (B)'}.`);
  }
}

function setCmpError(html) {
  setHTML(el('cmp-error'), html, { force: true });
}

async function submitCompare(e) {
  if (e) e.preventDefault();
  const a = Number(el('cmp-a').value) || null;
  const b = Number(el('cmp-b').value) || null;
  fieldError('cmp-a', a ? '' : 'Select the baseline run.');
  fieldError('cmp-b', b ? (a === b ? 'Pick a different run than A.' : '') : 'Select the run to compare.');
  const { th, bad } = readCmpThresholds();
  if (!a || !b || a === b || bad) {
    const first = !a ? 'cmp-a' : (!b || a === b ? 'cmp-b' : bad);
    if (first.startsWith('cmp-th')) el('cmp-th').open = true;
    el(first).focus();
    return;
  }
  cmp.a = a;
  cmp.b = b;
  cmp.th = th;
  fillCmpThresholds();
  syncCmpHash();
  await runCompare();
}

// ---------------------------------------------------------------------------
// Fetch and the analysis_missing → analyze → retry path.

async function runCompare() {
  const { a, b } = cmp;
  if (a == null || b == null) return;
  if (a === b) { setCmpError('<div class="err-box">Pick two different runs.</div>'); return; }
  const seq = ++cmp.seq;
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(cmp.th)) q.set(k, v);
  setText(el('cmp-msg'), `Comparing ${runNum(a)} with ${runNum(b)}…`);
  setCmpError('');
  el('cmp-btn').disabled = true;
  const res = await api(`/api/runs/${a}/compare/${b}${q.toString() ? '?' + q : ''}`, 'GET', null, { timeout: 60000 });
  if (seq !== cmp.seq) return;
  el('cmp-btn').disabled = false;
  if (res.ok && res.data && typeof res.data === 'object') {
    cmp.data = res.data;
    cmp.page = 0;
    const n = (res.data.regressions || []).length;
    setText(el('cmp-msg'), `Compared ${runNum(a)} (A) with ${runNum(b)} (B): ${n ? plural(n, 'regression') : 'no regressions'}.`);
    renderCmpResult();
    announce(n ? `${n} regressions found` : 'No regressions');
    return;
  }
  cmp.data = null;
  setHTML(el('cmp-result'), '', { force: true });
  setText(el('cmp-msg'), '');
  showCompareFailure(res);
}

function showCompareFailure(res) {
  const d = (res.data && typeof res.data === 'object') ? res.data : {};
  if (res.code === 'analysis_missing') {
    const id = d.run_id;
    const side = id === cmp.a ? 'baseline A' : (id === cmp.b ? 'candidate B' : 'run');
    let h = `<div class="warn-box cmp-missing"><p><b>Run #${esc(id)} (${side}) has no stored analysis</b>, so it cannot be compared yet.</p>`;
    if (d.has_capture) {
      const busy = cmp.busy.has(id);
      h += `<p>Its replay capture is on the server. Analysing it takes from seconds to a few minutes; the comparison then runs again by itself.</p>` +
        `<p class="btn-row"><button type="button" class="btn btn-primary" data-act="cmp-analyze" data-id="${esc(id)}" data-fk="cmp-analyze-${esc(id)}"${busy ? ' disabled' : ''}>${busy ? `Analysing run #${esc(id)}…` : `Analyze run #${esc(id)}`}</button></p>`;
    } else {
      h += `<p>It has no replay capture to analyse (slave-mode runs, and runs that failed before sending, have none). Upload a capture taken on the target side in <a href="#/analysis/${esc(id)}">Analysis for run #${esc(id)}</a>, then compare again.</p>` +
        '<p class="btn-row"><button type="button" class="btn btn-secondary" data-act="cmp-retry" data-fk="cmp-retry">Compare again</button></p>';
    }
    setCmpError(h + '</div>');
    return;
  }
  let why = '';
  if (res.code === 'run_running') why = 'Compare it once it has finished.';
  else if (res.code === 'not_benchmark') why = 'Only stateful (benchmark) runs can be compared; raw L2 replays have no per-RTU results.';
  else if (res.code === 'not_found') why = 'The run, or the analysis chosen for it, no longer exists.';
  else if (res.code === 'invalid_query') {
    const k = CMP_TH.map(t => t[0]).find(key => String(res.error).includes(key));
    if (k) { el('cmp-th').open = true; fieldError('cmp-th-' + k, res.error); }
  }
  setCmpError(`<div class="err-box"><p>Comparison failed: ${esc(res.error)}</p>${why ? `<p class="hint-strong">${esc(why)}</p>` : ''}` +
    '<p class="btn-row"><button type="button" class="btn btn-secondary" data-act="cmp-retry" data-fk="cmp-retry">Try again</button></p></div>');
}

async function cmpAnalyze(id, btn) {
  if (cmp.busy.has(id)) return;
  cmp.busy.add(id);
  if (btn) { btn.disabled = true; btn.textContent = `Analysing run #${id}…`; }
  setText(el('cmp-msg'), `Analysing the replay capture of run #${id}…`);
  const res = await api(`/api/runs/${id}/analyze`, 'POST', null, { timeout: 0 });
  cmp.busy.delete(id);
  if (!res.ok || !res.data) {
    setText(el('cmp-msg'), '');
    const hint = typeof analyzeErrorHint === 'function' ? analyzeErrorHint(res.code) : '';
    setCmpError(`<div class="err-box"><p>Analysis of run #${esc(id)} failed: ${esc(res.error || 'bad reply')}</p>${hint ? `<p class="hint-strong">${esc(hint)}</p>` : ''}` +
      `<p class="btn-row"><button type="button" class="btn btn-secondary" data-act="cmp-analyze" data-id="${esc(id)}" data-fk="cmp-analyze-${esc(id)}">Try again</button>` +
      '<button type="button" class="btn btn-text" data-act="cmp-retry" data-fk="cmp-retry">Compare again</button></p></div>');
    return;
  }
  const v = String(res.data.verdict || '').replace(/_/g, ' ');
  notify(`Run #${id} analysed: ${v} ${Number(res.data.score_pct).toFixed(1)}%`, 'ok');
  announce(`Run ${id} analysed`);
  S.runDetail.delete(id);
  pollRunsSoon();
  await runCompare();   // automatic retry
}

actions({
  'cmp-analyze': b => cmpAnalyze(Number(b.dataset.id), b),
  'cmp-retry': () => runCompare(),
  'cmp-swap': () => {
    const a = el('cmp-a').value;
    el('cmp-a').value = el('cmp-b').value;
    el('cmp-b').value = a;
    cmp.a = Number(el('cmp-a').value) || null;
    cmp.b = Number(el('cmp-b').value) || null;
    syncCmpHash();
    if (cmp.a && cmp.b && cmp.a !== cmp.b) runCompare();
  },
  'cmp-sort': b => {
    const k = b.dataset.key;
    if (cmp.sort === k) cmp.dir = -cmp.dir;
    else { cmp.sort = k; cmp.dir = 1; }
    renderCmpRows();
  },
  'cmp-page': b => { cmp.page = Number(b.dataset.page); renderCmpRows(); },
  'cmp-show-rtu': b => {
    cmp.q = b.dataset.rtu;
    cmp.onlyReg = false;
    cmp.page = 0;
    const q = el('cmp-q');
    if (q) q.value = cmp.q;
    const r = el('cmp-only-reg');
    if (r) r.checked = false;
    renderCmpRows();
    const t = el('cmp-rtu-section');
    if (t) t.scrollIntoView({ block: 'start' });
  },
});

// ---------------------------------------------------------------------------
// Rendering.

const isNum = v => typeof v === 'number' && isFinite(v);
const fmtPct = v => (isNum(v) ? v.toFixed(1) + '%' : '—');
// Latency in ms with one decimal (µs below 0.1 ms, where that rounds to 0).
const msFmt = us => (Math.abs(us) < 100 ? fmtInt(us) + ' µs' : (us / 1000).toLocaleString(undefined, { minimumFractionDigits: 1, maximumFractionDigits: 1 }) + ' ms');
const fmtLat = v => (isNum(v) ? msFmt(v) : '—');
// Display names of the regression metric ids (the server sends `label`
// too; this covers older responses).
const METRIC_LABELS = { score: 'Score', delivered_pct: 'Delivered', p50_us: 'Ack p50', p99_us: 'Ack p99', throughput: 'Throughput', sessions_failed: 'Failed sessions', errors: 'Failed sessions', verdict: 'Verdict', missing_in_b: 'Missing in B' };
const metricLabel = m => METRIC_LABELS[m] || String(m).replace(/_/g, ' ');
const rateNum = v => (Math.abs(v) >= 100 ? fmtInt(v) : fmt(v));
const fmtRate = v => (isNum(v) ? rateNum(v) + ' msg/s' : '—');

// Signed delta with a better/worse cue that does not rely on colour.
function deltaHtml(dv, better, fmtFn) {
  if (!isNum(dv)) return '<span class="muted">—</span>';
  if (dv === 0) return '<span class="dl-same">±0</span>';
  const s = (dv > 0 ? '+' : '−') + fmtFn(Math.abs(dv));
  if (!better) return `<span class="dl-same">${esc(s)}</span>`;
  const good = better === 'up' ? dv > 0 : dv < 0;
  return `<span class="${good ? 'dl-good' : 'dl-bad'}">${esc(s)}<span class="sr-only"> (${good ? 'better' : 'worse'})</span></span>`;
}

const pts = v => v.toFixed(2) + ' pt';
const FLEET_ROWS = [
  // key, label, better, value formatter, delta formatter, regression metric
  ['score', 'Score', 'up', fmtPct, pts, 'score'],
  ['frame_weighted_score', 'Frame-weighted score', 'up', fmtPct, pts],
  ['delivered_pct', 'Delivered', 'up', fmtPct, pts, 'delivered_pct'],
  ['delivered', 'Delivered I-frames', 'up', fmtInt, fmtInt],
  ['expected', 'Expected I-frames', null, fmtInt, fmtInt],
  ['rtus', 'RTUs analysed', null, fmtInt, fmtInt],
  ['fully_correct', 'All correct', 'up', fmtInt, fmtInt],
  ['partial', 'Partial', 'down', fmtInt, fmtInt],
  ['failed', 'Failed', 'down', fmtInt, fmtInt],
  ['never_connected', 'Never connected', 'down', fmtInt, fmtInt],
  ['sessions', 'Sessions', null, fmtInt, fmtInt],
  ['sessions_failed', 'Failed sessions', 'down', fmtInt, fmtInt, 'sessions_failed'],
  ['msgs_sent', 'Messages sent', null, fmtInt, fmtInt],
  ['msgs_received', 'Messages received', null, fmtInt, fmtInt],
  ['p50_us', 'Ack latency p50', 'down', fmtLat, msFmt, 'p50_us'],
  ['p90_us', 'Ack latency p90', 'down', fmtLat, msFmt],
  ['p99_us', 'Ack latency p99', 'down', fmtLat, msFmt, 'p99_us'],
  ['max_us', 'Ack latency max', 'down', fmtLat, msFmt],
  ['throughput', 'Throughput', 'up', fmtRate, v => rateNum(v) + ' msg/s', 'throughput'],
];

function sideHtml(label, s, run) {
  if (!s) return '';
  const name = libraryName(s.pcap_id, run && run.pcap);
  return `<div class="cmp-side"><p class="cmp-side-label">${esc(label)}</p>` +
    `<p class="cmp-side-run"><a href="#/runs/${esc(s.run_id)}">${runNum(s.run_id)}</a> <span class="status s-${esc(s.status)}">${esc(s.status)}</span></p>` +
    `<p class="meta-line">${esc(s.role)} role · ${esc(name)} · started ${esc(fmtClock(s.started_at))}</p>` +
    `<p class="meta-line">Analysis <a href="#/analysis/${esc(s.run_id)}/${esc(s.analysis_id)}">#${esc(s.analysis_id)}</a>${s.analysis_source ? ` (${esc(String(s.analysis_source).replace(/_/g, '-'))})` : ''}</p></div>`;
}

function renderCmpResult() {
  const d = cmp.data;
  const f = d.fleet || {};
  const fa = f.a || {};
  const fb = f.b || {};
  const fd = f.delta || {};
  const regs = d.regressions || [];
  const fleetRegs = new Set(regs.filter(r => r.scope === 'fleet').map(r => r.metric));
  const runA = S.runs.find(x => x.id === (d.a && d.a.run_id));
  const runB = S.runs.find(x => x.id === (d.b && d.b.run_id));
  let h = '<div class="card cmp-card">';
  h += `<div class="cmp-sides">${sideHtml('A · baseline', d.a, runA)}<span class="cmp-arrow" aria-hidden="true">→</span>${sideHtml('B · candidate', d.b, runB)}</div>`;
  h += d.regressed
    ? `<div class="err-box cmp-verdict"><b>${plural(regs.length, 'regression')}</b> from A to B at these thresholds${fleetRegs.size ? `, ${fleetRegs.size} of them fleet-wide` : ''}.</div>`
    : '<div class="ok-box cmp-verdict"><b>No regressions</b> from A to B at these thresholds.</div>';
  if ((d.warnings || []).length) h += '<div class="warn-box"><ul>' + d.warnings.map(w => `<li>${esc(w)}</li>`).join('') + '</ul></div>';
  if (d.a && d.b && d.a.pcap_id && d.b.pcap_id && d.a.pcap_id !== d.b.pcap_id) {
    h += '<div class="warn-box">The two runs replayed different pcaps; per-RTU deltas compare different scripts.</div>';
  }

  // Fleet summary.
  h += '<h3 class="card-title cmp-h">Fleet</h3><div class="table-scroll"><table class="t cmp-fleet"><caption class="sr-only">Fleet figures of run A and run B with the change from A to B</caption>' +
    '<thead><tr><th scope="col">Metric</th><th scope="col" class="num">A</th><th scope="col" class="num">B</th><th scope="col" class="num">Change (B − A)</th></tr></thead><tbody>';
  const vChanged = f.verdict_changed;
  h += `<tr${fleetRegs.has('verdict') ? ' class="row-problem"' : ''}><th scope="row">Verdict${fleetRegs.has('verdict') ? ' <span class="reg-tag">regression</span>' : ''}</th><td class="num">${fa.verdict ? verdictHtml(fa.verdict) : '—'}</td><td class="num">${fb.verdict ? verdictHtml(fb.verdict) : '—'}</td>` +
    `<td class="num">${vChanged ? `<span class="${fleetRegs.has('verdict') ? 'dl-bad' : 'dl-same'}">changed</span>` : '<span class="dl-same">same</span>'}</td></tr>`;
  for (const [k, label, better, vf, df, metric] of FLEET_ROWS) {
    const a = fa[k];
    const b = fb[k];
    if (a == null && b == null) continue;
    const dv = fd[k] != null ? fd[k] : (isNum(a) && isNum(b) ? b - a : null);
    const reg = metric && fleetRegs.has(metric);
    h += `<tr${reg ? ' class="row-problem"' : ''}><th scope="row">${esc(label)}${reg ? ' <span class="reg-tag">regression</span>' : ''}</th>` +
      `<td class="num">${esc(vf(a))}</td><td class="num">${esc(vf(b))}</td><td class="num">${deltaHtml(dv, better, df)}</td></tr>`;
  }
  h += '</tbody></table></div>';

  // Regressions.
  if (regs.length) {
    const head = regs.slice(0, 20);
    const item = r => `<li><span class="reg-metric">${esc(r.rtu ? 'RTU' : 'Fleet')}</span> ${esc(r.message)}` +
      (r.rtu ? ` <button type="button" class="btn btn-text" data-act="cmp-show-rtu" data-rtu="${esc(r.rtu)}" aria-label="Show RTU ${esc(r.rtu)} in the table">show</button>` : '') + '</li>';
    h += `<h3 class="card-title cmp-h">Regressions (${regs.length})</h3><ol class="cmp-regs">${head.map(item).join('')}</ol>`;
    if (regs.length > head.length) {
      h += `<details class="cmp-more"><summary>Show the other ${regs.length - head.length}</summary><ol class="cmp-regs" start="${head.length + 1}">${regs.slice(head.length).map(item).join('')}</ol></details>`;
    }
  }

  // Per-RTU table (rows filled by renderCmpRows).
  const rtus = d.rtus || [];
  h += `<section id="cmp-rtu-section" aria-labelledby="cmp-rtu-h"><h3 class="card-title cmp-h" id="cmp-rtu-h">Per RTU (${fmtInt(rtus.length)} in both runs)</h3>`;
  h += '<div class="sess-toolbar cmp-toolbar">' +
    `<div class="field"><label for="cmp-q">Find RTU</label><input id="cmp-q" type="search" placeholder="IP" value="${esc(cmp.q)}" spellcheck="false" autocomplete="off"></div>` +
    `<label class="check"><input type="checkbox" id="cmp-only-reg"${cmp.onlyReg ? ' checked' : ''}> Only regressions</label>` +
    `<label class="check"><input type="checkbox" id="cmp-only-changed"${cmp.onlyChanged ? ' checked' : ''}> Only verdict changes</label>` +
    '<span class="picker-count" id="cmp-count" role="status" aria-live="polite"></span></div>';
  h += '<div class="table-scroll"><table class="t cmp-rtus"><caption class="sr-only">Per-RTU figures, A to B; rows with regressions are marked</caption>' +
    '<thead id="cmp-thead"></thead><tbody id="cmp-tbody"></tbody></table></div><div class="pager" id="cmp-pager"></div>';
  const oa = d.only_in_a || [];
  const ob = d.only_in_b || [];
  if (oa.length || ob.length) {
    h += '<div class="cmp-only">';
    if (oa.length) h += `<details${oa.length <= 20 ? ' open' : ''}><summary><b class="bad">${plural(oa.length, 'RTU')} only in A</b> (missing from B; each is a regression)</summary><p class="cmp-ips">${oa.map(ip => `<code>${esc(ip)}</code>`).join(' ')}</p></details>`;
    if (ob.length) h += `<details${ob.length <= 20 ? ' open' : ''}><summary><b>${plural(ob.length, 'RTU')} only in B</b> (new in B)</summary><p class="cmp-ips">${ob.map(ip => `<code>${esc(ip)}</code>`).join(' ')}</p></details>`;
    h += '</div>';
  }
  h += '</section>';
  const t = d.thresholds;
  if (t) {
    h += `<p class="hint cmp-th-used">Thresholds used: score drop &gt; ${esc(t.score_drop)} pt · delivered drop &gt; ${esc(t.delivered_drop)} pt · ` +
      `p50 rise &gt; ${esc(t.p50_increase_pct)}% · p99 rise &gt; ${esc(t.p99_increase_pct)}% (and &gt; ${esc(t.latency_min_us)} µs) · throughput drop &gt; ${esc(t.throughput_drop_pct)}%.</p>`;
  }
  h += '</div>';
  setHTML(el('cmp-result'), h, { force: true });
  renderCmpRows();
}

const CMP_COLS = [
  // key, header, sort value
  ['rtu', 'RTU', x => ipToInt(x.rtu)],
  ['verdict', 'Verdict A → B', x => (x.verdict_changed ? 0 : 1)],
  ['score', 'Score', x => x.delta.score],
  ['delivered', 'Delivered', x => x.delta.delivered_pct],
  ['p50', 'Ack p50', x => x.delta.p50_us],
  ['p99', 'Ack p99', x => x.delta.p99_us],
  ['errors', 'Failed sessions', x => x.delta.errors],
  ['problems', 'Regressed', x => -(x.regressions || []).length],
];

function cmpCell(a, b, dv, better, vf, df, reg) {
  if (a == null && b == null) return '<td class="num"><span class="muted">—</span></td>';
  return `<td class="num${reg ? ' reg' : ''}"><span class="ab">${esc(vf(a))} → ${esc(vf(b))}</span> ${deltaHtml(dv, better, df)}${reg ? '<span class="sr-only"> (regression)</span>' : ''}</td>`;
}

function renderCmpRows() {
  const tbody = el('cmp-tbody');
  if (!tbody || !cmp.data) return;
  const all = cmp.data.rtus || [];
  const q = cmp.q;
  let rows = all.filter(x => (!q || x.rtu.includes(q)) && (!cmp.onlyReg || (x.regressions || []).length) && (!cmp.onlyChanged || x.verdict_changed));
  const col = CMP_COLS.find(c => c[0] === cmp.sort) || CMP_COLS[CMP_COLS.length - 1];
  const key = col[2];
  const nv = v => (isNum(v) ? v : Infinity);
  rows = rows.slice().sort((x, y) => (cmp.dir * (nv(key(x)) - nv(key(y)))) || (nv(key(x)) === Infinity) - (nv(key(y)) === Infinity) || (ipToInt(x.rtu) - ipToInt(y.rtu)));
  const pages = Math.max(1, Math.ceil(rows.length / CMP_ROWS_PER_PAGE));
  cmp.page = Math.min(cmp.page, pages - 1);
  const page = rows.slice(cmp.page * CMP_ROWS_PER_PAGE, (cmp.page + 1) * CMP_ROWS_PER_PAGE);
  setHTML(el('cmp-thead'), '<tr>' + CMP_COLS.map(([k, label]) => {
    const sort = cmp.sort === k ? (cmp.dir > 0 ? 'ascending' : 'descending') : 'none';
    return `<th scope="col"${k === 'rtu' || k === 'verdict' ? '' : ' class="num"'} aria-sort="${sort}"><button type="button" class="sort-btn" data-act="cmp-sort" data-key="${k}" data-fk="cmp-sort-${k}">${esc(label)}</button></th>`;
  }).join('') + '</tr>');
  let h = '';
  for (const x of page) {
    const reg = new Set(x.regressions || []);
    const a = x.a || {};
    const b = x.b || {};
    const vcell = (a.verdict || b.verdict)
      ? `${a.verdict ? verdictHtml(a.verdict) : '—'} <span aria-hidden="true">→</span><span class="sr-only">to</span> ${b.verdict ? verdictHtml(b.verdict) : '—'}`
      : '—';
    h += `<tr${reg.size ? ' class="row-problem"' : ''}><th scope="row"><code>${esc(x.rtu)}</code></th>` +
      `<td class="cmp-vd${reg.has('verdict') ? ' reg' : ''}">${vcell}</td>` +
      cmpCell(a.score, b.score, x.delta.score, 'up', fmtPct, pts, reg.has('score')) +
      cmpCell(a.delivered_pct, b.delivered_pct, x.delta.delivered_pct, 'up', fmtPct, pts, reg.has('delivered_pct')) +
      cmpCell(a.p50_us, b.p50_us, x.delta.p50_us, 'down', fmtLat, msFmt, reg.has('p50_us')) +
      cmpCell(a.p99_us, b.p99_us, x.delta.p99_us, 'down', fmtLat, msFmt, reg.has('p99_us')) +
      `<td class="num${reg.has('errors') ? ' reg' : ''}" title="${esc(b.error || a.error || '')}">${fmtInt(a.errors || 0)} → ${fmtInt(b.errors || 0)}</td>` +
      `<td class="num">${reg.size ? `<span class="reg-tag">${esc([...new Set([...reg].map(metricLabel))].join(', '))}</span>` : '<span class="muted">—</span>'}</td></tr>`;
  }
  if (!page.length) h = `<tr><td colspan="${CMP_COLS.length}" class="empty-cell">${all.length ? 'No RTU matches the filter.' : 'No RTU appears in both runs.'}</td></tr>`;
  setHTML(tbody, h, { force: true });
  const nreg = all.filter(x => (x.regressions || []).length).length;
  setText(el('cmp-count'), `${fmtInt(rows.length)} of ${fmtInt(all.length)} shown · ${fmtInt(nreg)} with regressions`);
  setHTML(el('cmp-pager'), pagerHtml('cmp-page', cmp.page, pages, rows.length, 'RTUs'));
}

document.addEventListener('input', e => {
  if (e.target.id === 'cmp-q') { cmp.q = e.target.value.trim(); cmp.page = 0; renderCmpRows(); }
});
document.addEventListener('change', e => {
  const t = e.target;
  if (t.id === 'cmp-only-reg') { cmp.onlyReg = t.checked; cmp.page = 0; renderCmpRows(); }
  if (t.id === 'cmp-only-changed') { cmp.onlyChanged = t.checked; cmp.page = 0; renderCmpRows(); }
});

function initCompare() {
  renderCmpThresholds();
  el('cmp-form').addEventListener('submit', submitCompare);
  el('cmp-form').addEventListener('change', e => {
    const t = e.target;
    if (t.id === 'cmp-a' || t.id === 'cmp-b') {
      cmp[t.id === 'cmp-a' ? 'a' : 'b'] = Number(t.value) || null;
      fieldError(t.id, '');
      syncCmpHash();
    }
    if (t.dataset && t.dataset.th) {
      const { th } = readCmpThresholds();
      cmp.th = th;
      syncCmpHash();
    }
  });
  on('route', r => { if (r.view === 'compare') onCmpRoute(r); });
  on('runs', () => { if (S.view === 'compare') renderCmpPickers(); });
  // Capture names come from the library, which may load after the result.
  on('library', () => { if (S.view === 'compare') { renderCmpPickers(); if (cmp.data && !isBusyIn(el('cmp-result'))) renderCmpResult(); } });
  on('analysis-event', ({ data }) => {
    // An analysis finished for a run whose comparison is waiting on it.
    if (S.view !== 'compare' || cmp.data || cmp.a == null || cmp.b == null) return;
    if (data && (Number(data.run_id) === cmp.a || Number(data.run_id) === cmp.b) && !cmp.busy.size) runCompare();
  });
}
