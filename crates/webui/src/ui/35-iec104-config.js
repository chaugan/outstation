// 35-iec104-config.js — the IEC 104 "Command handling" and "Fault
// injection" editors under Configure → IEC 104 options. They build the
// `commands`, `faults` and `fault_seed` keys of proto_config (next to
// the cp56 and session keys built in 30-configure.js), validate them
// with the server's ranges (crates/proto_iec104/src/{commands,faults}.rs),
// restore them from saved form state, a profile or a run's request, and
// put the server's "proto_config (faults): faults[i] (…)" errors back
// on the row they belong to.
'use strict';

const FAULT_MAX = 256;
const FAULT_DURATION_MAX = 86400000;

// Parameter ranges mirror faults.rs (uint / pct).
const FAULT_PARAMS = {
  duration_ms: { label: 'Duration (ms)', min: 1, max: FAULT_DURATION_MAX },
  pct: { label: 'Probability (%)', min: 0, max: 100, exclusiveMin: true, real: true },
  count: { label: 'Frames', min: 1, max: 1000 },
  ms: { label: 'Extra delay (ms)', min: 1, max: 600000 },
  extra_ms: { label: 'Ack delay (ms)', min: 1, max: 600000 },
};

const FAULT_KINDS = {
  withhold_acks: { label: 'Withhold acknowledgements', params: ['duration_ms'], help: 'No S-frames, and our I-frames repeat the last N(R), so the peer\'s t1 runs out.' },
  drop_iframes: { label: 'Drop I-frames', params: ['pct', 'duration_ms'], help: 'Each outgoing I-frame is dropped with this probability; its N(S) is used up, so the next one is out of sequence.' },
  duplicate_iframes: { label: 'Duplicate I-frames', params: ['pct', 'duration_ms'], help: 'Each outgoing I-frame is sent twice with the same N(S), with this probability.' },
  corrupt_ns: { label: 'Corrupt N(S)', params: ['count'], help: 'The next N I-frames carry a wrong send sequence number.' },
  testfr_silence: { label: 'TESTFR silence', params: ['duration_ms'], help: 'TESTFR act is neither answered nor sent (t3 keep-alive fails).' },
  delay: { label: 'Delay I-frames', params: ['ms', 'duration_ms'], help: 'Every outgoing I-frame is held this much longer.' },
  rst: { label: 'TCP reset (RST)', params: [], help: 'Abortive close of the connection; the session ends.' },
  stopdt: { label: 'Send STOPDT', params: [], help: 'Master: STOPDT act, then STARTDT once confirmed. Slave: an unsolicited STOPDT act.' },
  malformed_apdu: { label: 'Malformed APDUs', params: ['count'], help: 'N APDUs with an invalid length octet.' },
  slow_ack: { label: 'Slow acknowledgements', params: ['extra_ms', 'duration_ms'], optional: ['duration_ms'], help: 'Every acknowledgement goes out late. Without a duration, until the session ends.' },
};

let _faultUid = 0;
let faultRows = [];   // [{uid, atType: 'ms'|'frame', at, kind, p: {param: string}}]
const _faultTouched = new Set();

function newFaultRow(o = {}) {
  return {
    uid: ++_faultUid,
    atType: o.atType === 'frame' ? 'frame' : 'ms',
    at: o.at != null ? String(o.at) : '0',
    kind: FAULT_KINDS[o.kind] ? o.kind : 'drop_iframes',
    p: Object.assign({}, o.p || {}),
  };
}

// ---------------------------------------------------------------------------
// Validation (client side; the server re-checks).

function checkUint(raw, lo, hi, label) {
  if (raw === '' || raw == null) return `Enter ${label.toLowerCase()}.`;
  const v = Number(raw);
  if (!Number.isFinite(v) || !Number.isInteger(v)) return `${label} must be a whole number.`;
  if (v < lo || v > hi) return `${label} must be ${lo.toLocaleString()} to ${hi.toLocaleString()}.`;
  return '';
}

function faultFieldError(row, key) {
  if (key === 'at') {
    return row.atType === 'frame'
      ? checkUint(row.at, 0, Number.MAX_SAFE_INTEGER, 'The I-frame number')
      : checkUint(row.at, 0, FAULT_DURATION_MAX, 'The start time');
  }
  const spec = FAULT_PARAMS[key];
  const kind = FAULT_KINDS[row.kind];
  const raw = (row.p[key] ?? '').toString().trim();
  if (raw === '' && kind.optional && kind.optional.includes(key)) return '';
  if (spec.real) {
    if (raw === '') return `Enter ${spec.label.toLowerCase()}.`;
    const v = Number(raw);
    if (!Number.isFinite(v)) return `${spec.label} must be a number.`;
    if (!(v > spec.min && v <= spec.max)) return `${spec.label} must be more than ${spec.min} and at most ${spec.max}.`;
    return '';
  }
  return checkUint(raw, spec.min, spec.max, spec.label);
}

function faultRowKeys(row) { return ['at'].concat(FAULT_KINDS[row.kind].params); }

// Validate every row, mark the bad fields, return the number of problems.
function validateFaultRows(onlyTouched) {
  let bad = 0;
  for (const row of faultRows) {
    for (const k of faultRowKeys(row)) {
      const id = `flt-${row.uid}-${k}`;
      const msg = faultFieldError(row, k);
      if (msg) bad++;
      if (!onlyTouched || _faultTouched.has(id) || (el(id) && el(id).getAttribute('aria-invalid') === 'true')) fieldError(id, msg);
    }
    fieldError(`flt-${row.uid}-row`, '');
  }
  return bad;
}

function faultEditorError() {
  if (faultRows.length > FAULT_MAX) return `At most ${FAULT_MAX} faults; remove ${faultRows.length - FAULT_MAX}.`;
  const bad = validateFaultRows(false);
  return bad ? `Fix ${plural(bad, 'fault setting')} in the plan above.` : '';
}

function faultSeedError() {
  const raw = val('cfg-fault-seed');
  if (raw === '') return '';
  const v = Number(raw);
  if (!Number.isFinite(v) || !Number.isInteger(v) || v < 0) return 'The seed must be a whole number of 0 or more.';
  if (v > Number.MAX_SAFE_INTEGER) return `The seed must be at most ${Number.MAX_SAFE_INTEGER}.`;
  return '';
}

function cmdMaxAgeError() {
  const raw = val('cfg-cmd-max-age');
  if (raw === '') return '';
  return checkUint(raw, 0, 86400000, 'The max age');
}

// ---------------------------------------------------------------------------
// proto_config pieces.

const CMD_KEYS = ['enabled', 'return_info', 'max_age_ms', 'unknown_ioa'];

// `commands` object with only the non-default keys, or null.
function commandsJson() {
  const o = {};
  if (!el('cfg-cmd-enabled').checked) o.enabled = false;
  const ri = val('cfg-cmd-return-info');
  if (ri && ri !== 'none') o.return_info = ri;
  const ma = val('cfg-cmd-max-age');
  if (ma !== '') o.max_age_ms = Number(ma);
  const ui = val('cfg-cmd-unknown-ioa');
  if (ui && ui !== 'negative') o.unknown_ioa = ui;
  return Object.keys(o).length ? o : null;
}

// `faults` array (server key order: at, kind, params), or null.
function faultsJson() {
  if (!faultRows.length) return null;
  return faultRows.map(row => {
    const kind = FAULT_KINDS[row.kind];
    const o = { at: { [row.atType]: Number(row.at) }, kind: row.kind };
    for (const k of kind.params) {
      const raw = (row.p[k] ?? '').toString().trim();
      if (raw === '' && kind.optional && kind.optional.includes(k)) continue;
      o[k] = Number(raw);
    }
    return o;
  });
}

// Merge the editors into a proto_config object (role decides whether
// the slave-only command settings apply).
function addIec104Editors(obj, role) {
  const cmds = role === 'slave' ? commandsJson() : null;
  if (cmds) obj.commands = Object.assign({}, obj.commands || {}, cmds);
  const faults = faultsJson();
  if (faults) {
    obj.faults = faults;
    const seed = val('cfg-fault-seed');
    if (seed !== '') obj.fault_seed = Number(seed);
  }
  return obj;
}

// Fill the command editor from a `commands` object. Returns false (and
// resets the editor) when the object has keys the editor cannot show,
// so the caller keeps it in the raw JSON field instead.
function loadCommandsForm(c) {
  const reset = () => {
    el('cfg-cmd-enabled').checked = true;
    el('cfg-cmd-return-info').value = 'none';
    el('cfg-cmd-max-age').value = '';
    el('cfg-cmd-unknown-ioa').value = 'negative';
  };
  reset();
  if (c == null) return true;
  if (typeof c !== 'object' || Array.isArray(c) || Object.keys(c).some(k => !CMD_KEYS.includes(k))) return false;
  if (c.return_info != null && !['none', 'spontaneous', 'retrem'].includes(c.return_info)) return false;
  if (c.unknown_ioa != null && !['negative', 'accept'].includes(c.unknown_ioa)) return false;
  el('cfg-cmd-enabled').checked = c.enabled !== false;
  if (c.return_info) el('cfg-cmd-return-info').value = c.return_info;
  if (c.max_age_ms != null) el('cfg-cmd-max-age').value = String(c.max_age_ms);
  if (c.unknown_ioa) el('cfg-cmd-unknown-ioa').value = c.unknown_ioa;
  if (c.return_info && c.return_info !== 'none' || c.enabled === false || c.max_age_ms != null || c.unknown_ioa === 'accept') el('cmd-params').open = true;
  return true;
}

// Fill the fault editor from `faults` / `fault_seed`. Returns false
// (editor emptied) when a fault cannot be represented by the editor.
function loadFaultForm(faults, seed) {
  faultRows = [];
  _faultTouched.clear();
  el('cfg-fault-seed').value = seed != null && Number.isInteger(seed) ? String(seed) : '';
  let ok = true;
  if (faults != null) {
    if (!Array.isArray(faults)) ok = false;
    else {
      for (const f of faults) {
        const kind = f && FAULT_KINDS[f.kind];
        const at = f && f.at;
        const atKeys = at && typeof at === 'object' ? Object.keys(at) : [];
        const extra = kind ? Object.keys(f).filter(k => k !== 'at' && k !== 'kind' && !kind.params.includes(k)) : [];
        if (!kind || atKeys.length !== 1 || !['ms', 'frame'].includes(atKeys[0]) || extra.length) { ok = false; break; }
        const p = {};
        for (const k of kind.params) if (f[k] != null) p[k] = String(f[k]);
        faultRows.push(newFaultRow({ atType: atKeys[0], at: at[atKeys[0]], kind: f.kind, p }));
      }
    }
  }
  if (!ok) { faultRows = []; el('cfg-fault-seed').value = ''; }
  if (faultRows.length) el('fault-params').open = true;
  renderFaultRows();
  return ok;
}

// Persisted form state (30-configure.js saveForm / loadForm).
function faultFormState() {
  return faultRows.map(r => ({ atType: r.atType, at: r.at, kind: r.kind, p: r.p }));
}
function restoreFaultForm(rows) {
  faultRows = Array.isArray(rows) ? rows.slice(0, FAULT_MAX).map(r => newFaultRow(r || {})) : [];
  // Settings that change the session should not hide in a closed panel.
  if (faultRows.length) el('fault-params').open = true;
  if (commandsJson()) el('cmd-params').open = true;
  renderFaultRows();
}

// ---------------------------------------------------------------------------
// Rendering.

function faultParamField(row, k, n) {
  const spec = FAULT_PARAMS[k];
  const kind = FAULT_KINDS[row.kind];
  const opt = kind.optional && kind.optional.includes(k);
  const id = `flt-${row.uid}-${k}`;
  const step = spec.real ? 'any' : '1';
  const min = spec.exclusiveMin ? '0' : String(spec.min);
  return `<div class="field"><label for="${id}">${esc(spec.label)}${opt ? ' <span class="opt">optional</span>' : ''}</label>` +
    `<input id="${id}" type="number" inputmode="${spec.real ? 'decimal' : 'numeric'}" min="${min}" max="${spec.max}" step="${step}" value="${esc(row.p[k] ?? '')}" data-flt="${k}" data-uid="${row.uid}" aria-describedby="${id}-err"${opt ? ` placeholder="until the end"` : ''} aria-label="${esc(spec.label)}, fault ${n}">` +
    `<p class="field-err" id="${id}-err"></p></div>`;
}

function faultRowHtml(row, idx) {
  const n = idx + 1;
  const kind = FAULT_KINDS[row.kind];
  const u = row.uid;
  let h = `<fieldset class="fault-row"><legend>Fault ${n}: ${esc(kind.label)}</legend><div class="fault-grid">`;
  h += `<div class="field"><label for="flt-${u}-kind">Kind</label><select id="flt-${u}-kind" data-flt="kind" data-uid="${u}" aria-describedby="flt-${u}-help">` +
    Object.entries(FAULT_KINDS).map(([k, v]) => `<option value="${k}"${k === row.kind ? ' selected' : ''}>${esc(v.label)}</option>`).join('') + '</select></div>';
  h += `<div class="field"><label for="flt-${u}-attype">Fires</label><select id="flt-${u}-attype" data-flt="atType" data-uid="${u}">` +
    `<option value="ms"${row.atType === 'ms' ? ' selected' : ''}>At a time after connect</option>` +
    `<option value="frame"${row.atType === 'frame' ? ' selected' : ''}>Before an I-frame</option></select></div>`;
  const atLabel = row.atType === 'frame' ? 'I-frame number (0-based)' : 'Time after connect (ms)';
  h += `<div class="field"><label for="flt-${u}-at">${atLabel}</label><input id="flt-${u}-at" type="number" inputmode="numeric" min="0" step="1"${row.atType === 'ms' ? ` max="${FAULT_DURATION_MAX}"` : ''} value="${esc(row.at)}" data-flt="at" data-uid="${u}" aria-describedby="flt-${u}-at-err"><p class="field-err" id="flt-${u}-at-err"></p></div>`;
  for (const k of kind.params) h += faultParamField(row, k, n);
  h += `<div class="field fault-remove"><button type="button" class="btn btn-text danger" data-act="fault-remove" data-uid="${u}" data-fk="flt-${u}-remove" aria-label="Remove fault ${n}">Remove</button></div>`;
  h += `</div><p class="hint" id="flt-${u}-help">${esc(kind.help)}</p><p class="field-err" id="flt-${u}-row-err"></p></fieldset>`;
  return h;
}

function renderFaultRows() {
  const list = el('fault-rows');
  if (!list) return;
  reconcile(list, faultRows, r => r.uid, (li, row) => {
    const idx = faultRows.indexOf(row);
    const html = faultRowHtml(row, idx);
    if (li._html !== html) setHTML(li, html, { force: true });
  }, { tag: 'li', className: 'fault-li' });
  el('fault-empty').hidden = faultRows.length > 0;
  const n = faultRows.length;
  setText(el('fault-count'), n ? `${n} of at most ${FAULT_MAX}` : '');
  el('fault-add').disabled = n >= FAULT_MAX;
  const sum = el('fault-summary');
  setText(sum, n ? `${plural(n, 'fault')} planned: this run deliberately breaks the session` : 'none planned');
  sum.classList.toggle('warn', n > 0);
  // Re-show errors on fields that were already flagged.
  validateFaultRows(true);
  if (typeof renderStartSummary === 'function') renderStartSummary();
}

// ---------------------------------------------------------------------------
// Editing.

function faultRowOf(node) {
  const uid = Number(node.dataset.uid);
  return faultRows.find(r => r.uid === uid) || null;
}

function onFaultInput(e) {
  const t = e.target;
  if (!t.dataset || !t.dataset.flt) return false;
  const row = faultRowOf(t);
  if (!row) return true;
  const k = t.dataset.flt;
  if (k === 'kind' || k === 'atType') {
    if (e.type !== 'change') return true;
    row[k] = t.value;
    if (k === 'atType') row.at = '0';
    renderFaultRows();
  } else {
    if (k === 'at') row.at = t.value.trim();
    else row.p[k] = t.value.trim();
    if (e.type === 'change') _faultTouched.add(t.id);
    if (_faultTouched.has(t.id) || t.getAttribute('aria-invalid') === 'true') fieldError(t.id, faultFieldError(row, k));
    if (!qs('#fault-rows [aria-invalid="true"]')) fieldError('fault-editor', '');
  }
  saveFormSoon();
  return true;
}

actions({
  'fault-add': () => {
    if (faultRows.length >= FAULT_MAX) return;
    const last = faultRows[faultRows.length - 1];
    const row = newFaultRow(last ? { atType: last.atType, kind: last.kind, p: last.p, at: last.at } : { p: { pct: '10', duration_ms: '1000' } });
    faultRows.push(row);
    renderFaultRows();
    saveFormSoon();
    const k = el(`flt-${row.uid}-kind`);
    if (k) k.focus();
    announce(`Fault ${faultRows.length} added`);
  },
  'fault-remove': b => {
    const uid = Number(b.dataset.uid);
    const idx = faultRows.findIndex(r => r.uid === uid);
    if (idx < 0) return;
    faultRows.splice(idx, 1);
    renderFaultRows();
    saveFormSoon();
    fieldError('fault-editor', '');
    // Keep focus in the editor: the next row's remove button, or Add.
    const next = faultRows[idx] || faultRows[idx - 1];
    const f = next ? el(`flt-${next.uid}-kind`) : el('fault-add');
    if (f) f.focus();
    announce(`Fault ${idx + 1} removed`);
  },
});

// ---------------------------------------------------------------------------
// Server-side errors: "proto_config (faults): faults[2] (delay): "ms"
// must be 1..=600000, got 0", "proto_config (faults): fault_seed must be
// …", "proto_config (commands): …". Returns true when the message was
// shown on a field of the editors.

function showIec104ConfigError(msg) {
  const s = String(msg || '');
  let m = s.match(/proto_config \(faults\): (.*)$/s);
  if (m) {
    const text = m[1];
    el('fault-params').open = true;
    const ix = text.match(/^faults\[(\d+)\]/);
    const row = ix ? faultRows[Number(ix[1])] : null;
    if (row) {
      const key = (text.match(/"(\w+)"/) || [])[1];
      const target = key === 'ms' && /\.at:/.test(text) ? 'at' : (key === 'frame' ? 'at' : key);
      if (target && el(`flt-${row.uid}-${target}`)) fieldError(`flt-${row.uid}-${target}`, `Server: ${text}`);
      else fieldError(`flt-${row.uid}-row`, `Server: ${text}`);
    } else if (/fault_seed/.test(text)) {
      fieldError('cfg-fault-seed', `Server: ${text}`);
    } else {
      fieldError('fault-editor', `Server: ${text}`);
    }
    return true;
  }
  m = s.match(/proto_config \(commands\): (.*)$/s);
  if (m) {
    el('cmd-params').open = true;
    if (/max_age/.test(m[1])) fieldError('cfg-cmd-max-age', `Server: ${m[1]}`);
    else setText(el('cmd-params-err'), `Server: ${m[1]}`);
    return true;
  }
  return false;
}

function clearIec104ServerErrors() {
  setText(el('cmd-params-err'), '');
  for (const n of qsa('#fault-rows [id$="-row-err"]')) n.textContent = '';
}

function faultPlanSummary() {
  return faultRows.length ? `${plural(faultRows.length, 'fault')} planned` : '';
}

function initIec104Config() {
  const editor = el('fault-params');
  editor.addEventListener('input', onFaultInput);
  editor.addEventListener('change', onFaultInput);
  renderFaultRows();
}
