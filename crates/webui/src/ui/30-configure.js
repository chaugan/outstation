// 30-configure.js — run configuration: mode and role segmented
// choices, pre-flight validation with inline errors, persisted form
// state, the RTU picker (filter, sort, shift-range select, selection
// kept per pcap and role), NIC pickers that flag protected NICs, the
// override (force) confirmation, and starting a run.
'use strict';

const CFG_INPUTS = [
  'cfg-proto', 'cfg-target-ip', 'cfg-target-port', 'cfg-listen-port-base', 'cfg-master-bind-ip',
  'cfg-target-mac', 'cfg-nic', 'cfg-alias-iface', 'cfg-tcp-nodelay', 'cfg-speed', 'cfg-iterations',
  'cfg-warmup', 'cfg-loop-within-session', 'cfg-top-speed', 'cfg-realtime', 'cfg-skip-non-ip',
  'cfg-fresh-ts', 'cfg-proto-config', 'cfg-k', 'cfg-w', 'cfg-t0', 'cfg-t1', 'cfg-t2', 'cfg-t3',
  'cfg-idle-serve', 'cfg-gi-ci-synth', 'cfg-scada-gw', 'cfg-scada-gw-ip', 'cfg-scada-gw-iface',
  'cfg-scada-upstream',
];
const CFG_RADIOS = ['mode', 'role', 'pacing', 'concurrency', 'cp56-zone'];
const FORM_KEY = 'runForm.v1';

const radio = name => (qs(`input[name="${name}"]:checked`) || {}).value;
const val = id => { const n = el(id); return n ? (n.type === 'checkbox' ? n.checked : n.value.trim()) : ''; };
const cfg = () => ({
  mode: radio('mode') || 'benchmark',
  role: radio('role') || 'master',
  pacing: radio('pacing') || 'fast',
  proto: val('cfg-proto') || 'iec104',
});

// ---------------------------------------------------------------------------
// Persistence (F100). The override checkbox is deliberately never saved.

function saveForm() {
  const o = { inputs: {}, radios: {} };
  for (const id of CFG_INPUTS) {
    const n = el(id);
    if (!n) continue;
    o.inputs[id] = n.type === 'checkbox' ? n.checked : (n.value || n.dataset.want || '');
  }
  for (const r of CFG_RADIOS) o.radios[r] = radio(r);
  prefs.set(FORM_KEY, o);
}
let _saveT = null;
function saveFormSoon() { clearTimeout(_saveT); _saveT = setTimeout(saveForm, 250); }

function loadForm() {
  const o = prefs.get(FORM_KEY, null);
  if (!o || typeof o !== 'object') return;
  for (const [id, v] of Object.entries(o.inputs || {})) {
    const n = el(id);
    if (!n) continue;
    if (n.type === 'checkbox') n.checked = !!v;
    else if (n.tagName === 'SELECT') { n.dataset.want = v; n.value = v; }
    else n.value = v;
  }
  for (const [name, v] of Object.entries(o.radios || {})) {
    const r = v && qs(`input[name="${name}"][value="${CSS.escape(v)}"]`);
    if (r) r.checked = true;
  }
}

// ---------------------------------------------------------------------------
// Visibility of mode / role / protocol specific fields.

function applyVisibility() {
  const c = cfg();
  for (const n of qsa('#run-form [data-mode], #run-form [data-role], #run-form [data-proto]')) {
    const show = (!n.dataset.mode || n.dataset.mode === c.mode)
      && (!n.dataset.role || c.mode !== 'benchmark' || n.dataset.role === c.role)
      && (!n.dataset.proto || n.dataset.proto === c.proto);
    n.hidden = !show;
  }
  el('speed-field').hidden = c.mode === 'benchmark' && c.pacing !== 'original';
  const lbl = el('cfg-target-ip-label');
  const hint = el('cfg-target-ip-hint');
  if (c.mode === 'raw') {
    setText(lbl, 'Target IP');
    setText(hint, 'Destination IP written into every replayed frame.');
  } else if (c.role === 'master') {
    setText(lbl, 'Target server IP');
    setText(hint, 'The RTU or server the master sessions connect to.');
  } else {
    lbl.innerHTML = 'Master IP <span class="opt">optional</span>';
    setText(hint, 'The SCADA master connects in to our listeners; this is informational.');
  }
  setText(el('rtu-title'), c.role === 'slave' ? 'RTUs to simulate' : 'Masters to replay');
  renderPicker();
  renderStartSummary();
}

// ---------------------------------------------------------------------------
// Protocols and NICs.

function renderProtoSelect() {
  const sel = el('cfg-proto');
  const want = sel.value || sel.dataset.want || 'iec104';
  if (!S.protocols.length) {
    sel.innerHTML = '<option value="iec104">iec104</option>';
    return;
  }
  sel.innerHTML = S.protocols.map(p => {
    const ready = p.status === 'ready';
    const ports = (p.ports || []).length ? `, port ${p.ports.join('/')}` : '';
    return `<option value="${esc(p.name)}"${ready ? '' : ' disabled'}>${esc(p.name)}${ready ? esc(ports) : ' (stub, not ready)'}</option>`;
  }).join('');
  const ok = S.protocols.find(p => p.name === want && p.status === 'ready')
    || S.protocols.find(p => p.status === 'ready');
  if (ok) sel.value = ok.name;
  applyVisibility();
}

function renderNicSelects() {
  fillNicSelect(el('cfg-nic'), 'None: keep the replay bridge isolated');
  fillNicSelect(el('cfg-alias-iface'), 'Default-route NIC (protected: needs override)');
  fillNicSelect(el('cfg-scada-gw-iface'), 'Select a NIC');
  fillNicSelect(el('cfg-scada-upstream'), 'None: SCADA has no upstream');
  updateNicWarnings();
}

function selectedProtected(id) {
  const sel = el(id);
  const opt = sel && sel.selectedOptions && sel.selectedOptions[0];
  return !!(opt && opt.dataset.protected);
}

function updateNicWarnings() {
  const force = el('cfg-force').checked;
  const base = 'Empty: the replay bridge stays isolated on this host.';
  setText(el('cfg-nic-hint'), selectedProtected('cfg-nic') && !force
    ? 'This NIC is protected; the run will be refused unless you override protection below.'
    : base);
  el('cfg-nic-hint').classList.toggle('warn', selectedProtected('cfg-nic') && !force);
}

// ---------------------------------------------------------------------------
// Selected pcap summary (F098/F104: re-rendered when analysis finishes).

function renderPcapSelect() {
  const sel = el('cfg-pcap');
  let h = `<option value="">${S.library.length ? 'Select a pcap…' : 'No pcaps in the library yet'}</option>`;
  for (const p of S.library) {
    const v = p.viability ? p.viability.verdict.replace(/_/g, ' ') : 'analysing';
    h += `<option value="${esc(p.id)}">${esc(p.name)} (${esc(v)})</option>`;
  }
  if (sel._html !== h) { sel.innerHTML = h; sel._html = h; }
  sel.value = S.library.some(p => p.id === S.selectedPcapId) ? S.selectedPcapId : '';
}

function renderPcapSummary() {
  const box = el('cfg-pcap-summary');
  const p = S.library.find(x => x.id === S.selectedPcapId);
  if (!p) {
    setHTML(box, S.libraryLoaded && !S.library.length
      ? '<p class="hint">Upload a pcap in the <a href="#/library">Library</a> first.</p>' : '');
  } else if (!p.viability) {
    setHTML(box, `<p class="meta-line">${fmtBytes(p.size_bytes)} · <span class="badge analyzing">analysing</span> The server is still parsing this pcap; this updates by itself.</p>`);
  } else {
    setHTML(box, `<p class="meta-line">${pcapMeta(p)}</p>` + viabilityHtml(p.viability));
  }
  renderPicker();
  renderStartSummary();
}

// ---------------------------------------------------------------------------
// RTU picker (F099, F125).

const picker = { key: null, rows: [], filter: '', sort: 'ip', dir: 1, lastIdx: null, visible: [] };
const pickerSel = new Map();   // "pcapId|role" -> Set of selected IPs

function pickerRowsFor(p, role) {
  if (!p || !p.viability) return [];
  return (role === 'slave' ? p.viability.slave_rtus : p.viability.master_clients) || [];
}

function pickerSet(key, rows) {
  if (!pickerSel.has(key)) {
    const saved = prefs.get('rtuSel.' + key, null);
    const all = rows.map(r => r.ip);
    const set = new Set(Array.isArray(saved) ? saved.filter(ip => all.includes(ip)) : all);
    pickerSel.set(key, set);
  }
  return pickerSel.get(key);
}

function savePicker() {
  const set = pickerSel.get(picker.key);
  if (!set) return;
  prefs.set('rtuSel.' + picker.key, set.size === picker.rows.length ? null : Array.from(set));
}

function cidrMatch(ip, filter) {
  const m = filter.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/);
  if (!m || !isIPv4(m[1])) return null;
  const bits = Number(m[2]);
  if (bits > 32) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((ipToInt(ip) & mask) >>> 0) === ((ipToInt(m[1]) & mask) >>> 0);
}

function renderPicker() {
  const box = el('rtu-picker');
  const c = cfg();
  if (c.mode !== 'benchmark') return;
  const p = S.library.find(x => x.id === S.selectedPcapId);
  const rows = pickerRowsFor(p, c.role);
  const key = p ? `${p.id}|${c.role}` : null;
  if (!p || !p.viability || !rows.length) {
    picker.key = null;
    picker.rows = [];
    setHTML(box, `<p class="hint">${!p ? 'Select a pcap to choose endpoints.'
      : !p.viability ? 'Waiting for the server to finish analysing the pcap.'
        : 'No IEC 104 endpoints were detected in this pcap; every source is used.'}</p>`);
    return;
  }
  if (picker.key !== key) {
    picker.key = key;
    picker.rows = rows;
    picker.lastIdx = null;
    const what = c.role === 'slave' ? 'RTU' : 'master';
    setHTML(box,
      '<div class="picker-toolbar">' +
        '<div class="field"><label for="rtu-filter">Filter</label>' +
        `<input id="rtu-filter" type="search" placeholder="IP text or CIDR, e.g. 10.1.0.0/24" spellcheck="false" autocomplete="off" value="${esc(picker.filter)}"></div>` +
        '<div class="btn-row">' +
          '<button type="button" class="btn btn-secondary" data-act="rtu-all">Select all</button>' +
          '<button type="button" class="btn btn-secondary" data-act="rtu-none">Select none</button>' +
          '<button type="button" class="btn btn-secondary" data-act="rtu-visible">Only visible</button>' +
          '<button type="button" class="btn btn-secondary" data-act="rtu-invert">Invert</button>' +
        '</div>' +
        '<span class="picker-count" id="rtu-count" role="status" aria-live="polite"></span>' +
      '</div>' +
      '<div class="picker-scroll"><table class="t picker">' +
        `<caption class="sr-only">${what}s in the pcap; shift-click a checkbox to select a range</caption>` +
        '<thead><tr><th scope="col"><span class="sr-only">Selected</span></th>' +
        '<th scope="col" data-sort="ip"><button type="button" class="sort-btn" data-act="rtu-sort" data-key="ip">IP</button></th>' +
        '<th scope="col" class="num" data-sort="bytes"><button type="button" class="sort-btn" data-act="rtu-sort" data-key="bytes">Payload</button></th>' +
        '<th scope="col" class="num" data-sort="msgs"><button type="button" class="sort-btn" data-act="rtu-sort" data-key="msgs">Messages</button></th>' +
        '<th scope="col" class="col-bar">Traffic</th></tr></thead>' +
        '<tbody id="rtu-tbody"></tbody></table></div>' +
      `<p class="hint">Shift-click a checkbox to select a range.</p>`, { force: true });
    el('rtu-filter').addEventListener('input', e => { picker.filter = e.target.value.trim(); renderPickerRows(); });
  }
  renderPickerRows();
}

function renderPickerRows() {
  const tbody = el('rtu-tbody');
  if (!tbody) return;
  const set = pickerSet(picker.key, picker.rows);
  const f = picker.filter;
  let rows = picker.rows.filter(r => {
    if (!f) return true;
    const c = cidrMatch(r.ip, f);
    return c === null ? r.ip.includes(f) : c;
  });
  const k = picker.sort;
  const d = picker.dir;
  rows = rows.slice().sort((a, b) => {
    if (k === 'bytes') return d * ((a.payload_bytes || 0) - (b.payload_bytes || 0));
    if (k === 'msgs') return d * ((a.messages || 0) - (b.messages || 0));
    return d * (ipToInt(a.ip) - ipToInt(b.ip));
  });
  picker.visible = rows.map(r => r.ip);
  const max = picker.rows.reduce((m, r) => Math.max(m, r.payload_bytes || 0), 0) || 1;
  const what = cfg().role === 'slave' ? 'RTU' : 'master';
  let h = '';
  for (const r of rows) {
    const w = (((r.payload_bytes || 0) / max) * 100).toFixed(1);
    h += `<tr><td><input type="checkbox" class="rtu-cb" data-ip="${esc(r.ip)}"${set.has(r.ip) ? ' checked' : ''} aria-label="Include ${what} ${esc(r.ip)}"></td>` +
      `<td><code>${esc(r.ip)}</code></td><td class="num">${fmtBytes(r.payload_bytes || 0)}</td><td class="num">${fmtInt(r.messages || 0)}</td>` +
      `<td class="col-bar"><span class="bar" aria-hidden="true"><span style="width:${w}%"></span></span></td></tr>`;
  }
  if (!rows.length) h = '<tr><td colspan="5" class="empty-cell">No endpoint matches the filter.</td></tr>';
  tbody.innerHTML = h;
  for (const th of qsa('.picker th[data-sort]')) {
    th.setAttribute('aria-sort', th.dataset.sort === k ? (d > 0 ? 'ascending' : 'descending') : 'none');
  }
  updatePickerCount();
}

function updatePickerCount() {
  const set = pickerSel.get(picker.key);
  if (!set) return;
  const n = picker.rows.length;
  setText(el('rtu-count'), `${set.size} of ${n} selected${set.size === n ? ' (all)' : ''}`);
  renderStartSummary();
}

function setPickerSelection(fn) {
  const set = pickerSel.get(picker.key);
  if (!set) return;
  fn(set);
  savePicker();
  renderPickerRows();
}

document.addEventListener('click', e => {
  const cb = e.target.closest && e.target.closest('.rtu-cb');
  if (!cb) return;
  const set = pickerSel.get(picker.key);
  if (!set) return;
  const idx = picker.visible.indexOf(cb.dataset.ip);
  if (e.shiftKey && picker.lastIdx != null && idx >= 0) {
    const [a, b] = [Math.min(idx, picker.lastIdx), Math.max(idx, picker.lastIdx)];
    for (let i = a; i <= b; i++) {
      const ip = picker.visible[i];
      if (cb.checked) set.add(ip); else set.delete(ip);
      const box = qs(`.rtu-cb[data-ip="${CSS.escape(ip)}"]`);
      if (box) box.checked = cb.checked;
    }
  } else if (cb.checked) set.add(cb.dataset.ip);
  else set.delete(cb.dataset.ip);
  picker.lastIdx = idx;
  savePicker();
  updatePickerCount();
  fieldError('rtu-picker', '');
});

actions({
  'rtu-all': () => setPickerSelection(s => { for (const r of picker.rows) s.add(r.ip); }),
  'rtu-none': () => setPickerSelection(s => s.clear()),
  'rtu-visible': () => setPickerSelection(s => { s.clear(); for (const ip of picker.visible) s.add(ip); }),
  'rtu-invert': () => setPickerSelection(s => {
    for (const r of picker.rows) { if (s.has(r.ip)) s.delete(r.ip); else s.add(r.ip); }
  }),
  'rtu-sort': b => {
    if (picker.sort === b.dataset.key) picker.dir = -picker.dir;
    else { picker.sort = b.dataset.key; picker.dir = b.dataset.key === 'ip' ? 1 : -1; }
    renderPickerRows();
  },
});

// Empty list = all endpoints (the backend default).
function selectedEndpoints() {
  const set = pickerSel.get(picker.key);
  if (!set || set.size === picker.rows.length) return [];
  return Array.from(set).sort((a, b) => ipToInt(a) - ipToInt(b));
}

// ---------------------------------------------------------------------------
// Validation (F096, F097). Returns an error message or ''.

function numIn(id, lo, hi, { integer = true, required = true, label } = {}) {
  const raw = val(id);
  if (raw === '') return required ? `Enter ${label}.` : '';
  const v = Number(raw);
  if (!Number.isFinite(v) || (integer && !Number.isInteger(v))) return `${label[0].toUpperCase() + label.slice(1)} must be ${integer ? 'a whole number' : 'a number'}.`;
  if (v < lo || v > hi) return `${label[0].toUpperCase() + label.slice(1)} must be between ${lo} and ${hi}.`;
  return '';
}

function parseRewriteMap() {
  const raw = val('cfg-proto-config');
  if (!raw) return { obj: {}, err: '' };
  let obj;
  try { obj = JSON.parse(raw); } catch (e) {
    return { obj: null, err: `Not valid JSON: ${e.message}. Fix it or clear the field; the run will not start with it.` };
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return { obj: null, err: 'Must be a JSON object, such as {"ioa": {"1001": 2001}}.' };
  return { obj, err: '' };
}

const optNum = id => { const v = val(id); return v === '' ? null : Number(v); };

function linkParamErrors() {
  const e = {};
  e['cfg-k'] = numIn('cfg-k', 1, 32767, { required: false, label: 'k' });
  e['cfg-w'] = numIn('cfg-w', 1, 32767, { required: false, label: 'w' });
  for (const [id, name] of [['cfg-t0', 't0'], ['cfg-t1', 't1'], ['cfg-t2', 't2'], ['cfg-t3', 't3']]) {
    const m = numIn(id, 0, 86400, { integer: false, required: false, label: name });
    e[id] = m || (optNum(id) === 0 ? `${name} must be greater than 0.` : '');
  }
  e['cfg-idle-serve'] = numIn('cfg-idle-serve', 0, 1e9, { integer: false, required: false, label: 'idle serve time' });
  const t1 = optNum('cfg-t1') ?? 15;
  const t2 = optNum('cfg-t2') ?? 10;
  if (!e['cfg-t1'] && !e['cfg-t2'] && t2 >= t1) e['cfg-t2'] = `t2 (${t2} s) must be less than t1 (${t1} s).`;
  return e;
}

function validators() {
  const c = cfg();
  const bench = c.mode === 'benchmark';
  const v = {
    'cfg-pcap': () => {
      if (!S.selectedPcapId) return 'Select a pcap.';
      const p = S.library.find(x => x.id === S.selectedPcapId);
      return p ? '' : 'The selected pcap is no longer in the library.';
    },
    'cfg-target-ip': () => {
      const ip = val('cfg-target-ip');
      if (!ip) return bench && c.role === 'slave' ? '' : 'Enter the target IP address.';
      return isIPv4(ip) ? '' : `"${ip}" is not an IPv4 address.`;
    },
  };
  if (bench) {
    v['cfg-proto'] = () => {
      const p = S.protocols.find(x => x.name === c.proto);
      return p && p.status !== 'ready' ? `${c.proto} is a stub and cannot run yet.` : '';
    };
    if (c.role === 'master') {
      v['cfg-target-port'] = () => numIn('cfg-target-port', 1, 65535, { label: 'the target port' });
      v['cfg-master-bind-ip'] = () => { const ip = val('cfg-master-bind-ip'); return !ip || isIPv4(ip) ? '' : `"${ip}" is not an IPv4 address.`; };
    } else {
      v['cfg-listen-port-base'] = () => {
        const m = numIn('cfg-listen-port-base', 1, 65535, { label: 'the listen port base' });
        if (m) return m;
        const set = pickerSel.get(picker.key);
        const n = set ? set.size : Math.max(1, picker.rows.length);
        return Number(val('cfg-listen-port-base')) + n - 1 > 65535 ? `Base + ${n} RTUs exceeds port 65535.` : '';
      };
    }
    if (c.pacing === 'original') v['cfg-speed'] = () => numIn('cfg-speed', 0.001, 1000, { integer: false, label: 'the speed factor' });
    if (c.proto === 'iec104') {
      v['cfg-proto-config'] = () => parseRewriteMap().err;
      for (const id of ['cfg-k', 'cfg-w', 'cfg-t0', 'cfg-t1', 'cfg-t2', 'cfg-t3', 'cfg-idle-serve']) {
        v[id] = () => linkParamErrors()[id] || '';
      }
    }
    if (val('cfg-scada-gw')) {
      v['cfg-scada-gw-ip'] = () => { const ip = val('cfg-scada-gw-ip'); return !ip ? 'Enter the gateway IP, or turn off gateway mode.' : (isIPv4(ip) ? '' : `"${ip}" is not an IPv4 address.`); };
      v['cfg-scada-gw-iface'] = () => (val('cfg-scada-gw-iface') ? '' : 'Select the inner NIC, or turn off gateway mode.');
    }
    v['rtu-picker'] = () => {
      const set = pickerSel.get(picker.key);
      return set && set.size === 0 ? 'Select at least one endpoint.' : '';
    };
  } else {
    v['cfg-target-mac'] = () => { const m = val('cfg-target-mac'); return !m ? 'Enter the target MAC, or use ARP lookup.' : (MAC_RE.test(m) ? '' : `"${m}" is not a MAC address (aa:bb:cc:dd:ee:ff).`); };
    v['cfg-speed'] = () => numIn('cfg-speed', 0.001, 1000, { integer: false, label: 'the speed factor' });
  }
  v['cfg-iterations'] = () => numIn('cfg-iterations', 0, 1e9, { label: 'the number of iterations' });
  v['cfg-warmup'] = () => numIn('cfg-warmup', 0, 3600, { label: 'the warmup' });
  return v;
}

const _touched = new Set();
function validateField(id) {
  const fn = validators()[id];
  return fieldError(id, fn ? fn() : '');
}
function validateAll() {
  const v = validators();
  // Clear errors on fields that do not apply in the current mode.
  for (const n of qsa('#run-form [aria-invalid="true"]')) if (!v[n.id]) fieldError(n.id, '');
  let first = null;
  let count = 0;
  for (const [id, fn] of Object.entries(v)) {
    const msg = fn();
    fieldError(id, msg);
    if (id === 'rtu-picker' && msg) notifyPicker(msg);
    if (msg) { count++; if (!first) first = id; }
  }
  return { ok: !count, first, count };
}
function notifyPicker(msg) {
  const c = el('rtu-count');
  if (c) setText(c, msg);
}

// ---------------------------------------------------------------------------
// Request body.

function buildProtoConfig() {
  const c = cfg();
  if (c.mode !== 'benchmark' || c.proto !== 'iec104') return null;
  const obj = Object.assign({}, parseRewriteMap().obj || {});
  const fresh = el('cfg-fresh-ts').checked;
  const zone = radio('cp56-zone') || 'local';
  if (fresh || zone !== 'local') obj.cp56 = { rewrite_to_now: fresh, zone };
  const session = {};
  for (const [id, k] of [['cfg-k', 'k'], ['cfg-w', 'w'], ['cfg-t0', 't0'], ['cfg-t1', 't1'], ['cfg-t2', 't2'], ['cfg-t3', 't3']]) {
    const n = optNum(id);
    if (n != null) session[k] = n;
  }
  if (c.role === 'slave' && optNum('cfg-idle-serve') != null) session.idle_serve_secs = optNum('cfg-idle-serve');
  if (Object.keys(session).length) obj.session = Object.assign({}, obj.session || {}, session);
  if (!el('cfg-gi-ci-synth').checked) obj.gi_ci_synthesis = false;
  return Object.keys(obj).length ? JSON.stringify(obj) : null;
}

function buildBody(force) {
  const c = cfg();
  const bench = c.mode === 'benchmark';
  const body = {
    pcap_id: S.selectedPcapId,
    mode: c.mode,
    target_ip: val('cfg-target-ip') || '0.0.0.0',
    nic: val('cfg-nic') || null,
    warmup_secs: Number(val('cfg-warmup')),
    iterations: Number(val('cfg-iterations')),
    force: !!force,
  };
  if (bench) {
    Object.assign(body, {
      proto_name: c.proto,
      role: c.role,
      pacing: c.pacing,
      speed: c.pacing === 'original' ? Number(val('cfg-speed')) : 1.0,
      proto_config: buildProtoConfig(),
      tcp_nodelay: { on: true, off: false }[val('cfg-tcp-nodelay')] ?? null,
    });
    if (c.role === 'master') {
      body.target_port = Number(val('cfg-target-port'));
      body.concurrency = radio('concurrency') || 'all_at_once';
      body.master_bind_ip = val('cfg-master-bind-ip') || null;
    } else {
      body.listen_port_base = Number(val('cfg-listen-port-base'));
      body.loop_within_session = el('cfg-loop-within-session').checked;
      body.alias_iface = val('cfg-alias-iface') || null;
    }
    if (el('cfg-scada-gw').checked) {
      body.scada_gateway_ip = val('cfg-scada-gw-ip');
      body.scada_gateway_iface = val('cfg-scada-gw-iface');
      body.upstream_nat_iface = val('cfg-scada-upstream') || null;
    }
    const sel = selectedEndpoints();
    if (sel.length) body.selected_rtus = sel;
  } else {
    Object.assign(body, {
      target_mac: val('cfg-target-mac'),
      speed: Number(val('cfg-speed')),
      top_speed: el('cfg-top-speed').checked,
      realtime: el('cfg-realtime').checked,
      skip_non_ip: el('cfg-skip-non-ip').checked,
    });
  }
  return body;
}

function renderStartSummary() {
  const c = cfg();
  const p = S.library.find(x => x.id === S.selectedPcapId);
  const parts = [];
  if (c.mode === 'benchmark') {
    parts.push(`Stateful ${c.proto}`, c.role === 'slave' ? 'we act as slaves' : 'we act as master');
    const set = pickerSel.get(picker.key);
    if (set && picker.key) parts.push(`${set.size} of ${picker.rows.length} ${c.role === 'slave' ? 'RTUs' : 'masters'}`);
  } else {
    parts.push('Raw L2 replay');
  }
  parts.push(p ? p.name : 'no pcap selected');
  setText(el('start-summary'), parts.join(' · '));
  const caps = S.status && S.status.capabilities;
  const w = el('caps-warn');
  const missing = caps && !(caps.net_admin && caps.net_raw);
  w.hidden = !missing;
  if (missing) setText(w, 'This server lacks CAP_NET_ADMIN / CAP_NET_RAW, so runs will fail when they set up the network. Start it through the systemd unit, or grant those capabilities.');
}

// ---------------------------------------------------------------------------
// Start, with override confirmation and the 409 / failure paths.

let watchRunId = null;

const FIELD_FOR_PARAM = {
  pcap_id: 'cfg-pcap', target_ip: 'cfg-target-ip', target_mac: 'cfg-target-mac', speed: 'cfg-speed',
  warmup_secs: 'cfg-warmup', target_port: 'cfg-target-port', listen_port_base: 'cfg-listen-port-base',
  proto_config: 'cfg-proto-config', scada_gateway_ip: 'cfg-scada-gw-ip', scada_gateway_iface: 'cfg-scada-gw-iface',
  master_bind_ip: 'cfg-master-bind-ip', proto_name: 'cfg-proto', iterations: 'cfg-iterations',
};

function showRunError(msg, extraHtml) {
  const hint = explainRunError(msg);
  setHTML(el('run-error'), msg
    ? `<div class="err-box"><p>${esc(msg)}</p>${hint ? `<p class="hint-strong">${esc(hint)}</p>` : ''}${extraHtml || ''}</div>`
    : '', { force: true });
}

async function startRun(e) {
  if (e) e.preventDefault();
  const btn = el('start-btn');
  if (btn.disabled) return;
  showRunError('');
  setText(el('run-result'), '');
  const v = validateAll();
  if (!v.ok) {
    setText(el('run-result'), `Fix ${plural(v.count, 'field')} before starting.`);
    const n = el(v.first);
    if (n) {
      const card = n.closest('details');
      if (card) card.open = true;
      (n.tagName === 'DIV' ? (qs('input', n) || n) : n).focus();
    }
    return;
  }
  const force = el('cfg-force').checked;
  if (force) {
    const prot = ['cfg-nic', 'cfg-alias-iface', 'cfg-scada-gw-iface'].filter(selectedProtected).map(id => val(id));
    const ok = await askDialog({
      title: 'Start with protection overridden?',
      body: [
        'The run may then use the default-route NIC, the address this page is served on, bridge ports, and addresses held by other interfaces. That can cut this host off the network or take over a live address.',
        prot.length ? `Selected protected NICs: ${prot.join(', ')}.` : 'Loopback, gateway and multicast addresses stay refused.',
      ],
      confirm: 'Start with override',
      danger: true,
    });
    if (!ok) return;
  }
  saveForm();
  btn.disabled = true;
  setText(el('run-result'), 'Starting…');
  const res = await api('/api/run', 'POST', buildBody(force), { timeout: 120000 });
  btn.disabled = false;
  if (!res.ok) {
    setText(el('run-result'), '');
    if (res.status === 409 && res.code === 'run_active') {
      const d = res.data || {};
      const who = d.client_ip ? ` by ${d.client_ip}` : '';
      const when = d.started_at ? ` at ${fmtClock(d.started_at)}` : '';
      showRunError(`Run #${d.active_run_id} is already active (started${who}${when}). Only one run can be active at a time: stop it, or wait for it to finish.`,
        `<p><a href="#/runs/${esc(d.active_run_id)}">Open run #${esc(d.active_run_id)}</a></p>`);
      return;
    }
    const m = String(res.error).match(/^(?:proto_config \(\w+\): )?([a-z_]+)\b/);
    const field = res.error.startsWith('proto_config') ? 'cfg-proto-config' : (m && FIELD_FOR_PARAM[m[1]]);
    if (field) fieldError(field, res.error);
    showRunError(`The server refused the run: ${res.error}`);
    return;
  }
  watchRunId = res.data.id;
  _usedForce = force;
  el('cfg-force').checked = false;
  updateNicWarnings();
  setHTML(el('run-result'), `Run #${esc(watchRunId)} started. <a href="#/runs/${esc(watchRunId)}">Watch it in Runs</a>`, { force: true });
  announce(`Run ${watchRunId} started`);
  if (typeof pollRunsSoon === 'function') pollRunsSoon();
}
let _usedForce = false;

// Follow the run just started, so a failure in its first seconds shows
// up here, next to the start button (F097).
function updateWatchedRun() {
  if (watchRunId == null) return;
  const r = S.runs.find(x => x.id === watchRunId);
  if (!r) return;
  const link = `<a href="#/runs/${esc(r.id)}">open in Runs</a>`;
  if (r.status === 'running') {
    const p = r.planned ? ` · ${pct(r.sent, r.planned)}%` : '';
    setHTML(el('run-result'), `Run #${esc(r.id)} is running${p}. ${link}`, { force: true });
    return;
  }
  setHTML(el('run-result'), `Run #${esc(r.id)} ${esc(r.status)}. ${link}`, { force: true });
  if (r.status === 'failed' || r.error) {
    const forceable = /set force|protected/i.test(r.error || '') && !_usedForce;
    showRunError(`Run #${r.id} ${r.status}: ${r.error || 'no error text recorded'}`,
      forceable ? '<p><button type="button" class="btn btn-secondary" data-act="retry-force">Retry with override…</button></p>' : '');
    announce(`Run ${r.id} ${r.status}`);
  }
  watchRunId = null;
}

actions({
  'retry-force': () => { el('cfg-force').checked = true; updateNicWarnings(); startRun(); },
  arp: async () => {
    const ip = val('cfg-target-ip');
    const status = el('arp-status');
    if (!isIPv4(ip)) { setText(status, 'Enter a valid target IP first.'); status.className = 'hint warn'; return; }
    status.className = 'hint';
    setText(status, 'Probing…');
    const res = await api('/api/arp', 'POST', { ip, iface: val('cfg-nic') || null }, { timeout: 30000 });
    const d = res.data || {};
    if (!res.ok || d.error) { status.className = 'hint warn'; setText(status, `ARP failed: ${res.error || d.error}`); return; }
    if (d.mac) {
      el('cfg-target-mac').value = d.mac;
      fieldError('cfg-target-mac', '');
      saveFormSoon();
      status.className = 'hint ok';
      setText(status, `Resolved on ${d.iface}.`);
    } else {
      status.className = 'hint warn';
      setText(status, `No ARP reply from ${ip}${d.iface ? ' on ' + d.iface : ''}.`);
    }
  },
});

function initConfigure() {
  loadForm();
  const form = el('run-form');
  form.addEventListener('submit', startRun);
  form.addEventListener('change', e => {
    const t = e.target;
    if (t.id === 'cfg-pcap') { selectPcap(t.value || null); }
    if (t.name === 'mode' || t.name === 'role' || t.name === 'pacing' || t.id === 'cfg-proto') applyVisibility();
    if (t.id === 'cfg-force' || t.tagName === 'SELECT') updateNicWarnings();
    if (t.id && !t.classList.contains('rtu-cb') && t.id !== 'rtu-filter') { _touched.add(t.id); validateField(t.id); }
    if (t.id === 'cfg-t1') validateField('cfg-t2');
    if (!t.classList.contains('rtu-cb') && t.id !== 'rtu-filter') saveFormSoon();
    renderStartSummary();
  });
  form.addEventListener('input', e => {
    const t = e.target;
    if (t.id === 'rtu-filter' || t.classList.contains('rtu-cb')) return;
    // Live feedback once a field has been touched, and always for JSON.
    if (t.id === 'cfg-proto-config' || _touched.has(t.id) || t.getAttribute('aria-invalid') === 'true') validateField(t.id);
    saveFormSoon();
  });
  on('library', () => { renderPcapSelect(); renderPcapSummary(); });
  on('selected', () => { renderPcapSelect(); renderPcapSummary(); validateField('cfg-pcap'); });
  on('protocols', renderProtoSelect);
  on('nics', renderNicSelects);
  on('status', renderStartSummary);
  on('runs', updateWatchedRun);
  renderNicSelects();
  applyVisibility();
}
