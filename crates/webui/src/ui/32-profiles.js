// 32-profiles.js — named run profiles (save the Configure form on the
// server, then load, rename, overwrite or delete), and filling the form
// from a stored run request: a profile's, or a finished run's
// (`GET /api/runs/:id` → `.request`, "Load into Configure").
'use strict';

const prof = { list: [], loaded: false, busy: false };

// ---------------------------------------------------------------------------
// Request → form.

function setField(id, v) {
  const n = el(id);
  if (!n) return;
  if (n.type === 'checkbox') { n.checked = !!v; return; }
  const s = v == null ? '' : String(v);
  if (n.tagName === 'SELECT') { n.dataset.want = s; n.value = s; }
  else n.value = s;
}
function setRadio(name, v) {
  const r = v && qs(`input[name="${name}"][value="${CSS.escape(v)}"]`);
  if (r) r.checked = true;
}

const SESSION_FIELDS = [['k', 'cfg-k'], ['w', 'cfg-w'], ['t0', 'cfg-t0'], ['t1', 'cfg-t1'], ['t2', 'cfg-t2'], ['t3', 'cfg-t3'], ['idle_serve_secs', 'cfg-idle-serve']];

// Split a proto_config string over the IEC 104 controls; whatever the
// controls cannot show stays in the raw JSON field, so nothing is lost.
function applyProtoConfigToForm(text) {
  for (const [, id] of SESSION_FIELDS) setField(id, '');
  setField('cfg-fresh-ts', false);
  setRadio('cp56-zone', 'local');
  setField('cfg-gi-ci-synth', true);
  let obj = null;
  if (text && String(text).trim()) {
    try { obj = JSON.parse(text); } catch (_) { obj = null; }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
      loadCommandsForm(null);
      loadFaultForm(null, null);
      setField('cfg-proto-config', text);
      return;
    }
  }
  obj = Object.assign({}, obj || {});
  const cp = obj.cp56;
  if (cp && typeof cp === 'object' && !Array.isArray(cp) &&
      Object.keys(cp).every(k => ['rewrite_to_now', 'zone', 'rewrite_cp56_to_now', 'cp56_zone'].includes(k))) {
    setField('cfg-fresh-ts', cp.rewrite_to_now ?? cp.rewrite_cp56_to_now);
    setRadio('cp56-zone', (cp.zone || cp.cp56_zone) === 'utc' ? 'utc' : 'local');
    delete obj.cp56;
  }
  const ses = obj.session;
  if (ses && typeof ses === 'object' && !Array.isArray(ses)) {
    const rest = Object.assign({}, ses);
    for (const [k, id] of SESSION_FIELDS) {
      if (typeof rest[k] === 'number') { setField(id, rest[k]); delete rest[k]; }
    }
    if (Object.keys(rest).length) obj.session = rest; else delete obj.session;
    if (SESSION_FIELDS.some(([k]) => typeof ses[k] === 'number')) el('link-params').open = true;
  }
  if (typeof obj.gi_ci_synthesis === 'boolean') {
    setField('cfg-gi-ci-synth', obj.gi_ci_synthesis);
    delete obj.gi_ci_synthesis;
  }
  if (loadCommandsForm(obj.commands)) delete obj.commands;
  if (loadFaultForm(obj.faults, obj.fault_seed)) { delete obj.faults; delete obj.fault_seed; }
  setField('cfg-proto-config', Object.keys(obj).length ? JSON.stringify(obj) : '');
}

// Fill the whole Configure form from a canonical run request. Returns
// notes worth telling the user (pcap gone, override not carried over).
function applyRequestToForm(req) {
  const notes = [];
  const mode = req.mode === 'raw' ? 'raw' : 'benchmark';
  const role = req.role === 'slave' ? 'slave' : 'master';
  setRadio('mode', mode);
  setRadio('role', role);
  setRadio('pacing', req.pacing === 'original' ? 'original' : 'fast');
  setRadio('concurrency', req.concurrency === 'staggered' ? 'staggered' : 'all_at_once');
  setField('cfg-proto', req.proto_name || 'iec104');
  setField('cfg-target-ip', req.target_ip && req.target_ip !== '0.0.0.0' ? req.target_ip : '');
  setField('cfg-target-port', req.target_port ?? 2404);
  setField('cfg-listen-port-base', req.listen_port_base ?? 2404);
  setField('cfg-master-bind-ip', req.master_bind_ip || '');
  setField('cfg-target-mac', req.target_mac || '');
  setField('cfg-nic', req.nic || '');
  setField('cfg-alias-iface', req.alias_iface || '');
  setField('cfg-tcp-nodelay', req.tcp_nodelay === true ? 'on' : req.tcp_nodelay === false ? 'off' : '');
  setField('cfg-speed', req.speed ?? 1);
  setField('cfg-iterations', req.iterations ?? 1);
  setField('cfg-warmup', req.warmup_secs ?? 5);
  setField('cfg-loop-within-session', req.loop_within_session);
  setField('cfg-top-speed', req.top_speed);
  setField('cfg-realtime', req.realtime);
  setField('cfg-skip-non-ip', req.skip_non_ip);
  const gw = !!req.scada_gateway_ip;
  setField('cfg-scada-gw', gw);
  setField('cfg-scada-gw-ip', req.scada_gateway_ip || '');
  setField('cfg-scada-gw-iface', req.scada_gateway_iface || '');
  setField('cfg-scada-upstream', req.upstream_nat_iface || '');
  if (gw) el('scada-gw-card').open = true;
  applyProtoConfigToForm(req.proto_config);
  // The override is never loaded: it must be chosen again, every time.
  el('cfg-force').checked = false;
  if (req.force) notes.push('It overrode NIC and address protection; that override is not loaded. Tick it again if you need it.');

  let pid = S.selectedPcapId;
  if (req.pcap_id) {
    if (S.library.some(p => p.id === req.pcap_id)) { pid = req.pcap_id; selectPcap(pid); }
    else notes.push(`Its pcap (${req.pcap_id}) is no longer in the library; select another one.`);
  }
  // Endpoint selection: stored per pcap and role; the picker filters it
  // against the pcap's endpoints when it renders.
  if (mode === 'benchmark' && pid) {
    const key = `${pid}|${role}`;
    const sel = Array.isArray(req.selected_rtus) ? req.selected_rtus : [];
    if (sel.length) prefs.set('rtuSel.' + key, sel); else prefs.del('rtuSel.' + key);
    pickerSel.delete(key);
    picker.key = null;
  }
  for (const n of qsa('#run-form [aria-invalid="true"]')) fieldError(n.id, '');
  _touched.clear();
  showRunError('');
  setText(el('run-result'), '');
  renderProtoSelect();
  renderNicSelects();
  applyVisibility();
  saveForm();
  return notes;
}

// Canonical request of the form, for a profile: no override, and no
// pcap when none is selected (profiles may be pcap-agnostic).
function profileRequest() {
  const body = buildBody(false);
  delete body.force;
  if (!body.pcap_id) delete body.pcap_id;
  return body;
}

// "Load into Configure" from a run (card or detail).
async function loadRunIntoConfigure(id) {
  const r = await fetchRunRequest(id);
  if (r.error) { notify(`Load run #${id}: ${r.error}`, 'error'); return; }
  const notes = applyRequestToForm(r.request);
  go('configure');
  setProfStatus(`Loaded the settings of run #${id}.${notes.length ? ' ' + notes.join(' ') : ''}`, notes.length ? 'warn' : 'ok');
  announce(`Settings of run ${id} loaded into Configure`);
}

// GET /api/runs/:id and its stored request.
async function fetchRunRequest(id) {
  const res = await api(`/api/runs/${id}`, 'GET', null, { timeout: 15000 });
  if (!res.ok || !res.data || typeof res.data !== 'object') return { error: res.error || 'could not load the run' };
  if (!res.data.request) return { error: `run #${id} was recorded before run settings were stored, so its settings are unknown.`, run: res.data };
  return { request: res.data.request, run: res.data };
}

// ---------------------------------------------------------------------------
// Profiles UI.

function setProfStatus(text, cls) {
  const n = el('prof-status');
  n.className = 'hint' + (cls ? ' ' + cls : '');
  setText(n, text || '');
}
function setProfError(html) {
  setHTML(el('prof-error'), html ? `<div class="err-box">${html}</div>` : '', { force: true });
}

function selectedProfile() {
  const id = Number(el('prof-select').value);
  return prof.list.find(p => p.id === id) || null;
}

function renderProfiles() {
  const sel = el('prof-select');
  const want = sel.value || String(prefs.get('profileSel', '') || '');
  let h = prof.list.length ? '' : `<option value="">${prof.loaded ? 'No saved profiles yet' : 'Loading…'}</option>`;
  for (const p of prof.list) {
    const pc = p.request && p.request.pcap_id ? ` · ${libraryName(p.request.pcap_id)}` : '';
    const mode = p.request ? (p.request.mode === 'raw' ? 'raw' : `${p.request.proto_name || 'iec104'} ${p.request.role || ''}`) : '';
    h += `<option value="${p.id}">${esc(p.name)} (${esc(mode.trim())}${esc(pc)}, saved ${esc(fmtClock(p.updated_at))})</option>`;
  }
  if (sel._html !== h) { sel.innerHTML = h; sel._html = h; }
  if (prof.list.some(p => String(p.id) === want)) sel.value = want;
  else if (prof.list.length) sel.value = String(prof.list[0].id);
  const has = !!selectedProfile();
  for (const id of ['prof-load', 'prof-overwrite', 'prof-rename', 'prof-delete']) el(id).disabled = !has || prof.busy;
  el('prof-save').disabled = prof.busy;
}

async function refreshProfiles() {
  const res = await api('/api/profiles');
  if (!res.ok || !Array.isArray(res.data)) {
    prof.loaded = true;
    setProfError(`Could not load the profiles: ${esc(res.error || 'bad reply')}`);
    renderProfiles();
    return;
  }
  prof.list = res.data;
  prof.loaded = true;
  renderProfiles();
}

const PROFILE_NAME_MAX = 100;
function profileNameError(v) {
  const n = String(v || '').trim();
  if (!n) return 'Enter a name.';
  if ([...n].length > PROFILE_NAME_MAX) return `At most ${PROFILE_NAME_MAX} characters.`;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(n)) return 'No control characters.';
  return '';
}

// Client-side check before saving: the same fields a run needs, except
// that a profile does not need a pcap.
function profileFormErrors() {
  const v = validators();
  delete v['cfg-pcap'];
  let count = 0;
  let first = null;
  for (const [id, fn] of Object.entries(v)) {
    const msg = fn();
    fieldError(id, msg);
    if (msg) { count++; if (!first) first = id; }
  }
  return { count, first };
}

async function profBusy(fn) {
  if (prof.busy) return;
  prof.busy = true;
  renderProfiles();
  try { await fn(); } finally { prof.busy = false; renderProfiles(); }
}

function explainProfileError(res, name) {
  if (res.code === 'profile_exists') {
    return `A profile named <b>“${esc(name)}”</b> already exists. Choose another name, or select that profile and use <b>Overwrite with form</b>.`;
  }
  if (res.code === 'not_found') return `That profile no longer exists (another user may have deleted it). ${esc(res.error)}`;
  return esc(res.error);
}

async function saveProfileAs() {
  setProfError('');
  const errs = profileFormErrors();
  if (errs.count) {
    setProfStatus('');
    setProfError(`Fix ${plural(errs.count, 'field')} in the form before saving it as a profile.`);
    const n = el(errs.first);
    if (n) {
      for (let d = n.closest('details'); d; d = d.parentElement && d.parentElement.closest('details')) d.open = true;
      n.focus();
    }
    return;
  }
  const name = await askDialog({
    title: 'Save the form as a profile',
    body: 'Stores the current Configure settings on the server under a name. The protection override is never stored.',
    input: { label: 'Profile name', value: '', validate: profileNameError },
    confirm: 'Save profile',
  });
  if (name === false) return;
  const clean = String(name).trim();
  await profBusy(async () => {
    setProfStatus(`Saving “${clean}”…`);
    const res = await api('/api/profiles', 'POST', { name: clean, request: profileRequest() });
    if (!res.ok) {
      setProfStatus('');
      setProfError(`Profile not saved. ${explainProfileError(res, clean)}`);
      return;
    }
    prefs.set('profileSel', String(res.data.id));
    el('prof-select').value = '';
    await refreshProfiles();
    el('prof-select').value = String(res.data.id);
    setProfStatus(`Saved profile “${res.data.name}”.`, 'ok');
    announce(`Profile ${res.data.name} saved`);
  });
}

async function loadProfile() {
  const p = selectedProfile();
  if (!p) return;
  setProfError('');
  await profBusy(async () => {
    const res = await api(`/api/profiles/${p.id}`);
    if (!res.ok || !res.data) { setProfError(`Could not load “${esc(p.name)}”: ${explainProfileError(res, p.name)}`); return; }
    const notes = applyRequestToForm(res.data.request || {});
    setProfStatus(`Loaded profile “${res.data.name}”.${notes.length ? ' ' + notes.join(' ') : ''}`, notes.length ? 'warn' : 'ok');
    announce(`Profile ${res.data.name} loaded`);
  });
}

async function overwriteProfile() {
  const p = selectedProfile();
  if (!p) return;
  setProfError('');
  const errs = profileFormErrors();
  if (errs.count) { setProfError(`Fix ${plural(errs.count, 'field')} in the form before saving it.`); return; }
  const ok = await askDialog({
    title: `Overwrite “${p.name}”?`,
    body: `Its stored settings are replaced by the current form (last saved ${fmtClock(p.updated_at)}). This cannot be undone.`,
    confirm: 'Overwrite profile',
    danger: true,
  });
  if (!ok) return;
  await profBusy(async () => {
    const res = await api(`/api/profiles/${p.id}`, 'PUT', { request: profileRequest() });
    if (!res.ok) { setProfError(`“${esc(p.name)}” was not overwritten. ${explainProfileError(res, p.name)}`); await refreshProfiles(); return; }
    await refreshProfiles();
    setProfStatus(`Overwrote profile “${p.name}” with the current form.`, 'ok');
    announce(`Profile ${p.name} overwritten`);
  });
}

async function renameProfile() {
  const p = selectedProfile();
  if (!p) return;
  setProfError('');
  const name = await askDialog({
    title: `Rename “${p.name}”`,
    input: { label: 'New name', value: p.name, validate: profileNameError },
    confirm: 'Rename',
  });
  if (name === false) return;
  const clean = String(name).trim();
  if (clean === p.name) return;
  await profBusy(async () => {
    const res = await api(`/api/profiles/${p.id}`, 'PUT', { name: clean });
    if (!res.ok) { setProfError(`Not renamed. ${explainProfileError(res, clean)}`); return; }
    await refreshProfiles();
    setProfStatus(`Renamed “${p.name}” to “${clean}”.`, 'ok');
    announce(`Profile renamed to ${clean}`);
  });
}

async function deleteProfile() {
  const p = selectedProfile();
  if (!p) return;
  setProfError('');
  const ok = await askDialog({
    title: `Delete profile “${p.name}”?`,
    body: 'Runs started from it are not affected. This cannot be undone.',
    confirm: 'Delete profile',
    danger: true,
  });
  if (!ok) return;
  await profBusy(async () => {
    const res = await api(`/api/profiles/${p.id}`, 'DELETE');
    if (!res.ok && res.code !== 'not_found') { setProfError(`Not deleted: ${esc(res.error)}`); return; }
    prefs.del('profileSel');
    el('prof-select').value = '';
    await refreshProfiles();
    setProfStatus(`Deleted profile “${p.name}”.`, 'ok');
    announce(`Profile ${p.name} deleted`);
  });
}

actions({
  'prof-save': saveProfileAs,
  'prof-load': loadProfile,
  'prof-overwrite': overwriteProfile,
  'prof-rename': renameProfile,
  'prof-delete': deleteProfile,
});

function initProfiles() {
  el('prof-select').addEventListener('change', e => {
    prefs.set('profileSel', e.target.value);
    setProfError('');
    renderProfiles();
  });
  on('library', renderProfiles);
  renderProfiles();
  refreshProfiles();
}
