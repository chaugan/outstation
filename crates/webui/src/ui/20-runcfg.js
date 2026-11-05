// 20-runcfg.js — run configuration form and start
// Spliced into the served page by crates/webui/build.rs (classic script,
// shared global scope with the other ui/*.js files, loaded in file-name order).

// =========================================================================
//  run start / stop
// =========================================================================
function toggleBenchmarkControls() {
  const on = el('run-benchmark').checked;
  el('bench-controls').style.display = on ? 'block' : 'none';
}

function toggleRoleControls() {
  const role = document.querySelector('input[name="run-role"]:checked')?.value || 'master';
  const isSlave = role === 'slave';
  el('bench-target-port-field').style.display = isSlave ? 'none' : '';
  el('bench-listen-port-field').style.display = isSlave ? '' : 'none';
  el('bench-concurrency-field').style.display = isSlave ? 'none' : '';
  el('bench-note-master').style.display = isSlave ? 'none' : '';
  el('bench-note-slave').style.display = isSlave ? '' : 'none';
}

// Show/hide any form block tagged with `<div data-proto="…">` based on
// which protocol the user picked in the run-proto selector. Keeps
// protocol-specific knobs (IEC 104 CP56 / ASDU rewrite map / …) out
// of view when they don't apply.
function applyProtoVisibility() {
  const sel = el('run-proto');
  if (!sel) return;
  const active = sel.value;
  document.querySelectorAll('[data-proto]').forEach(node => {
    const want = node.dataset.proto === active;
    node.hidden = !want;
    // `hidden` attribute is overridden by display:block in some CSS
    // rules, so mirror to inline style as a belt-and-braces.
    node.style.display = want ? '' : 'none';
  });
}

async function startRun() {
  const isBench = el('run-benchmark').checked;
  const concurrency = document.querySelector('input[name="run-concurrency"]:checked')?.value || 'all_at_once';
  if (!selectedPcapId && !selectedRawPath) {
    alert('select a pcap from the library or enter a raw path');
    return;
  }
  const pcRaw = el('run-proto-config').value.trim();
  const role = document.querySelector('input[name="run-role"]:checked')?.value || 'master';
  const pacing = document.querySelector('input[name="run-pacing"]:checked')?.value || 'fast';
  // Merge protocol-specific knobs that used to be top-level RunReq
  // fields into the proto_config JSON. The form's textarea may also
  // contain an IEC 104 ASDU rewrite map; preserve those keys and
  // attach a `cp56` sub-object with the fresh-timestamps controls.
  let protoCfgObj = {};
  if (pcRaw) {
    try { protoCfgObj = JSON.parse(pcRaw) || {}; }
    catch (_) { /* ignore — the backend reports the parse error */ }
  }
  const cp56Rewrite = el('run-fresh-timestamps')?.checked || false;
  const cp56Zone = document.querySelector('input[name="run-cp56-zone"]:checked')?.value || 'local';
  if (cp56Rewrite || cp56Zone !== 'local') {
    protoCfgObj.cp56 = { rewrite_to_now: cp56Rewrite, zone: cp56Zone };
  }
  const pc = Object.keys(protoCfgObj).length > 0
    ? JSON.stringify(protoCfgObj)
    : null;
  const body = {
    target_ip:   el('run-target-ip').value.trim() || '0.0.0.0',
    target_mac:  el('run-target-mac').value.trim(),
    speed:       parseFloat(el('run-speed').value) || 1.0,
    bridge:      el('run-bridge').value.trim() || 'pcr_br0',
    nic:         el('run-nic').value.trim() || null,
    top_speed:   el('run-top-speed').checked,
    realtime:    el('run-realtime').checked,
    skip_non_ip: el('run-skip-non-ip').checked,
    warmup_secs: parseInt(el('run-warmup').value) || 0,
    // 0 is the "unlimited" sentinel — treat as a valid value, not falsy.
    iterations: (() => {
      const raw = parseInt(el('run-iterations').value);
      return Number.isFinite(raw) && raw >= 0 ? raw : 1;
    })(),
    mode:        isBench ? 'benchmark' : 'raw',
    target_port: parseInt(el('run-target-port').value) || 2404,
    proto_name:  el('run-proto').value,
    concurrency,
    proto_config: pc,
    role,
    listen_port_base: parseInt(el('run-listen-port-base').value) || 2404,
    pacing,
    master_bind_ip: (el('run-master-bind-ip').value.trim() || null),
    tcp_nodelay: (() => {
      const v = el('run-tcp-nodelay').value;
      if (v === 'on')  return true;
      if (v === 'off') return false;
      return null;  // role-default
    })(),
    loop_within_session: el('run-loop-within-session')?.checked || false,
  };
  if (isBench && el('run-scada-gw-enable').checked) {
    const gw = el('run-scada-gw-ip').value.trim();
    const iface = el('run-scada-gw-iface').value.trim();
    if (!gw || !iface) {
      alert('scada-gateway mode: fill in both gateway ip and inner nic, or disable the checkbox');
      return;
    }
    body.scada_gateway_ip = gw;
    body.scada_gateway_iface = iface;
    const up = el('run-scada-upstream').value.trim();
    if (up) body.upstream_nat_iface = up;
  }
  // The server accepts library ids only (raw paths are rejected).
  if (selectedPcapId) body.pcap_id = selectedPcapId;
  const sel = collectSelectedRtus();
  if (sel.length > 0) body.selected_rtus = sel;

  const btn = el('start-btn');
  btn.disabled = true;
  const res = await api('/api/run', 'POST', body);
  btn.disabled = false;
  const out = el('run-result');
  if (!res.ok) {
    out.innerHTML = `<span style="color:var(--err)">${esc(res.data.error || res.data)}</span>`;
    return;
  }
  out.innerHTML = `<span style="color:var(--ok)">started &middot; run #${res.data.id}</span>`;
  setTimeout(() => { out.textContent = ''; }, 3000);
  currentDetailId = res.data.id;
  refreshRuns();
}

async function stopRun(id) {
  await api(`/api/runs/${id}/stop`, 'POST');
  refreshRuns();
}

async function deleteRun(id) {
  if (!confirm(`Delete run #${id}? This removes it from history and deletes its captured pcap.`)) return;
  const res = await api(`/api/runs/${id}`, 'DELETE');
  if (!res.ok) {
    const msg = (res.data && (res.data.error || res.data)) || `HTTP ${res.status}`;
    alert(`Delete failed: ${msg}`);
    return;
  }
  if (currentDetailId === id) currentDetailId = null;
  refreshRuns();
}
async function loadNics() {
  const res = await api('/api/nics');
  if (!res.ok) return;
  const nics = res.data.filter(n => !n.loopback && !n.bridge);
  const fillSelect = (id, placeholder) => {
    const sel = el(id);
    if (!sel) return;
    const current = sel.value;
    sel.innerHTML = `<option value="">${placeholder}</option>`;
    for (const n of nics) {
      const ip = n.ipv4.length ? ` · ${n.ipv4.join(',')}` : '';
      const status = n.up ? '' : ' · DOWN';
      const opt = document.createElement('option');
      opt.value = n.name;
      opt.textContent = `${n.name}${ip}${status}`;
      sel.appendChild(opt);
    }
    if (current) sel.value = current;
  };
  fillSelect('run-nic',          '(none — bridge stays isolated)');
  fillSelect('run-scada-gw-iface', '(select nic)');
  fillSelect('run-scada-upstream', '(none — scada has no upstream)');
}

function toggleScadaGwControls() {
  const on = el('run-scada-gw-enable').checked;
  el('run-scada-gw-ip-field').style.display    = on ? '' : 'none';
  el('run-scada-gw-iface-field').style.display = on ? '' : 'none';
  el('run-scada-upstream-field').style.display = on ? '' : 'none';
}

async function arpProbe() {
  const ip = el('run-target-ip').value.trim();
  const iface = el('run-nic').value;
  const status = el('arp-status');
  if (!ip) {
    status.innerHTML = '<span style="color:var(--err)">enter target ip first</span>';
    return;
  }
  status.innerHTML = 'probing…';
  status.style.color = 'var(--dim)';
  const res = await api('/api/arp', 'POST', { ip, iface: iface || null });
  if (!res.ok) {
    status.innerHTML = `<span style="color:var(--err)">${esc(res.data.error || res.data)}</span>`;
    return;
  }
  const d = res.data;
  if (d.error) {
    status.innerHTML = `<span style="color:var(--err)">${esc(d.error)}</span>`;
    return;
  }
  if (d.mac) {
    el('run-target-mac').value = d.mac;
    status.innerHTML = `<span style="color:var(--ok)">resolved on ${esc(d.iface)}</span>`;
  } else {
    status.innerHTML = `<span style="color:var(--err)">no reply</span>`;
  }
}
