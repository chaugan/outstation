// 10-library.js — pcap library: list, upload, select
// Spliced into the served page by crates/webui/build.rs (classic script,
// shared global scope with the other ui/*.js files, loaded in file-name order).

// =========================================================================
//  library
// =========================================================================
let libraryPcaps = [];
let selectedPcapId = null;
let selectedRawPath = null;  // if set, overrides library selection

async function refreshLibrary() {
  const res = await api('/api/pcaps');
  if (!res.ok) { return; }
  libraryPcaps = res.data || [];
  el('lib-meta').textContent = libraryPcaps.length
    ? `${libraryPcaps.length} pcap${libraryPcaps.length===1?'':'s'}`
    : '—';
  renderLibrary();
  if (selectedPcapId && !libraryPcaps.find(p => p.id === selectedPcapId)) {
    selectedPcapId = null;
    updateSelectedLabel();
  }
}

function renderLibrary() {
  const list = el('pcap-list');
  if (!libraryPcaps.length) {
    list.innerHTML = '<div class="lib-empty">no pcaps uploaded</div>';
    return;
  }
  let h = '';
  for (const p of libraryPcaps) {
    const sel = selectedPcapId === p.id ? 'selected' : '';
    const srcDesc = p.ip_sources + (p.non_ip_sources ? `+${p.non_ip_sources} l2` : '') + ' src';
    let badge = '';
    if (p.viability && p.viability.verdict) {
      badge = `<span class="badge ${esc(p.viability.verdict)}">${esc(p.viability.verdict.replace('_',' '))}</span>`;
    } else {
      // viability=null means the background analyzer hasn't finished
      // walking the pcap yet. Show a pulsing "ANALYZING" badge.
      badge = `<span class="badge analyzing">ANALYZING</span>`;
    }
    if (p.mac_collisions && p.mac_collisions > 0) {
      badge += `<span class="badge mac_warn" title="${p.mac_collisions} source IP(s) had multiple MACs in the pcap — replay uses most-common pick">MAC ${p.mac_collisions}</span>`;
    }
    // Absolute capture range (UTC) — shown as a secondary hint so
    // users eyeing fresh-timestamps mode can see how stale the pcap's
    // own CP56Time2a stamps are.
    let rangeStr = '';
    if (p.pcap_start_unix_ms && p.pcap_end_unix_ms) {
      const a = fmtUtcShort(p.pcap_start_unix_ms);
      const b = fmtUtcShort(p.pcap_end_unix_ms);
      if (a && b) rangeStr = a === b ? a : `${a} → ${b}`;
    }
    h += `<div class="pcap-row ${sel}" onclick="selectPcap('${esc(p.id)}')">`;
    h += `  <div>`;
    h += `    <div class="name">${esc(p.name)}${badge}</div>`;
    h += `    <div class="meta">${p.packets.toLocaleString()} pkts &middot; ${srcDesc} &middot; ${p.tcp_flows} flows &middot; ${fmtDuration(p.duration_ms)} &middot; ${fmtBytes(p.size_bytes)} &middot; ${fmtTimeAgo(p.uploaded_at_ms)}</div>`;
    if (rangeStr) {
      h += `    <div class="meta" style="opacity:0.7" title="Pcap capture time range (UTC)">captured ${esc(rangeStr)}</div>`;
    }
    h += `  </div>`;
    h += `  <div class="actions">`;
    h += `    <button onclick="event.stopPropagation(); renamePcap('${esc(p.id)}')">rename</button>`;
    h += `    <button onclick="event.stopPropagation(); deletePcap('${esc(p.id)}')">delete</button>`;
    h += `  </div>`;
    h += `</div>`;
  }
  list.innerHTML = h;
}

function selectPcap(id) {
  selectedPcapId = id;
  selectedRawPath = null;
  el('raw-path').value = '';
  renderLibrary();
  updateSelectedLabel();
}

function updateSelectedLabel() {
  const box = el('selected-box');
  let viaCard = el('viability-card');
  if (viaCard) viaCard.remove();
  if (selectedRawPath) {
    box.innerHTML = `<span class="name">${esc(selectedRawPath)}</span><span class="sub">&middot; raw path</span>`;
  } else if (selectedPcapId) {
    const p = libraryPcaps.find(x => x.id === selectedPcapId);
    if (p) {
      let verdictHtml = '';
      if (p.viability && p.viability.verdict) {
        verdictHtml = `<span class="verdict ${esc(p.viability.verdict)}">${esc(p.viability.verdict.replace('_',' '))}</span>`;
      } else {
        verdictHtml = `<span class="verdict analyzing">ANALYZING…</span>`;
      }
      const meta = p.viability
        ? `${p.packets.toLocaleString()} pkts &middot; ${p.ip_sources} src &middot; ${fmtDuration(p.duration_ms)} &middot; ${fmtBytes(p.size_bytes)}`
        : `${fmtBytes(p.size_bytes)} &middot; server is parsing — refreshes automatically`;
      box.innerHTML = `<span class="name">${esc(p.name)}</span><span class="sub">&middot; ${meta}</span>${verdictHtml}`;
      // Render full viability advisory below the box.
      if (p.viability) {
        const v = p.viability;
        let card = `<div class="viability-card ${esc(v.verdict)}" id="viability-card">`;
        card += `<div class="reason">${esc(v.verdict_reason)}</div>`;
        card += `<div class="note">est. peak ram: ${v.estimated_peak_mb} MB &middot; master sessions: ${v.sessions_master_mode} &middot; slave sessions: ${v.sessions_slave_mode}</div>`;
        for (const n of v.notes) {
          card += `<div class="note">&middot; ${esc(n)}</div>`;
        }
        card += renderRtuPicker(v);
        card += `</div>`;
        box.insertAdjacentHTML('afterend', card);
        wireRtuPicker();
      }
    }
  } else {
    box.innerHTML = '<span class="empty">no pcap selected &mdash; pick one from the library above</span>';
  }
}

// Pre-run RTU picker: shows the captured slave/master endpoints with
// per-RTU traffic bars and a checkbox per row. The bar width is
// proportional to that RTU's payload bytes (relative to the heaviest
// in the set), so the operator can spot which slaves are talkative
// vs. silent before committing to a run. "Select all / none" toggles
// flip every checkbox at once. Selection is read at run-start time
// (see collectSelectedRtus), so the user can flip the role/proto
// without losing their checks.
function renderRtuPicker(v) {
  const slaves = v.slave_rtus || [];
  if (slaves.length === 0) return '';
  const maxBytes = slaves.reduce((m, r) => Math.max(m, r.payload_bytes || 0), 0) || 1;
  let h = `<div class="rtu-picker" id="rtu-picker" style="margin-top:10px;border-top:1px solid var(--rule);padding-top:10px">`;
  h += `<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">`;
  h += `<div style="font-family:var(--sans);font-size:10px;font-weight:700;letter-spacing:0.08em;color:var(--ink)">RTUs TO SIMULATE (${slaves.length})</div>`;
  h += `<button type="button" class="ghost" style="font-size:11px;padding:2px 8px" onclick="toggleAllRtus(true)">Select all</button>`;
  h += `<button type="button" class="ghost" style="font-size:11px;padding:2px 8px" onclick="toggleAllRtus(false)">Select none</button>`;
  h += `<span class="muted" id="rtu-picker-count" style="font-size:11px;margin-left:auto"></span>`;
  h += `</div>`;
  h += `<div style="max-height:260px;overflow-y:auto;font-family:var(--mono);font-size:11px;border:1px solid var(--rule);border-radius:2px">`;
  for (const r of slaves) {
    const pct = ((r.payload_bytes || 0) / maxBytes) * 100;
    const sizeStr = (r.payload_bytes || 0) >= 1024
      ? ((r.payload_bytes / 1024).toFixed(1) + ' KiB')
      : ((r.payload_bytes || 0) + ' B');
    h += `<label style="display:grid;grid-template-columns:24px 110px 1fr 90px 80px;gap:10px;align-items:center;padding:3px 8px;border-bottom:1px solid var(--rule);cursor:pointer">`;
    h += `<input type="checkbox" class="rtu-cb" data-ip="${esc(r.ip)}" checked onchange="updateRtuPickerCount()">`;
    h += `<code style="font-family:var(--mono);font-size:11px;color:var(--ink)">${esc(r.ip)}</code>`;
    h += `<div style="position:relative;background:var(--surface-2);height:10px;border-radius:1px;overflow:hidden">`;
    h += `<div style="position:absolute;left:0;top:0;bottom:0;width:${pct.toFixed(1)}%;background:var(--blue,#39c)"></div>`;
    h += `</div>`;
    h += `<div style="text-align:right">${sizeStr}</div>`;
    h += `<div style="text-align:right" class="muted">${(r.messages||0)} msg</div>`;
    h += `</label>`;
  }
  h += `</div></div>`;
  return h;
}

function wireRtuPicker() {
  updateRtuPickerCount();
}

function toggleAllRtus(check) {
  document.querySelectorAll('#rtu-picker .rtu-cb').forEach(cb => { cb.checked = !!check; });
  updateRtuPickerCount();
}

function updateRtuPickerCount() {
  const cbs = document.querySelectorAll('#rtu-picker .rtu-cb');
  if (!cbs.length) return;
  const checked = Array.from(cbs).filter(c => c.checked).length;
  const lbl = document.getElementById('rtu-picker-count');
  if (lbl) lbl.textContent = `${checked} of ${cbs.length} selected (run all = ${checked === cbs.length ? 'yes' : 'no'})`;
}

function collectSelectedRtus() {
  const cbs = Array.from(document.querySelectorAll('#rtu-picker .rtu-cb'));
  if (!cbs.length) return [];
  const all = cbs.length;
  const checked = cbs.filter(c => c.checked).map(c => c.dataset.ip);
  // "Run all" = empty list = backend default (no filter).
  if (checked.length === all) return [];
  return checked;
}

async function deletePcap(id) {
  if (!confirm('delete this pcap?')) return;
  let res = await api(`/api/pcaps/${id}`, 'DELETE');
  if (res.status === 409 && res.data && res.data.code === 'pcap_in_use') {
    const ids = (res.data.runs || []).map(r => '#' + r).join(', ');
    if (!confirm(`Runs ${ids} use this pcap. Their gap histograms and analysis will stop working. Delete anyway?`)) return;
    res = await api(`/api/pcaps/${id}?force=1`, 'DELETE');
  }
  if (!res.ok) alert(`Delete failed: ${(res.data && res.data.error) || res.status}`);
  if (selectedPcapId === id) selectedPcapId = null;
  updateSelectedLabel();
  refreshLibrary();
}

async function renamePcap(id) {
  const p = libraryPcaps.find(x => x.id === id);
  const name = prompt('new name:', p ? p.name : '');
  if (!name) return;
  await api(`/api/pcaps/${id}`, 'PATCH', { name });
  refreshLibrary();
}

// drop zone + upload
const dz = el('dropzone');
dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag'); });
dz.addEventListener('dragleave', () => dz.classList.remove('drag'));
dz.addEventListener('drop', async e => {
  e.preventDefault();
  dz.classList.remove('drag');
  for (const f of e.dataTransfer.files) await uploadFile(f);
});
el('lib-file').addEventListener('change', async e => {
  for (const f of e.target.files) await uploadFile(f);
  e.target.value = '';
});

async function uploadFile(file) {
  const status = el('upload-status');
  status.style.display = 'block';

  // Pre-upload size advisory. For >100 MB pcaps the upload itself
  // takes long enough on a LAN that a confirmation is friendly; for
  // anything in the gigabytes ask explicitly so the user doesn't
  // accidentally shove a multi-GB file at the host.
  const mb = file.size / (1024 * 1024);
  if (mb >= 100) {
    const gb = mb / 1024;
    const sizeStr = gb >= 1 ? `${gb.toFixed(2)} GB` : `${mb.toFixed(0)} MB`;
    // ~12.5 MB/s is a common LAN floor (100 Mbps); 1 Gbps is ~125 MB/s.
    // Quote the conservative estimate so the user isn't surprised.
    const slowSec = Math.round(mb / 12.5);
    const fastSec = Math.round(mb / 125);
    const ok = confirm(
      `${file.name} is ${sizeStr}.\n\n` +
      `Estimated upload time: ${fastSec}–${slowSec} seconds depending on network speed.\n` +
      `Estimated parse time after upload: ${Math.round(mb / 60)}–${Math.round(mb / 30)} seconds.\n\n` +
      `The browser will show progress while uploading and the library row will say ANALYZING while the server parses it. ` +
      `Continue?`
    );
    if (!ok) {
      status.style.display = 'none';
      return;
    }
  }

  // Switch to XHR so we can hook upload.onprogress for a real bar.
  return new Promise((resolve) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/pcaps', true);
    xhr.upload.onprogress = e => {
      if (!e.lengthComputable) return;
      const pct = Math.round((e.loaded / e.total) * 100);
      const sentMb = (e.loaded / (1024 * 1024)).toFixed(1);
      const totalMb = (e.total / (1024 * 1024)).toFixed(1);
      status.innerHTML = `
        <div style="text-align:left;font-family:var(--mono);font-size:11px;color:var(--ink-2)">
          uploading ${esc(file.name)}<br>
          <div style="margin-top:6px;height:6px;background:var(--rule-soft);position:relative;overflow:hidden">
            <div style="position:absolute;inset:0;width:${pct}%;background:var(--accent);transition:width 200ms"></div>
          </div>
          <div style="margin-top:4px;color:var(--dim)">${pct}% &middot; ${sentMb} / ${totalMb} MB</div>
        </div>
      `;
    };
    xhr.upload.onerror = () => {
      status.innerHTML = `<span style="color:var(--err)">upload network error</span>`;
      setTimeout(() => { status.style.display = 'none'; }, 4000);
      resolve();
    };
    xhr.onload = async () => {
      if (xhr.status < 200 || xhr.status >= 300) {
        let errText = xhr.responseText || `HTTP ${xhr.status}`;
        try { const j = JSON.parse(errText); errText = j.error || errText; } catch {}
        status.innerHTML = `<span style="color:var(--err)">upload failed: ${esc(errText)}</span>`;
        setTimeout(() => { status.style.display = 'none'; }, 6000);
        resolve();
        return;
      }
      let entry;
      try { entry = JSON.parse(xhr.responseText); } catch (e) {
        status.innerHTML = `<span style="color:var(--err)">bad server reply</span>`;
        setTimeout(() => { status.style.display = 'none'; }, 4000);
        resolve();
        return;
      }
      status.innerHTML = `
        <div style="text-align:left;font-family:var(--mono);font-size:11px">
          <span style="color:var(--ok)">uploaded</span>
          <span style="color:var(--dim)">&middot; ${esc(entry.name)} &middot; server is parsing…</span>
        </div>
      `;
      await refreshLibrary();
      selectPcap(entry.id);
      // Begin polling the library every 2s while any entry is still
      // analyzing. Stops automatically once everything is done.
      kickAnalyzePoll();
      setTimeout(() => { status.style.display = 'none'; }, 5000);
      resolve();
    };
    const fd = new FormData();
    fd.append('file', file);
    xhr.send(fd);
  });
}

let analyzePollTimer = null;
function kickAnalyzePoll() {
  if (analyzePollTimer) return;
  const tick = async () => {
    await refreshLibrary();
    const stillAnalyzing = libraryPcaps.some(p => !p.viability);
    if (stillAnalyzing) {
      analyzePollTimer = setTimeout(tick, 2000);
    } else {
      analyzePollTimer = null;
    }
  };
  analyzePollTimer = setTimeout(tick, 2000);
}

// raw-path escape hatch
el('raw-path').addEventListener('input', e => {
  const v = e.target.value.trim();
  selectedRawPath = v || null;
  if (v) {
    selectedPcapId = null;
    renderLibrary();
  }
  updateSelectedLabel();
});

async function inspectRaw() {
  const path = el('raw-path').value.trim();
  if (!path) return;
  const res = await api('/api/inspect', 'POST', { path });
  const out = el('inspect-result');
  if (!res.ok) {
    out.innerHTML = `<div class="err-box">${esc(res.data.error || res.data)}</div>`;
    return;
  }
  const d = res.data;
  let h = `<div class="inspect-card">`;
  h += `<div class="summary"><b>${d.packets.toLocaleString()}</b> packets &middot; <b>${d.sources.length}</b> ipv4 sources &middot; <b>${d.tcp_flows.length}</b> tcp flows &middot; <b>${fmt(d.duration_ms/1000)}</b>s</div>`;
  if (d.sources.length) {
    h += `<table class="t"><tr><th>src ip</th><th>mac</th><th class="num">pkts</th><th class="num">bytes</th><th class="num">flows</th></tr>`;
    for (const s of d.sources) {
      h += `<tr><td>${esc(s.src_ip)}</td><td><code>${esc(s.src_mac)}</code></td><td class="num">${s.packet_count}</td><td class="num">${fmtBytes(s.byte_count)}</td><td class="num">${s.flow_count}</td></tr>`;
    }
    h += `</table>`;
  }
  h += `</div>`;
  out.innerHTML = h;
}

