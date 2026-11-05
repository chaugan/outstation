// 20-library.js — pcap library view: upload (button + drag and drop),
// list of pcaps as real buttons, selection, rename, delete (with the
// "runs use this pcap" confirmation), source inspection, and polling
// while the server is still analysing an upload.
'use strict';

function pcapBadges(p) {
  let b = '';
  if (p.viability && p.viability.verdict) {
    b += `<span class="badge v-${esc(p.viability.verdict)}">${esc(p.viability.verdict.replace(/_/g, ' '))}</span>`;
  } else {
    b += '<span class="badge analyzing">analysing</span>';
  }
  if (p.mac_collisions > 0) {
    b += `<span class="badge mac-warn" title="${esc(p.mac_collisions)} source IP(s) had several MACs; replay uses the most common one">MAC ×${esc(p.mac_collisions)}</span>`;
  }
  return b;
}

function pcapMeta(p) {
  const src = p.ip_sources + (p.non_ip_sources ? ` + ${p.non_ip_sources} L2` : '') + ' sources';
  return `${fmtInt(p.packets)} packets · ${src} · ${fmtInt(p.tcp_flows)} TCP flows · ${fmtDuration(p.duration_ms)} · ${fmtBytes(p.size_bytes)}`;
}

function pcapRange(p) {
  if (!p.pcap_start_unix_ms || !p.pcap_end_unix_ms) return '';
  const a = fmtUtcShort(p.pcap_start_unix_ms);
  const b = fmtUtcShort(p.pcap_end_unix_ms);
  if (!a || !b) return '';
  return a === b ? a : `${a} → ${b}`;
}

async function refreshLibrary() {
  const res = await api('/api/pcaps');
  if (!res.ok || !Array.isArray(res.data)) {
    if (!S.libraryLoaded) setText(el('lib-meta'), `could not load the library: ${res.error || 'bad reply'}`);
    return false;
  }
  const prevSel = S.library.find(p => p.id === S.selectedPcapId);
  S.library = res.data;
  S.libraryLoaded = true;
  if (S.selectedPcapId && !S.library.some(p => p.id === S.selectedPcapId)) selectPcap(null);
  const nowSel = S.library.find(p => p.id === S.selectedPcapId);
  // Analysis finished (or name changed) for the selected pcap: tell the
  // listeners so the configure summary and RTU picker appear (F098/F104).
  const selChanged = !!nowSel && (!prevSel || (!prevSel.viability) !== (!nowSel.viability) || prevSel.name !== nowSel.name);
  emit('library', { selChanged });
  if (S.library.some(p => !p.viability)) kickAnalyzePoll();
  return true;
}

function renderLibrary() {
  const list = el('pcap-list');
  const n = S.library.length;
  setText(el('lib-meta'), n ? plural(n, 'pcap') : '—');
  el('lib-empty').hidden = n > 0 || !S.libraryLoaded;
  reconcile(list, S.library, p => p.id, (li, p) => {
    li.className = 'pcap-row' + (p.id === S.selectedPcapId ? ' selected' : '');
    const range = pcapRange(p);
    const html =
      `<button type="button" class="pcap-select" data-act="pcap-select" data-id="${esc(p.id)}" data-fk="pcap-${esc(p.id)}" aria-pressed="${p.id === S.selectedPcapId}">` +
        `<span class="name">${esc(p.name)}</span>${pcapBadges(p)}` +
        `<span class="meta">${pcapMeta(p)} · uploaded ${fmtTimeAgo(p.uploaded_at_ms)}</span>` +
        (range ? `<span class="meta">captured ${esc(range)}</span>` : '') +
      '</button>' +
      '<span class="row-actions">' +
        `<button type="button" class="btn btn-text" data-act="pcap-use" data-id="${esc(p.id)}" data-fk="pcap-use-${esc(p.id)}" aria-label="Configure a run with ${esc(p.name)}">Use</button>` +
        `<button type="button" class="btn btn-text" data-act="pcap-rename" data-id="${esc(p.id)}" data-fk="pcap-rename-${esc(p.id)}" aria-label="Rename ${esc(p.name)}">Rename</button>` +
        `<a class="btn btn-text" href="/api/pcaps/${encodeURIComponent(p.id)}/download" download aria-label="Download ${esc(p.name)}">Download</a>` +
        `<button type="button" class="btn btn-text danger" data-act="pcap-delete" data-id="${esc(p.id)}" data-fk="pcap-delete-${esc(p.id)}" aria-label="Delete ${esc(p.name)}">Delete</button>` +
      '</span>';
    setHTML(li, html);
  }, { tag: 'li' });
  renderLibraryDetail();
}

function renderLibraryDetail() {
  const box = el('lib-detail');
  const p = S.library.find(x => x.id === S.selectedPcapId);
  if (!p) { setHTML(box, ''); return; }
  let h = `<div class="card"><h3 class="card-title">${esc(p.name)}</h3>`;
  h += `<p class="meta-line">${pcapMeta(p)}</p>`;
  if (p.viability) {
    h += viabilityHtml(p.viability);
  } else {
    h += '<p class="hint">The server is still analysing this pcap; this panel updates by itself.</p>';
  }
  h += '<div class="btn-row">';
  h += `<button type="button" class="btn btn-primary" data-act="pcap-use" data-id="${esc(p.id)}" data-fk="lib-detail-use">Configure a run</button>`;
  h += `<button type="button" class="btn btn-secondary" data-act="pcap-inspect" data-id="${esc(p.id)}" data-fk="lib-detail-inspect">Inspect sources</button>`;
  h += '</div><div id="inspect-result" class="inspect-result"></div></div>';
  setHTML(box, h);
}

function viabilityHtml(v) {
  let h = `<div class="viability v-${esc(v.verdict)}">`;
  h += `<p class="reason"><span class="badge v-${esc(v.verdict)}">${esc(v.verdict.replace(/_/g, ' '))}</span> ${esc(v.verdict_reason)}</p>`;
  h += `<p class="note">Estimated peak RAM ${fmtInt(v.estimated_peak_mb)} MB · ${fmtInt(v.sessions_master_mode)} master sessions · ${fmtInt(v.sessions_slave_mode)} slave sessions</p>`;
  if (v.notes && v.notes.length) {
    h += '<ul class="notes">' + v.notes.map(n => `<li>${esc(n)}</li>`).join('') + '</ul>';
  }
  return h + '</div>';
}

function selectPcap(id) {
  S.selectedPcapId = id;
  prefs.set('selectedPcap', id);
  emit('selected', id);
}

async function deletePcap(id) {
  const p = S.library.find(x => x.id === id);
  const name = p ? p.name : id;
  const ok = await askDialog({
    title: `Delete ${name}?`,
    body: 'The pcap is removed from the library. This cannot be undone.',
    confirm: 'Delete pcap',
    danger: true,
  });
  if (!ok) return;
  let res = await api(`/api/pcaps/${encodeURIComponent(id)}`, 'DELETE');
  if (res.status === 409 && res.code === 'pcap_in_use') {
    const ids = (res.data && res.data.runs) || [];
    const force = await askDialog({
      title: `${name} is used by ${plural(ids.length, 'run')}`,
      body: [
        `Runs ${ids.map(r => '#' + r).join(', ')} replayed this pcap.`,
        'After deleting it, their gap histograms and fidelity analysis stop working, because both compare against the original pcap.',
      ],
      confirm: 'Delete anyway',
      danger: true,
    });
    if (!force) return;
    res = await api(`/api/pcaps/${encodeURIComponent(id)}?force=1`, 'DELETE');
  }
  if (!res.ok) {
    notify(`Delete ${name} failed: ${res.error}`);
    return;
  }
  announce(`${name} deleted`);
  if (S.selectedPcapId === id) selectPcap(null);
  refreshLibrary();
}

async function renamePcap(id) {
  const p = S.library.find(x => x.id === id);
  const name = await askDialog({
    title: 'Rename pcap',
    input: {
      label: 'New name',
      value: p ? p.name : '',
      validate: v => {
        const t = v.trim();
        if (!t) return 'Enter a name.';
        if (t.length > 256) return `Names can be at most 256 characters (this one is ${t.length}).`;
        return null;
      },
    },
    confirm: 'Rename',
  });
  if (name === false) return;
  const res = await apiAction('Rename', `/api/pcaps/${encodeURIComponent(id)}`, 'PATCH', { name: name.trim() });
  if (res.ok) announce('Renamed');
  refreshLibrary();
}

async function inspectPcap(id) {
  const out = el('inspect-result');
  if (out) out.textContent = 'Inspecting…';
  const res = await api('/api/inspect', 'POST', { pcap_id: id });
  const node = el('inspect-result');
  if (!node) return;
  if (!res.ok) {
    node.innerHTML = `<div class="err-box" role="alert">${esc(res.error)}</div>`;
    return;
  }
  const d = res.data;
  let h = `<p class="meta-line"><b>${fmtInt(d.packets)}</b> packets · <b>${(d.sources || []).length}</b> IPv4 sources · <b>${(d.tcp_flows || []).length}</b> TCP flows · <b>${fmt((d.duration_ms || 0) / 1000)}</b> s</p>`;
  if (d.sources && d.sources.length) {
    h += '<div class="table-scroll"><table class="t"><thead><tr><th scope="col">Source IP</th><th scope="col">MAC</th><th scope="col" class="num">Packets</th><th scope="col" class="num">Bytes</th><th scope="col" class="num">Flows</th></tr></thead><tbody>';
    for (const s of d.sources) {
      h += `<tr><td>${esc(s.src_ip)}</td><td><code>${esc(s.src_mac)}</code></td><td class="num">${fmtInt(s.packet_count)}</td><td class="num">${fmtBytes(s.byte_count)}</td><td class="num">${fmtInt(s.flow_count)}</td></tr>`;
    }
    h += '</tbody></table></div>';
  }
  node.innerHTML = h;
}

actions({
  'pcap-select': b => selectPcap(b.dataset.id),
  'pcap-use': b => { selectPcap(b.dataset.id); go('configure'); },
  'pcap-rename': b => renamePcap(b.dataset.id),
  'pcap-delete': b => deletePcap(b.dataset.id),
  'pcap-inspect': b => inspectPcap(b.dataset.id),
});

// ---------------------------------------------------------------------------
// Upload

function setUploadStatus(html) {
  setHTML(el('upload-status'), html, { force: true });
}

async function uploadFiles(files) {
  for (const f of files) {
    // One at a time; stop the batch if the user cancels a large one.
    if (!(await uploadFile(f))) break;
  }
}

async function uploadFile(file) {
  const mb = file.size / (1024 * 1024);
  if (mb >= 100) {
    const gb = mb / 1024;
    const sizeStr = gb >= 1 ? `${gb.toFixed(2)} GB` : `${mb.toFixed(0)} MB`;
    const ok = await askDialog({
      title: `Upload ${file.name}?`,
      body: [
        `The file is ${sizeStr}. Uploading takes about ${Math.max(1, Math.round(mb / 125))}–${Math.max(1, Math.round(mb / 12.5))} s depending on the network, and the server then needs about ${Math.max(1, Math.round(mb / 60))}–${Math.max(1, Math.round(mb / 30))} s to parse it.`,
      ],
      confirm: 'Upload',
    });
    if (!ok) return false;
  }
  return new Promise(resolve => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/pcaps', true);
    xhr.setRequestHeader('X-Client-Id', CLIENT_ID);
    setUploadStatus(`<p>Uploading ${esc(file.name)}…</p><progress max="100" value="0" aria-label="Upload progress"></progress>`);
    xhr.upload.onprogress = e => {
      if (!e.lengthComputable) return;
      const p = Math.round((e.loaded / e.total) * 100);
      const prog = qs('#upload-status progress');
      if (prog) prog.value = p;
      const lbl = qs('#upload-status .prog-label');
      const txt = `${p}% · ${(e.loaded / 1048576).toFixed(1)} / ${(e.total / 1048576).toFixed(1)} MiB`;
      if (lbl) lbl.textContent = txt;
      else if (prog) prog.insertAdjacentHTML('afterend', `<p class="prog-label">${esc(txt)}</p>`);
    };
    const fail = msg => {
      setUploadStatus(`<p class="err">Upload of ${esc(file.name)} failed: ${esc(msg)}</p>`);
      notify(`Upload of ${file.name} failed: ${msg}`);
      resolve(true);
    };
    xhr.onerror = () => fail('network error');
    xhr.onabort = () => fail('aborted');
    xhr.onload = async () => {
      let data = null;
      try { data = JSON.parse(xhr.responseText); } catch (_) { /* not JSON */ }
      if (xhr.status < 200 || xhr.status >= 300) {
        fail((data && data.error) || xhr.responseText || `HTTP ${xhr.status}`);
        return;
      }
      if (!data || !data.id) { fail('the server sent a malformed reply'); return; }
      setUploadStatus(`<p class="ok">Uploaded ${esc(data.name)}. The server is analysing it; the badge updates when done.</p>`);
      await refreshLibrary();
      selectPcap(data.id);
      kickAnalyzePoll();
      resolve(true);
    };
    const fd = new FormData();
    fd.append('file', file);
    xhr.send(fd);
  });
}

// Poll the library every 2 s while any entry is still being analysed.
let _analyzePoll = null;
function kickAnalyzePoll() {
  if (_analyzePoll) return;
  _analyzePoll = setTimeout(async () => {
    _analyzePoll = null;
    await refreshLibrary();
  }, 2000);
}

function initLibrary() {
  wireDropzone(el('dropzone'), uploadFiles);
  S.selectedPcapId = prefs.get('selectedPcap', null);
  on('library', renderLibrary);
  on('selected', renderLibrary);
}
