// 50-shell.js — protocols, status, run events
// Spliced into the served page by crates/webui/build.rs (classic script,
// shared global scope with the other ui/*.js files, loaded in file-name order).

// =========================================================================
//  protocols + status
// =========================================================================
async function loadProtocols() {
  const res = await api('/api/protocols');
  const out = el('protocols-list');
  if (!res.ok) { out.innerHTML = '<span class="muted">error</span>'; return; }
  let h = '';
  for (const p of res.data) {
    const cls = p.status === 'ready' ? 'ready' : '';
    h += `<div class="row"><span class="dot ${cls}"></span><span class="name">${esc(p.name)}</span><span class="ports">${esc(p.status)} &middot; ${p.ports.join(',') || '—'}</span></div>`;
  }
  out.innerHTML = h;
}

async function loadStatus() {
  const res = await api('/api/status');
  if (res.ok) {
    const v = 'v' + res.data.version;
    el('version').textContent = v;
    const foot = el('foot-version');
    if (foot) foot.textContent = v;
  }
  el('host-label').textContent = location.host;
}
// Run lifecycle events (SSE). Shows a banner when another client starts
// or stops a run; T07 will polish this.
function startRunEvents() {
  if (!window.EventSource) return;
  const es = new EventSource('/api/events');
  const show = (ev) => {
    let d; try { d = JSON.parse(ev.data); } catch { return; }
    refreshRuns();
    if (d.client_id && d.client_id === CLIENT_ID) return;
    if (ev.type === 'run_finished') return;
    const t = new Date(d.time * 1000).toLocaleTimeString();
    const verb = ev.type === 'run_started' ? 'was started' : 'was stopped';
    el('run-banner-text').textContent = `Run #${d.run_id} ${verb} by ${d.client_ip} at ${t}`;
    el('run-banner').classList.add('on');
  };
  es.addEventListener('run_started', show);
  es.addEventListener('run_stopped', show);
  es.addEventListener('run_finished', show);
}
