// 00-core.js — helpers, api(), tooltip
// Spliced into the served page by crates/webui/build.rs (classic script,
// shared global scope with the other ui/*.js files, loaded in file-name order).

// =========================================================================
//  helpers
// =========================================================================
const el  = id => document.getElementById(id);
const esc = s  => (s ?? '').toString().replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = n  => (typeof n === 'number' && !isNaN(n)) ? n.toLocaleString(undefined, {maximumFractionDigits:1}) : (n ?? '—');
const fmtBytes = b => {
  if (b == null) return '—';
  const k = 1024;
  if (b < k) return b + ' B';
  if (b < k*k) return (b/k).toFixed(1) + ' KB';
  if (b < k*k*k) return (b/(k*k)).toFixed(1) + ' MB';
  return (b/(k*k*k)).toFixed(1) + ' GB';
};
const fmtDuration = ms => {
  if (ms == null) return '—';
  if (ms < 1000) return ms.toFixed(0) + ' ms';
  if (ms < 60000) return (ms / 1000).toFixed(1) + ' s';
  const m = Math.floor(ms / 60000);
  const s = Math.round((ms % 60000) / 1000);
  return `${m}m ${s}s`;
};
const fmtTimeAgo = tsMs => {
  const d = Math.floor((Date.now() - tsMs) / 1000);
  if (d < 2) return 'just now';
  if (d < 60) return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d/60)}m ago`;
  if (d < 86400) return `${Math.floor(d/3600)}h ago`;
  return `${Math.floor(d/86400)}d ago`;
};
const basename = p => (p || '').split('/').pop() || (p || '');
// Compact UTC timestamp for pcap capture ranges: "2026-04-16 17:02Z"
const fmtUtcShort = ms => {
  if (!ms || typeof ms !== 'number') return '';
  const d = new Date(ms);
  if (isNaN(d)) return '';
  const pad = n => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}Z`;
};

// Per-tab id echoed by the server in run events, so the banner can
// tell this tab's own actions from someone else's.
const CLIENT_ID = 'tab-' + Math.random().toString(36).slice(2, 10);
async function api(path, method='GET', body=null) {
  const opts = { method, headers: { 'X-Client-Id': CLIENT_ID } };
  if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(path, opts);
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { ok: r.ok, status: r.status, data };
}

// =========================================================================
//  tooltip
// =========================================================================
const tip = el('tooltip');
function showTip(html, clientX, clientY) {
  tip.innerHTML = html;
  tip.classList.add('on');
  tip.style.left = clientX + 'px';
  tip.style.top = clientY + 'px';
}
function hideTip() { tip.classList.remove('on'); }

