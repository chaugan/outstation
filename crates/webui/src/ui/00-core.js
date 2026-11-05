// 00-core.js — helpers shared by every view: formatting, the api()
// wrapper, notifications, the confirm/prompt dialog, a tiny store and
// event bus, persisted settings, and keyed DOM updates.
//
// Spliced into the served page by crates/webui/build.rs. The ui/*.js
// files are classic scripts that share one global scope and load in
// file-name order; nothing runs until 90-main.js calls boot().
'use strict';

// ---------------------------------------------------------------------------
// DOM + formatting helpers

const el = id => document.getElementById(id);
const qs = (sel, root = document) => root.querySelector(sel);
const qsa = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const esc = s => (s ?? '').toString().replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = n => (typeof n === 'number' && !isNaN(n)) ? n.toLocaleString(undefined, { maximumFractionDigits: 1 }) : (n ?? '—');
const fmtInt = n => (typeof n === 'number' && !isNaN(n)) ? Math.round(n).toLocaleString() : '—';
const fmtBytes = b => {
  if (b == null) return '—';
  const k = 1024;
  if (b < k) return b + ' B';
  if (b < k * k) return (b / k).toFixed(1) + ' KiB';
  if (b < k * k * k) return (b / (k * k)).toFixed(1) + ' MiB';
  return (b / (k * k * k)).toFixed(2) + ' GiB';
};
const fmtDuration = ms => {
  if (ms == null || isNaN(ms)) return '—';
  if (ms < 1000) return ms.toFixed(0) + ' ms';
  if (ms < 60000) return (ms / 1000).toFixed(1) + ' s';
  const m = Math.floor(ms / 60000);
  const s = Math.round((ms % 60000) / 1000);
  if (m < 60) return `${m} min ${s} s`;
  return `${Math.floor(m / 60)} h ${m % 60} min`;
};
const fmtTimeAgo = tsMs => {
  const d = Math.floor((Date.now() - tsMs) / 1000);
  if (d < 2) return 'just now';
  if (d < 60) return `${d} s ago`;
  if (d < 3600) return `${Math.floor(d / 60)} min ago`;
  if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
  return `${Math.floor(d / 86400)} d ago`;
};
// Unix seconds → local "HH:MM:SS" today, else "YYYY-MM-DD HH:MM".
const fmtClock = secs => {
  if (!secs) return '—';
  const d = new Date(secs * 1000);
  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  const t = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  if (d.toDateString() === now.toDateString()) return t;
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${t.slice(0, 5)}`;
};
const basename = p => (p || '').split('/').pop() || (p || '');
// Compact UTC timestamp for pcap capture ranges: "2026-04-16 17:02Z".
const fmtUtcShort = ms => {
  if (!ms || typeof ms !== 'number') return '';
  const d = new Date(ms);
  if (isNaN(d)) return '';
  const pad = n => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}Z`;
};
const runNum = id => 'RUN·' + String(id).padStart(4, '0');
const pct = (a, b) => (b > 0 ? Math.min(100, Math.round((a / b) * 100)) : 0);
const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : (many || one + 's')}`;

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const isIPv4 = s => IPV4_RE.test(String(s || '').trim());
const MAC_RE = /^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$/;
const ipToInt = ip => String(ip).split('.').reduce((a, o) => (a * 256) + (parseInt(o, 10) || 0), 0);

// Read a CSS custom property from :root, for chart colours.
function getCssVar(name) {
  try { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); } catch (_) { return ''; }
}

// ---------------------------------------------------------------------------
// api(): never throws. Always resolves to {ok, status, data, error, code}.
// `error` is a human-readable message, `code` the server's error code
// (`{"error","code"}` bodies) or 'network' / 'timeout' / 'bad_json'.

const CLIENT_ID = (() => {
  const fresh = 'tab-' + Math.random().toString(36).slice(2, 10);
  try {
    // sessionStorage is per tab and survives a reload, so reloading
    // does not turn this tab's own run into "someone else's".
    let id = sessionStorage.getItem('outstation.clientId');
    if (!id) { id = fresh; sessionStorage.setItem('outstation.clientId', id); }
    return id;
  } catch (_) { return fresh; }
})();

async function api(path, method = 'GET', body = null, opts = {}) {
  const timeoutMs = opts.timeout === undefined ? 20000 : opts.timeout;
  const ctl = new AbortController();
  const timer = timeoutMs ? setTimeout(() => ctl.abort(), timeoutMs) : null;
  const init = { method, headers: { 'X-Client-Id': CLIENT_ID, Accept: 'application/json' }, signal: ctl.signal };
  if (body instanceof FormData) {
    init.body = body;
  } else if (body != null) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let r;
  let text = '';
  try {
    r = await fetch(path, init);
    text = await r.text();
  } catch (e) {
    if (timer) clearTimeout(timer);
    const aborted = e && e.name === 'AbortError';
    return {
      ok: false, status: r ? r.status : 0, data: null,
      code: aborted ? 'timeout' : 'network',
      error: aborted ? `the server did not answer within ${Math.round(timeoutMs / 1000)} s`
        : (r ? 'the connection dropped while reading the reply' : 'cannot reach the server (network error)'),
    };
  }
  if (timer) clearTimeout(timer);
  let data = null;
  let parsed = false;
  if (text) {
    try { data = JSON.parse(text); parsed = true; } catch (_) { data = text; }
  }
  const isJson = (r.headers.get('content-type') || '').includes('json');
  if (r.ok) {
    if (isJson && text && !parsed) {
      return { ok: false, status: r.status, data, code: 'bad_json', error: 'the server sent a malformed reply' };
    }
    return { ok: true, status: r.status, data, error: null, code: null, headers: r.headers };
  }
  let error = null;
  let code = null;
  if (data && typeof data === 'object') { error = data.error; code = data.code || null; }
  else if (typeof data === 'string' && data.trim()) error = data.trim().slice(0, 400);
  if (!error) error = `HTTP ${r.status}${r.statusText ? ' ' + r.statusText : ''}`;
  return { ok: false, status: r.status, data, error: String(error), code };
}

// Mutating call whose failure must be visible: shows a toast on error.
async function apiAction(label, path, method = 'POST', body = null) {
  const res = await api(path, method, body);
  if (!res.ok) notify(`${label} failed: ${res.error}`, 'error');
  return res;
}

// ---------------------------------------------------------------------------
// Notifications (toasts) and screen-reader announcements.

function notify(msg, kind = 'error', opts = {}) {
  const box = el('toasts');
  if (!box) return;
  const t = document.createElement('div');
  t.className = `toast ${kind}`;
  if (kind === 'error') t.setAttribute('role', 'alert');
  const p = document.createElement('p');
  p.textContent = msg;
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'btn btn-text';
  b.textContent = 'Dismiss';
  b.addEventListener('click', () => t.remove());
  t.append(p, b);
  box.append(t);
  while (box.children.length > 4) box.firstChild.remove();
  const ttl = opts.timeout ?? (kind === 'error' ? 15000 : 5000);
  if (ttl) setTimeout(() => t.remove(), ttl);
}

function announce(msg) {
  const n = el('sr-status');
  if (!n) return;
  n.textContent = '';
  // A separate tick so repeated identical messages are announced again.
  setTimeout(() => { n.textContent = msg; }, 30);
}

// ---------------------------------------------------------------------------
// Modal dialog (native <dialog>): confirm, or prompt when `input` is set.
// Resolves to false on cancel, true on confirm, or the entered string.

let _dlgBusy = Promise.resolve();
function askDialog(o) {
  const run = () => new Promise(resolve => {
    const dlg = el('dlg');
    const ok = el('dlg-ok');
    const cancel = el('dlg-cancel');
    const form = el('dlg-form');
    const inputWrap = el('dlg-input-wrap');
    const input = el('dlg-input');
    const inputErr = el('dlg-input-err');
    const opener = document.activeElement;
    el('dlg-title').textContent = o.title || 'Confirm';
    const body = el('dlg-body');
    body.textContent = '';
    for (const para of [].concat(o.body || [])) {
      const p = document.createElement('p');
      p.textContent = para;
      body.append(p);
    }
    if (o.list && o.list.length) {
      const ul = document.createElement('ul');
      for (const li of o.list) { const x = document.createElement('li'); x.textContent = li; ul.append(x); }
      body.append(ul);
    }
    ok.textContent = o.confirm || 'OK';
    ok.className = 'btn ' + (o.danger ? 'btn-danger' : 'btn-primary');
    cancel.textContent = o.cancel || 'Cancel';
    inputWrap.hidden = !o.input;
    inputErr.textContent = '';
    input.removeAttribute('aria-invalid');
    if (o.input) {
      el('dlg-input-label').textContent = o.input.label || 'Value';
      input.value = o.input.value || '';
    }
    let done = false;
    const finish = v => {
      if (done) return;
      done = true;
      form.removeEventListener('submit', onSubmit);
      cancel.removeEventListener('click', onCancel);
      dlg.removeEventListener('cancel', onCancel);
      if (dlg.open) dlg.close();
      if (opener && opener.isConnected && typeof opener.focus === 'function') opener.focus();
      resolve(v);
    };
    const onSubmit = e => {
      e.preventDefault();
      if (o.input) {
        const v = input.value;
        const err = o.input.validate ? o.input.validate(v) : null;
        if (err) {
          inputErr.textContent = err;
          input.setAttribute('aria-invalid', 'true');
          input.focus();
          return;
        }
        finish(v);
      } else {
        finish(true);
      }
    };
    const onCancel = e => { if (e) e.preventDefault(); finish(false); };
    form.addEventListener('submit', onSubmit);
    cancel.addEventListener('click', onCancel);
    dlg.addEventListener('cancel', onCancel);
    if (typeof dlg.showModal === 'function') dlg.showModal(); else dlg.setAttribute('open', '');
    (o.input ? input : (o.danger ? cancel : ok)).focus();
    if (o.input) input.select();
  });
  // One dialog at a time.
  const p = _dlgBusy.then(run);
  _dlgBusy = p.catch(() => {});
  return p;
}

// ---------------------------------------------------------------------------
// Store + event bus. Views subscribe with on('runs', fn) etc.

const S = {
  library: [],
  libraryLoaded: false,
  selectedPcapId: null,
  runs: [],
  runsLoaded: false,
  runDetail: new Map(),   // id -> full /api/runs/:id body
  protocols: [],
  nics: [],
  status: null,
  active: null,           // {run_id, client_ip, started_at} from SSE / status
  view: 'library',
};
const _bus = new EventTarget();
function on(name, fn) { _bus.addEventListener(name, e => fn(e.detail)); }
function emit(name, detail) { _bus.dispatchEvent(new CustomEvent(name, { detail })); }

function libraryName(pcapId, fallbackPath) {
  const p = pcapId && S.library.find(x => x.id === pcapId);
  if (p) return p.name;
  return fallbackPath ? basename(fallbackPath) : (pcapId || '—');
}

// Persisted per-browser settings. Every access is guarded: storage can
// be disabled, full, or throw in private windows.
const prefs = {
  get(key, dflt) {
    try {
      const v = localStorage.getItem('outstation.' + key);
      return v == null ? dflt : JSON.parse(v);
    } catch (_) { return dflt; }
  },
  set(key, value) {
    try { localStorage.setItem('outstation.' + key, JSON.stringify(value)); } catch (_) { /* storage unavailable */ }
  },
  del(key) {
    try { localStorage.removeItem('outstation.' + key); } catch (_) { /* storage unavailable */ }
  },
};

// ---------------------------------------------------------------------------
// Keyed DOM updates. setHTML only touches a node when its markup changed,
// leaves it alone while the user types in it or has text selected in it,
// and restores focus to the element with the same data-fk afterwards.

function focusKeyIn(node) {
  const a = document.activeElement;
  if (!a || a === document.body || !node.contains(a)) return null;
  if (a.dataset && a.dataset.fk) return { fk: a.dataset.fk };
  if (a.id) return { id: a.id };
  return null;
}
function isBusyIn(node) {
  const a = document.activeElement;
  if (a && node.contains(a)) {
    const tag = a.tagName;
    if (tag === 'TEXTAREA' || tag === 'SELECT') return true;
    if (tag === 'INPUT' && !['checkbox', 'radio', 'button', 'submit', 'file'].includes(a.type)) return true;
  }
  const sel = window.getSelection && window.getSelection();
  if (sel && !sel.isCollapsed && sel.anchorNode && node.contains(sel.anchorNode)) return true;
  return false;
}
function restoreFocus(node, key) {
  if (!key) return;
  let t = null;
  if (key.fk) t = node.querySelector(`[data-fk="${CSS.escape(key.fk)}"]`);
  else if (key.id) t = document.getElementById(key.id);
  if (t && typeof t.focus === 'function') t.focus({ preventScroll: true });
}
function setHTML(node, html, opts = {}) {
  if (!node) return false;
  if (node._html === html) return false;
  if (!opts.force && node._html !== undefined && isBusyIn(node)) return false;
  const key = focusKeyIn(node);
  node.innerHTML = html;
  node._html = html;
  restoreFocus(node, key);
  return true;
}
function setText(node, text) {
  if (node && node.textContent !== text) node.textContent = text;
}

// Make container's children match `items` (by key), reusing existing
// child elements. `render(node, item, isNew)` fills a child.
function reconcile(container, items, keyOf, render, opts = {}) {
  const tag = opts.tag || 'div';
  const existing = new Map();
  for (const c of Array.from(container.children)) {
    if (c.dataset.key != null) existing.set(c.dataset.key, c);
    else c.remove();
  }
  let prev = null;
  for (const it of items) {
    const k = String(keyOf(it));
    let node = existing.get(k);
    const isNew = !node;
    if (isNew) {
      node = document.createElement(tag);
      node.dataset.key = k;
      if (opts.className) node.className = opts.className;
    }
    existing.delete(k);
    render(node, it, isNew);
    const want = prev ? prev.nextSibling : container.firstChild;
    if (node !== want) container.insertBefore(node, want);
    prev = node;
  }
  for (const n of existing.values()) n.remove();
}

// ---------------------------------------------------------------------------
// Delegated actions: <button data-act="name">. One listener for the page
// instead of inline onclick handlers built from escaped strings.

const ACTIONS = Object.create(null);
function actions(map) { Object.assign(ACTIONS, map); }
document.addEventListener('click', e => {
  const t = e.target.closest('[data-act]');
  if (!t || t.disabled) return;
  const fn = ACTIONS[t.dataset.act];
  if (!fn) return;
  if (t.tagName === 'A' && t.getAttribute('href') === '#') e.preventDefault();
  fn(t, e);
});
actions({
  'dismiss-banner': b => { const n = el(b.dataset.target); if (n) n.hidden = true; },
});

// ---------------------------------------------------------------------------
// Drop zones: real buttons that open their file input and accept drops.

function wireDropzone(btn, onFiles) {
  const input = el(btn.dataset.fileInput);
  btn.addEventListener('click', () => input.click());
  input.addEventListener('change', () => {
    const files = Array.from(input.files || []);
    input.value = '';
    if (files.length) onFiles(files);
  });
  let depth = 0;
  btn.addEventListener('dragenter', e => { e.preventDefault(); depth++; btn.classList.add('drag'); });
  btn.addEventListener('dragover', e => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
  btn.addEventListener('dragleave', () => { depth = Math.max(0, depth - 1); if (!depth) btn.classList.remove('drag'); });
  btn.addEventListener('drop', e => {
    e.preventDefault();
    depth = 0;
    btn.classList.remove('drag');
    const files = Array.from((e.dataTransfer && e.dataTransfer.files) || []);
    if (files.length) onFiles(files);
  });
}

// ---------------------------------------------------------------------------
// Tooltip for SVG chart buckets.

const tip = el('tooltip');
function showTip(html, x, y) {
  tip.innerHTML = html;
  tip.classList.add('on');
  tip.style.left = x + 'px';
  tip.style.top = y + 'px';
}
function hideTip() { tip.classList.remove('on'); }

// ---------------------------------------------------------------------------
// Inline form-field errors.

function fieldError(id, msg) {
  const input = el(id);
  const err = el(id + '-err');
  if (err) err.textContent = msg || '';
  if (input) {
    if (msg) input.setAttribute('aria-invalid', 'true');
    else input.removeAttribute('aria-invalid');
  }
  return !msg;
}

// Hint for common unprivileged-server failures.
function explainRunError(msg) {
  const m = String(msg || '');
  if (/operation not permitted|permission denied|EPERM/i.test(m)) {
    return 'The server lacks network privileges (CAP_NET_ADMIN / CAP_NET_RAW). Start it through the systemd unit, or grant those capabilities to the binary.';
  }
  if (/set force|protected/i.test(m)) {
    return 'The run touched a protected NIC or address. Pick another interface, or enable "Override NIC and address protection" in Configure and confirm.';
  }
  return '';
}
