#!/usr/bin/env node
// Browser smoke test for the outstation web UI.
//
// Usage:
//   node scripts/ui-smoke.mjs [BASE_URL] [--out DIR] [--pcap FILE] [--no-runs]
//
//   BASE_URL  default $UI_BASE or http://127.0.0.1:18105
//   --out     screenshot directory (default ./ui-smoke-shots)
//   --pcap    pcap to upload (default examples/synth_iec104_rtus200_ts.pcap)
//   --no-runs skip the steps that start runs (they are skipped anyway
//             when another run is already active)
//   --captures-dir DIR  the server's captures directory, when it is on
//             this machine and writable: the compare flow then gives
//             its candidate run a replay capture (a copy of --pcap), so
//             the live "analysis_missing → Analyze → retry" path runs
//             end to end instead of stopping at "no capture"
//
// Playwright is loaded from $PLAYWRIGHT_DIR (default
// /opt/code/tools/browser/node_modules/playwright). Runs Chromium at
// 1440x900 and 390x844 and WebKit at 1440x900, walks every view and
// asserts: no console errors, no horizontal overflow, every control
// labelled, text contrast >= 4.5:1 (3:1 for large text), no body text
// under 12px, keyboard reachability of the main flow, a single live
// WebSocket, invalid rewrite-map JSON blocking START, the RTU picker
// keeping its selection, the post-upload panel refreshing by itself,
// the start-failure message, and the concurrent-run banner plus the
// 409 run_active message across two browser contexts.
// Wave 3 (T19): profiles CRUD with the 409 profile_exists message, the
// IEC 104 fault-plan and command editors (client validation, proto_config
// serialisation, persistence), re-run (whose failure on an unprivileged
// server must be explained) and "Load into Configure", auto-analysis
// state on cards, the health chip and /metrics link, and the Compare
// view: hash-kept selection and thresholds, analysis_missing → Analyze
// → automatic retry, fleet and per-RTU tables, sort and filter.
// T17 (fx2): verdict/outcome colouring (N14), the phone chrome not
// covering the RTU picker (N24), neutral selection (N26), the running
// card fed by the WebSocket with thinned polling (F105), /api/runs
// pagination and "Load older runs" (F054) and the HTML report export
// (F131).
// T20 (ui3): every engine walk also runs in the dark theme; first-run
// guides on an empty server; viability chips; the ⋯ menu button from
// the keyboard; scenario presets and the sticky (desktop) / collapsed
// (phone) summary; the analysis overview (hero, heatmap with keyboard
// path and text alternative, dimensions, collapsed sections, one screen
// at 1440x900, 800 endpoints fast, charts on the page theme); the live
// dashboard strip; run-card status line; delete with Undo for profiles
// and finished runs; the theme toggle and keyboard shortcuts.
// T20b: live ack-latency p50 / p99 in the live strip and the diagram's
// session table; friendly regression labels and ms in Compare; the
// SCADA-gateway section disabled (and never sent) in master role.
// Exits non-zero when any check fails. Runs it starts are stopped and
// deleted at the end; the uploaded pcap is left in the library.

import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';

const argv = process.argv.slice(2);
const flag = (name, dflt) => {
  const i = argv.indexOf(name);
  if (i < 0) return dflt;
  const v = argv[i + 1];
  argv.splice(i, 2);
  return v;
};
const NO_RUNS = argv.includes('--no-runs');
if (NO_RUNS) argv.splice(argv.indexOf('--no-runs'), 1);
const OUT = flag('--out', 'ui-smoke-shots');
const CAPTURES_DIR = flag('--captures-dir', null);
const PCAP = flag('--pcap', 'examples/synth_iec104_rtus200_ts.pcap');
const BASE = (argv[0] || process.env.UI_BASE || 'http://127.0.0.1:18105').replace(/\/$/, '');
const PW = process.env.PLAYWRIGHT_DIR || '/opt/code/tools/browser/node_modules/playwright';
const SYSDEPS = '/opt/code/tools/browser/sysdeps/extracted/usr/lib/x86_64-linux-gnu';
if (fs.existsSync(SYSDEPS) && !(process.env.LD_LIBRARY_PATH || '').includes(SYSDEPS)) {
  process.env.LD_LIBRARY_PATH = SYSDEPS + (process.env.LD_LIBRARY_PATH ? ':' + process.env.LD_LIBRARY_PATH : '');
}
const require = createRequire(import.meta.url);
const { chromium, webkit } = require(PW);
fs.mkdirSync(OUT, { recursive: true });

const failures = [];
const notes = [];
let current = '';
function check(cond, msg) {
  if (cond) { console.log(`  ok   ${msg}`); return true; }
  console.log(`  FAIL ${msg}`);
  failures.push(`[${current}] ${msg}`);
  return false;
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
const MASTER_TARGET = '192.0.2.10';
const UNDO_MS = 1500;   // ?undo_ms= for the deferred-delete checks

async function apiGet(p) {
  const r = await fetch(BASE + p);
  return r.json();
}
async function apiSend(p, method, body) {
  const r = await fetch(BASE + p, {
    method,
    headers: { Origin: BASE, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  return r;
}

// Count WebSockets the page creates, so "one live socket" is measurable.
const INIT = () => {
  const W = window.WebSocket;
  window.__ws = [];
  window.WebSocket = class extends W {
    constructor(...a) { super(...a); window.__ws.push(this); }
  };
};

// In-page audits: overflow, labels, contrast, minimum font size.
const AUDIT = () => {
  const res = { overflow: document.documentElement.scrollWidth - window.innerWidth, unlabelled: [], lowContrast: [], tiny: [] };
  for (const c of document.querySelectorAll('input, select, textarea')) {
    if (c.type === 'hidden') continue;
    const named = (c.labels && c.labels.length) || c.getAttribute('aria-label') || c.getAttribute('aria-labelledby');
    if (!named) res.unlabelled.push(c.id || c.name || c.outerHTML.slice(0, 80));
  }
  const parse = s => {
    const m = s.match(/rgba?\(([^)]+)\)/);
    if (!m) return [0, 0, 0, 0];
    const p = m[1].split(/[ ,/]+/).filter(Boolean).map(Number);
    return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
  };
  const lum = ([r, g, b]) => {
    const f = c => { c /= 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
  const bgOf = el => {
    const layers = [];
    for (let e = el; e; e = e.parentElement) {
      const c = parse(getComputedStyle(e).backgroundColor);
      if (c[3] > 0) { layers.push(c); if (c[3] >= 1) break; }
    }
    let col = [255, 255, 255];
    for (const l of layers.reverse()) col = col.map((v, i) => l[i] * l[3] + v * (1 - l[3]));
    return col;
  };
  const seen = new Set();
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (!n.textContent.trim()) continue;
    const el = n.parentElement;
    if (!el || seen.has(el)) continue;
    seen.add(el);
    if (el.closest('svg, option, script, style, .sr-only, [aria-hidden="true"], :disabled, .tooltip, noscript')) continue;
    const rects = el.getClientRects();
    if (!rects.length) continue;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden') continue;
    let op = 1;
    for (let e = el; e; e = e.parentElement) op *= Number(getComputedStyle(e).opacity);
    if (op < 0.99) continue;   // animated or deliberately faded (e.g. pulsing badge)
    const size = parseFloat(cs.fontSize);
    if (size < 12) res.tiny.push(`${size}px "${n.textContent.trim().slice(0, 40)}"`);
    const fg = parse(cs.color);
    const bg = bgOf(el);
    const fgc = fg.slice(0, 3).map((v, i) => v * fg[3] + bg[i] * (1 - fg[3]));
    const r = ratio(fgc, bg);
    const large = size >= 24 || (size >= 18.66 && Number(cs.fontWeight) >= 700);
    if (r < (large ? 3 : 4.5)) res.lowContrast.push(`${r.toFixed(2)} "${n.textContent.trim().slice(0, 40)}" (${cs.color} on rgb(${bg.map(Math.round).join(',')}))`);
  }
  return res;
};

async function audit(page, label, shot) {
  const a = await page.evaluate(AUDIT);
  check(a.overflow <= 0, `${label}: no horizontal overflow (${a.overflow}px)`);
  check(!a.unlabelled.length, `${label}: every control has a label${a.unlabelled.length ? ' — missing: ' + a.unlabelled.slice(0, 6).join(', ') : ''}`);
  check(!a.lowContrast.length, `${label}: text contrast >= 4.5${a.lowContrast.length ? ' — ' + a.lowContrast.slice(0, 4).join(' | ') : ''}`);
  check(!a.tiny.length, `${label}: no text under 12px${a.tiny.length ? ' — ' + a.tiny.slice(0, 4).join(' | ') : ''}`);
  if (shot) await page.screenshot({ path: path.join(OUT, `${current}-${shot}.png`), fullPage: true });
}

async function tabWalk(page, max, wanted) {
  await page.evaluate(() => { document.activeElement && document.activeElement.blur(); window.scrollTo(0, 0); });
  await page.focus('body').catch(() => {});
  const reached = new Set();
  for (let i = 0; i < max && reached.size < wanted.length; i++) {
    await page.keyboard.press('Tab');
    const hit = await page.evaluate(sels => sels.filter(s => document.activeElement && document.activeElement.matches(s)), wanted);
    for (const h of hit) reached.add(h);
  }
  return wanted.filter(w => !reached.has(w));
}

async function go(page, view) {
  await page.goto(`${BASE}/#/${view}`);
  await page.waitForSelector(`#view-${view.split('/')[0]}:not([hidden])`);
  await page.waitForTimeout(900);
}

function trackConsole(page, bucket) {
  page.on('console', m => {
    if (m.type() !== 'error') return;
    const t = m.text();
    // HTTP error responses the UI handles (409, 400, ...) are logged by
    // the browser as resource errors; they are not script errors.
    if (/Failed to load resource|status of 4\d\d|status of 5\d\d/.test(t)) return;
    bucket.push(t);
  });
  page.on('pageerror', e => bucket.push('pageerror: ' + e.message));
}

const pcapName = path.basename(PCAP);
const startedRuns = [];
const flow = { firstId: null, slaveId: null, cmpA: null, cmpB: null };
const SMOKE_PROFILE = `smoke-profile-${process.pid}`;

async function waitRun(id, pred, ms = 30000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const r = (await apiGet('/api/runs')).find(x => x.id === id);
    if (r && pred(r)) return r;
    await sleep(500);
  }
  return null;
}

// Upload PCAP as the target-side capture of run `id` (a manual analysis).
async function uploadAnalysis(id) {
  const fd = new FormData();
  fd.append('file', new Blob([fs.readFileSync(PCAP)]), pcapName);
  fd.append('mode', 'generic');
  fd.append('run_id', String(id));
  const r = await fetch(`${BASE}/api/analyze?run_id=${id}`, { method: 'POST', headers: { Origin: BASE }, body: fd });
  return r.ok;
}

// A stopped slave run (starts fine unprivileged: its sessions stay pending).
async function stoppedSlaveRun(pcapId) {
  const r = await apiSend('/api/run', 'POST', { pcap_id: pcapId, mode: 'benchmark', role: 'slave', target_ip: '0.0.0.0', warmup_secs: 0, iterations: 1 });
  if (!r.ok) return null;
  const { id } = await r.json();
  startedRuns.push(id);
  await sleep(1000);
  await apiSend(`/api/runs/${id}/stop`, 'POST');
  await waitRun(id, x => x.status !== 'running', 20000);
  return id;
}

async function ensurePcap(page) {
  const lib = await apiGet('/api/pcaps');
  const have = lib.find(p => p.name === pcapName);
  if (have) {
    await go(page, 'library');
    await page.click(`.pcap-select[data-id="${have.id}"]`);
    return have.id;
  }
  await go(page, 'library');
  await page.setInputFiles('#lib-file', PCAP);
  await page.waitForSelector('.pcap-row', { timeout: 30000 });
  await page.waitForFunction(() => !document.querySelector('.pcap-row .badge.analyzing'), null, { timeout: 60000 });
  check(true, 'upload finished and the analysing badge cleared');
  // F098/F104: the configure panel must refresh by itself (no click).
  await page.click('.nav a[data-view="configure"]');
  const rows = await page.waitForFunction(() => document.querySelectorAll('#rtu-tbody tr').length, null, { timeout: 10000 }).then(h => h.jsonValue()).catch(() => 0);
  check(rows > 0, `RTU picker appears after upload without another click (${rows} rows)`);
  const lib2 = await apiGet('/api/pcaps');
  return (lib2.find(p => p.name === pcapName) || {}).id;
}

async function activeRun() {
  const st = await apiGet('/api/status');
  return st.active_run || null;
}

async function engineWalk(browser, name, viewport, deep, scheme = 'light') {
  current = name;
  console.log(`\n== ${name} ==`);
  const ctx = await browser.newContext({ viewport, colorScheme: scheme });
  await ctx.addInitScript(INIT);
  const page = await ctx.newPage();
  const errors = [];
  trackConsole(page, errors);
  const runPosts = [];
  page.on('request', r => { if (r.url().endsWith('/api/run') && r.method() === 'POST') runPosts.push(r); });

  const pcapId = await ensurePcap(page);
  check(!!pcapId, 'pcap is in the library');

  await go(page, 'library');
  const th = await page.evaluate(() => document.documentElement.dataset.theme);
  check(th === scheme, `theme follows prefers-color-scheme (${th})`);
  await audit(page, 'library', 'library');
  await libraryChecks(page);
  const missLib = await tabWalk(page, 40, ['#dropzone', '.pcap-select', '.pcap-row .menu-btn']);
  check(!missLib.length, `keyboard reaches the upload button and the pcap rows${missLib.length ? ' — missing ' + missLib : ''}`);
  const dz = await page.evaluate(() => getComputedStyle(document.querySelector('#dropzone')).display);
  check(dz !== 'inline', `drop zone is a block-level box (${dz})`);

  await go(page, 'configure');
  await page.selectOption('#cfg-pcap', pcapId);
  await page.click('label[for="mode-benchmark"]');
  await page.waitForSelector('#rtu-tbody tr');
  await audit(page, 'configure', 'configure');
  await chromeChecks(page, viewport);
  await configureChecks(page, viewport);
  const missCfg = await tabWalk(page, 600, ['#cfg-pcap', '#cfg-target-ip', '#start-btn']);
  check(!missCfg.length, `keyboard reaches pcap, target and start${missCfg.length ? ' — missing ' + missCfg : ''}`);

  if (deep) {
    // Picker: select none, then a shift-click range of 5, which must
    // survive a role switch back and forth and a reload (F099, F125).
    await page.click('label[for="role-slave"]');
    await page.waitForSelector('#rtu-tbody tr');
    await page.click('[data-act="rtu-none"]');
    const boxes = page.locator('#rtu-tbody .rtu-cb');
    await boxes.nth(0).click();
    await boxes.nth(4).click({ modifiers: ['Shift'] });
    const c1 = await page.textContent('#rtu-count');
    check(/^5 of/.test(c1), `shift-click selects a range (${c1})`);
    await page.click('label[for="role-master"]');
    await page.click('label[for="role-slave"]');
    const c2 = await page.textContent('#rtu-count');
    check(/^5 of/.test(c2), `selection kept across re-render (${c2})`);
    await page.fill('#rtu-filter', '192.168.10.1');
    const filtered = await page.locator('#rtu-tbody tr').count();
    check(filtered > 0 && filtered < 200, `filter narrows the list (${filtered} rows)`);
    await page.fill('#rtu-filter', '');
    await page.fill('#cfg-target-ip', '10.9.8.7');
    await page.waitForTimeout(400);
    await page.reload();
    await page.waitForSelector('#rtu-tbody tr');
    const c3 = await page.textContent('#rtu-count');
    const tip = await page.inputValue('#cfg-target-ip');
    check(/^5 of/.test(c3) && tip === '10.9.8.7', `form and selection persist across reload (${c3}, ${tip})`);

    // F096: invalid rewrite-map JSON blocks START with an inline error.
    await page.fill('#cfg-proto-config', '{"common_address": {"1": 100},}');
    const before = runPosts.length;
    await page.click('#start-btn');
    await page.waitForTimeout(300);
    const err = await page.textContent('#cfg-proto-config-err');
    check(err.trim().length > 0 && runPosts.length === before, `invalid JSON blocks start (${err.trim().slice(0, 60)})`);
    await page.fill('#cfg-proto-config', '');
    // Link parameters: t2 >= t1 is rejected inline.
    await page.click('#link-params > summary');
    await page.fill('#cfg-t1', '5');
    await page.fill('#cfg-t2', '6');
    await page.click('#start-btn');
    await page.waitForTimeout(200);
    const t2err = await page.textContent('#cfg-t2-err');
    check(/less than/.test(t2err), `t2 >= t1 is rejected inline (${t2err.trim()})`);
    await page.fill('#cfg-t1', '');
    await page.fill('#cfg-t2', '');
    await page.click('[data-act="rtu-all"]');
    await page.click('label[for="role-master"]');
  }

  await go(page, 'runs');
  await audit(page, 'runs', 'runs');
  await go(page, 'analysis');
  await audit(page, 'analysis', 'analysis');
  await colourChecks(page);
  await heatmapChecks(page, viewport);
  await go(page, 'library');
  // The tint is the theme's --blue (31,74,120 light; 143,184,230 dark).
  const sel = await page.evaluate(() => {
    const r = document.querySelector('.pcap-row.selected');
    if (!r) return null;
    const probe = document.createElement('span');
    probe.style.color = 'var(--blue)';
    document.body.append(probe);
    const blue = getComputedStyle(probe).color.match(/\d+, \d+, \d+/)[0];
    probe.remove();
    return { bg: getComputedStyle(r).backgroundColor, blue };
  });
  if (sel) check(sel.bg.includes(sel.blue), `selected pcap row is tinted neutral blue, not the error family (${sel.bg})`);
  if (flow.cmpA && flow.cmpB) {
    await go(page, `compare/${flow.cmpA}/${flow.cmpB}`);
    await page.waitForSelector('#cmp-tbody tr', { timeout: 15000 }).catch(() => {});
    await audit(page, 'compare (result)', 'compare');
  } else {
    await go(page, 'compare');
    await audit(page, 'compare', 'compare');
  }

  const live = await page.evaluate(() => (window.__ws || []).filter(s => s.readyState <= 1).length);
  check(live <= 1, `at most one live WebSocket (${live})`);
  check(!errors.length, `no console errors${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  await ctx.close();
  return pcapId;
}


// N24: on a phone the sticky top bar stays one compact block with a
// single scrolling nav row, the start bar is not sticky, and the RTU
// picker is not covered by either.
async function chromeChecks(page, viewport) {
  if (viewport.width > 600) return;
  const m = await page.evaluate(() => {
    const top = document.querySelector('.topbar').getBoundingClientRect().height;
    const nav = document.querySelector('.nav');
    const navH = nav.getBoundingClientRect().height;
    const sb = getComputedStyle(document.querySelector('.start-bar')).position;
    const row = document.querySelector('#rtu-tbody tr');
    let covered = null;
    if (row) {
      row.scrollIntoView({ block: 'center' });
      const r = row.getBoundingClientRect();
      const hit = document.elementFromPoint(Math.min(r.left + 30, innerWidth - 5), r.top + r.height / 2);
      covered = !(hit && row.contains(hit));
    }
    return { top, navH, sb, covered, navScroll: nav.scrollWidth > nav.clientWidth };
  });
  check(m.top <= 110, `phone top bar is compact (${Math.round(m.top)}px)`);
  check(m.navH <= 40, `phone nav is one row (${Math.round(m.navH)}px${m.navScroll ? ', scrolls' : ''})`);
  check(m.sb !== 'sticky' && m.sb !== 'fixed', `phone start bar is not sticky (${m.sb})`);
  check(m.covered === false, `RTU picker row is not covered by the sticky bars (${m.covered === null ? 'no picker row' : m.covered ? 'covered' : 'visible'})`);
}

// N14: colour follows the verdict/outcome, never the score. A synthetic
// report: a failing (degraded) endpoint scoring 100 and a stopped run.
async function colourChecks(page) {
  const c = await page.evaluate(() => {
    an.report = {
      run_id: 999999, verdict: 'stopped_clean', score_pct: 100, verdict_reason: 'synthetic', protocol: 'iec104', role: 'slave', mode: 'generic',
      run_warning: 'the run being analysed was STOPPED before it finished', notes: [],
      fleet: { slave_count: 2, fully_correct: 1, partial: 0, failed: 1, not_attempted: 0 },
      slaves: [
        { slave_ip: '10.250.0.1', outcome: 'fail', verdict: 'degraded', score_pct: 100, packets: 10, delivered_iframes: 8, expected_iframes: 8, startdt_handshake_ok: true, sessions: 1 },
        { slave_ip: '10.250.0.2', outcome: 'pass', verdict: 'good_delivery', score_pct: 100, packets: 10, delivered_iframes: 8, expected_iframes: 8, startdt_handshake_ok: true, sessions: 1 },
      ],
    };
    an.analysisId = null;
    an.details = new Map();
    renderAnalysis();
    const cls = ip => { const row = document.querySelector(`.an-slave-row[data-ip="${ip}"] summary`); return row ? row.children[5].className : null; };
    const out = { fleet: document.querySelector('.an-summary .an-score').className, bad: cls('10.250.0.1'), good: cls('10.250.0.2') };
    document.querySelector('#an-result').innerHTML = '';
    an.report = null;
    return out;
  });
  check(c.bad && !/\bok\b/.test(c.bad), `failing endpoint with score 100 is not green (${c.bad})`);
  check(/\bok\b/.test(c.good || ''), `passing endpoint is green (${c.good})`);
  check(!/\bok\b/.test(c.fleet), `stopped run is not shown as a plain pass (${c.fleet})`);
}

// F054: /api/runs pages; the Runs view loads older pages on demand.
async function paginationFlow(browser) {
  current = 'pagination';
  console.log('\n== runs pagination ==');
  const all = await apiGet('/api/runs?limit=1000');
  const total = all.length;
  const r1 = await fetch(`${BASE}/api/runs?limit=1`);
  const next = r1.headers.get('x-next-before');
  if (total >= 2) check(next === String(all[0].id), `/api/runs?limit=1 says where the next page starts (X-Next-Before ${next})`);
  if (next) {
    const p2 = await (await fetch(`${BASE}/api/runs?limit=1&before=${next}`)).json();
    check(p2.length === 1 && p2[0].id === all[1].id, `the next page continues the list (${p2.map(r => r.id)})`);
  }
  if (total < 3) { notes.push(`pagination UI not exercised: only ${total} runs`); return; }
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await ctx.addInitScript(INIT);
  const page = await ctx.newPage();
  const errors = [];
  trackConsole(page, errors);
  await page.goto(`${BASE}/?runs_page=2#/runs`);
  await page.waitForSelector('#runs-list > li');
  const n1 = await page.locator('#runs-list > li').count();
  check(n1 === 2, `the first page shows page-size runs (${n1})`);
  const btn = '[data-fk="runs-older"]';
  check(await page.isVisible(btn), '"Load older runs" is offered');
  await page.click(btn);
  await page.waitForFunction(n => document.querySelectorAll('#runs-list > li').length > n, n1, { timeout: 10000 }).catch(() => {});
  const n2 = await page.locator('#runs-list > li').count();
  check(n2 === Math.min(4, total), `older runs are appended (${n1} → ${n2})`);
  await page.waitForTimeout(4500);
  const n3 = await page.locator('#runs-list > li').count();
  check(n3 === n2, `loaded older runs survive the next poll (${n3})`);
  check(!errors.length, `no console errors${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  await ctx.close();
}

async function runFlows(browser, pcapId) {
  current = 'runs-flow';
  console.log('\n== run flows (two contexts) ==');
  if (NO_RUNS) { notes.push('run flows skipped (--no-runs)'); return; }
  if (await activeRun()) { notes.push('run flows skipped: a run is already active on this server'); return; }
  const ctxA = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const ctxB = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await ctxA.addInitScript(INIT);
  await ctxB.addInitScript(INIT);
  const a = await ctxA.newPage();
  const b = await ctxB.newPage();
  const errors = [];
  trackConsole(a, errors);
  trackConsole(b, errors);

  // 1. Master run: on an unprivileged server it fails at network setup;
  //    the failure must appear next to the start button.
  await go(a, 'configure');
  await a.selectOption('#cfg-pcap', pcapId);
  await a.click('label[for="mode-benchmark"]');
  await a.click('label[for="role-master"]');
  // TEST-NET-1: unicast (the server refuses loopback targets, N9) and
  // never reachable, so an unprivileged server fails the run at setup.
  await a.fill('#cfg-target-ip', MASTER_TARGET);
  await a.fill('#cfg-warmup', '0');
  await a.click('#start-btn');
  await a.waitForFunction(() => /Run #\d+/.test(document.querySelector('#run-result').textContent) || document.querySelector('#run-error').textContent.trim(), null, { timeout: 15000 });
  const m1 = (await a.textContent('#run-result')).match(/Run #(\d+)/);
  const firstId = m1 ? Number(m1[1]) : null;
  if (firstId) startedRuns.push(firstId);
  flow.firstId = firstId;
  // Wait for the run to end (an unprivileged server fails it at network setup).
  await a.waitForFunction(() => /Run #\d+ (failed|completed|stopped|partial)/.test(document.querySelector('#run-result').textContent), null, { timeout: 30000 }).catch(() => {});
  const resText = (await a.textContent('#run-result')) + ' ' + (await a.textContent('#run-error'));
  check(/run #\d+/i.test(resText), `start result names the run (${resText.trim().slice(0, 160)})`);
  if (/failed/i.test(resText)) {
    check(/privileges|CAP_NET|protected|override|refus/i.test(resText), 'failure message explains the cause');
  } else notes.push('master run did not fail (privileged server?)');
  await a.screenshot({ path: path.join(OUT, 'flow-start-result.png'), fullPage: false });
  const ar = await activeRun();
  if (ar) { await apiSend(`/api/runs/${ar.run_id}/stop`, 'POST'); await sleep(1500); }

  // 2. Slave run from A while B watches Runs: B shows the banner.
  await go(b, 'runs');
  await go(a, 'configure');
  await a.click('label[for="role-slave"]');
  await a.fill('#cfg-target-ip', '');
  await a.click('#start-btn');
  await a.waitForFunction(() => /Run #\d+ (started|is running)/.test(document.querySelector('#run-result').textContent), null, { timeout: 20000 });
  const slaveId = Number((await a.textContent('#run-result')).match(/#(\d+)/)[1]);
  startedRuns.push(slaveId);
  flow.slaveId = slaveId;
  const banner = await b.waitForSelector('#run-banner:not([hidden])', { timeout: 10000 }).then(() => b.textContent('#run-banner-text')).catch(() => '');
  check(new RegExp(`Run #${slaveId} was started by`).test(banner), `other tab shows the concurrent-run banner (${banner.trim()})`);
  const own = await a.isVisible('#run-banner');
  check(!own, 'the starting tab does not show the banner for its own run');

  // 3. A second start while the slave run is active: clear 409 message.
  await a.click('#start-btn');
  await a.waitForFunction(() => /already active/.test(document.querySelector('#run-error').textContent), null, { timeout: 10000 }).catch(() => {});
  const e409 = await a.textContent('#run-error');
  check(/already active/.test(e409), `409 run_active is shown clearly (${e409.trim().slice(0, 120)})`);
  await a.screenshot({ path: path.join(OUT, 'flow-409.png') });

  // 4. B: live diagram, single socket, sessions table, keyed updates.
  await b.waitForSelector('#diagram-section:not([hidden])', { timeout: 10000 }).catch(() => {});
  await b.waitForTimeout(2500);
  check(await b.isVisible('#diagram-section'), 'live diagram is shown for the running run');
  const strip = await b.evaluate(() => {
    const n = document.querySelector('#live-strip');
    return n && !n.hidden ? { text: n.textContent, spark: !!n.querySelector('.ls-spark'), bar: !!n.querySelector('.state-bar') } : null;
  });
  check(strip && strip.spark && strip.bar && /In flight/.test(strip.text) && /Ack latency/.test(strip.text),
    `live dashboard strip shows throughput, in-flight, ack latency and the session-state bar (${strip ? strip.text.replace(/\s+/g, ' ').slice(0, 90) : 'hidden'})`);
  const legend = await b.textContent('#diagram-legend');
  check(/pending/.test(legend), `diagram legend has state counts (${legend.trim().slice(0, 60)})`);
  // T20b: live ack latency. Pending slaves have no acks yet; the tile
  // says so. Then a frame carrying the server's ack_latency fields
  // (as a privileged run streams them) renders p50 / p99 in the strip
  // and per session in the diagram's table.
  const lat = await b.evaluate(() => {
    const tileText = () => [...document.querySelectorAll('#live-strip .ls-tile')].map(t => t.textContent).find(t => /Ack latency/.test(t)) || '';
    const before = { tile: tileText(), frameHas: !!(diag.latest && 'ack_latency' in diag.latest) };
    const f = JSON.parse(JSON.stringify(diag.latest));
    f.ack_latency = { p50_us: 2345, p99_us: 6012, samples: 12345, histogram: { log10_min_us: 1, log10_max_us: 7, counts: new Array(24).fill(0), underflow: 0, overflow: 0, total: 12345 } };
    f.per_session = f.per_session.map((p, i) => (i === 0 ? { ...p, ack_p50_us: 1500, ack_p99_us: 4200 } : p));
    diag.latest = f;
    diag.latestAt = Date.now();
    renderLiveStrip();
    const after = tileText();
    el('diagram-table-wrap').open = true;
    diag.tableAt = 0;
    renderDiagramText(f, f.per_session);
    const head = document.querySelector('#diagram-table thead').textContent;
    const row = document.querySelector('#diagram-table tbody tr').textContent;
    el('diagram-table-wrap').open = false;
    return { before, after, head, row };
  });
  check(/waiting for the first acknowledgement/.test(lat.before.tile) && !lat.before.frameHas,
    `ack latency waits for the first acknowledgement while slaves are pending (${lat.before.tile.replace(/\s+/g, ' ').slice(0, 80)})`);
  check(/2\.3 ms \/ 6\.0 ms/.test(lat.after) && /12,345 acks so far/.test(lat.after) && !/when the run ends/.test(lat.after),
    `live strip shows live ack p50 / p99 (${lat.after.replace(/\s+/g, ' ').slice(0, 80)})`);
  check(/Ack p50/.test(lat.head) && /Ack p99/.test(lat.head) && /1\.5 ms/.test(lat.row) && /4\.2 ms/.test(lat.row),
    `diagram session table has per-session ack p50 / p99 (${lat.row.replace(/\s+/g, ' ').slice(0, 90)})`);
  const created = await b.evaluate(async id => {
    const n0 = window.__ws.length;
    for (let i = 0; i < 5; i++) connectDiagram(id);
    await new Promise(r => setTimeout(r, 1500));
    return { created: window.__ws.length - n0, live: window.__ws.filter(s => s.readyState <= 1).length };
  }, slaveId);
  check(created.created === 0 && created.live === 1, `repeated connects keep one live WebSocket (created ${created.created}, live ${created.live})`);
  // F103/F105: while the stream is live the list is polled slowly and
  // carries no per-session rows; the card's rows come from the frames.
  const listPolls = [];
  const onReq = r => { if (/\/api\/runs\?limit=/.test(r.url())) listPolls.push(Date.now()); };
  b.on('request', onReq);
  await b.waitForTimeout(8500);
  b.off('request', onReq);
  check(listPolls.length <= 4, `run list polled slowly while the live stream is up (${listPolls.length} in 8.5 s)`);
  const slim = (await apiGet('/api/runs?status=running'))[0] || {};
  check(Array.isArray(slim.per_source_progress) && slim.per_source_progress.length === 0 && slim.source_states && Object.keys(slim.source_states).length > 0,
    `run list carries state counts, not per-session rows (${JSON.stringify(slim.source_states)})`);
  const rows = await b.locator(`#runs-list > li[data-key="${slaveId}"] .sess-table tbody tr`).count();
  check(rows > 0 && rows <= 25, `session rows are paged (${rows} rows shown)`);
  // Focus survives polling (F121): focus the Stop button, wait for polls.
  const stopSel = `[data-fk="run-${slaveId}-stop"]`;
  await b.focus(stopSel);
  await b.waitForTimeout(3000);
  const focusKept = await b.evaluate(sel => document.activeElement && document.activeElement.matches(sel), stopSel);
  check(focusKept, 'keyboard focus survives the runs poll');
  const node1 = await b.evaluate(id => { window.__card = document.querySelector(`#runs-list > li[data-key="${id}"] .run-head`); return !!window.__card; }, slaveId);
  await b.waitForTimeout(2000);
  const same = await b.evaluate(id => window.__card === document.querySelector(`#runs-list > li[data-key="${id}"] .run-head`), slaveId);
  check(node1 && same, 'run card is updated in place, not rebuilt');
  current = 'runs-flow';
  await audit(b, 'runs (live)', 'runs-live');
  const liveB = await b.evaluate(() => window.__ws.filter(s => s.readyState <= 1).length);
  check(liveB <= 1, `one live WebSocket in the watching tab (${liveB})`);

  // Phone layout of the live run.
  await b.setViewportSize({ width: 390, height: 844 });
  await b.waitForTimeout(1200);
  await audit(b, 'runs (live, 390px)', 'runs-live-390');
  // F119: compact session rows on a phone.
  const rowH = await b.evaluate(id => {
    const hs = [...document.querySelectorAll(`#runs-list > li[data-key="${id}"] .sess-table tbody tr`)].slice(0, 5).map(r => r.getBoundingClientRect().height);
    return hs.length ? Math.max(...hs) : null;
  }, slaveId);
  check(rowH !== null && rowH <= 90, `phone session rows are compact (${rowH && Math.round(rowH)}px)`);
  await b.setViewportSize({ width: 1440, height: 900 });

  // 5. Stop from B through the UI.
  await b.click(stopSel);
  await b.waitForFunction(id => { const r = S.runs.find(x => x.id === id); return r && r.status !== 'running'; }, slaveId, { timeout: 20000 }).catch(() => {});
  const st = await b.evaluate(id => (S.runs.find(x => x.id === id) || {}).status, slaveId);
  check(st && st !== 'running', `Stop ends the run (${st})`);

  // 6. Details of the failed run keep a text selection across polls (F107).
  if (firstId) {
    await go(b, `runs/${firstId}`);
    await b.waitForSelector(`#run-detail-${firstId} .detail`, { timeout: 10000 }).catch(() => {});
    const hasErr = await b.$(`#run-detail-${firstId} .err-box p`);
    if (hasErr) {
      await b.evaluate(id => {
        const p = document.querySelector(`#run-detail-${id} .err-box p`);
        const r = document.createRange();
        r.selectNodeContents(p);
        getSelection().removeAllRanges();
        getSelection().addRange(r);
      }, firstId);
      await b.waitForTimeout(5000);
      const sel = await b.evaluate(() => getSelection().toString().length);
      check(sel > 0, 'text selection in run details survives polling');
    }
    await b.screenshot({ path: path.join(OUT, 'flow-run-details.png'), fullPage: true });
  }

  // 7. Analysis against the slave run with an explicit run picker.
  await go(a, `analysis/${slaveId}`);
  const picked = await a.inputValue('#an-run');
  check(Number(picked) === slaveId, `analysis run picker preselects the run from the link (${picked})`);
  await a.setInputFiles('#an-file', PCAP);
  await a.click('#an-run-btn');
  await a.waitForFunction(() => /Done|failed/.test(document.querySelector('#an-msg').textContent + document.querySelector('#an-error').textContent), null, { timeout: 120000 }).catch(() => {});
  const anText = (await a.textContent('#an-msg')) + ' ' + (await a.textContent('#an-error'));
  check(new RegExp(`RUN·0*${slaveId}`).test(anText), `analysis names the run it compared against (${anText.trim().slice(0, 140)})`);
  if (await a.$('#an-result .an-slave-row')) {
    // The overview comes first; a heatmap tile opens that endpoint's
    // row in the (collapsed) endpoint table.
    check(await a.isVisible('#an-hm') && !(await a.evaluate(() => el('an-sec-endpoints').open)), 'analysis shows the heatmap overview with the endpoint table collapsed');
    await a.click('#an-hm .hm-t');
    await a.waitForFunction(() => document.querySelector('#an-result .an-slave-row .an-slave-detail').textContent.trim().length > 0, null, { timeout: 10000 }).catch(() => {});
    const filled = await a.evaluate(() => [...document.querySelectorAll('#an-result .an-slave-detail')].filter(d => d.textContent.trim()).length);
    check(filled === 1, `endpoint drill-down rendered only for the opened row (${filled})`);
  }
  // F131: the stored analysis exports as one self-contained HTML page.
  const rep = await a.getAttribute('#an-report-html', 'href').catch(() => null);
  check(!!rep, 'analysis offers "Download HTML report"');
  if (rep) {
    // Links are page-relative so the UI works under a proxy prefix.
    const r = await fetch(new URL(rep, BASE + '/').href);
    const html = await r.text();
    check(r.ok && /text\/html/.test(r.headers.get('content-type') || '') && /attachment/.test(r.headers.get('content-disposition') || ''),
      `report export is an HTML attachment (${r.status} ${r.headers.get('content-type')})`);
    check(html.includes('Replay fidelity report') && /<h2>Endpoints/.test(html), 'report has the verdict and the endpoint table');
    check(!/<script|\bsrc=|https?:\/\//i.test(html), 'report is self-contained (no scripts or external assets)');
    check(/default-src 'none'/.test(r.headers.get('content-security-policy') || ''), 'report is served with a no-load CSP');
  }
  current = 'runs-flow';
  await audit(a, 'analysis (result)', 'analysis-result');
  check(!errors.length, `no console errors in the run flows${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  await ctxA.close();
  await ctxB.close();
}

// ---------------------------------------------------------------------------
// T20: UI polish.

// Library: viability as chips and a plain verdict, raw notes collapsed;
// the row's ⋯ menu works from the keyboard.
async function libraryChecks(page) {
  const v = await page.evaluate(() => {
    const via = document.querySelector('#lib-detail .via');
    if (!via) return null;
    const notes = via.querySelector('.via-notes');
    return { chips: via.querySelectorAll('.chip').length, verdict: (via.querySelector('.via-verdict') || {}).textContent || '', notesClosed: !notes || !notes.open, bullets: via.querySelectorAll(':scope > ul.notes').length };
  });
  if (v) {
    check(v.chips >= 3 && /\./.test(v.verdict) && v.notesClosed && !v.bullets, `viability shows stat chips and a verdict sentence, notes collapsed (${v.chips} chips; ${v.verdict.trim().slice(0, 60)})`);
  } else notes.push('library: no pcap selected, viability panel not checked');
  const btn = '.pcap-row .menu-btn';
  if (!(await page.$(btn))) return;
  await page.focus(btn);
  await page.keyboard.press('Enter');
  const m1 = await page.evaluate(() => { const a = document.activeElement; return { role: a && a.getAttribute('role'), open: !!document.querySelector('.pcap-row .menu:not([hidden])') }; });
  check(m1.open && m1.role === 'menuitem', `Enter on the ⋯ button opens the menu on its first item (${JSON.stringify(m1)})`);
  await page.keyboard.press('ArrowDown');
  const m2 = await page.evaluate(() => document.activeElement && document.activeElement.textContent.trim());
  check(m2 === 'Download', `ArrowDown moves to the next menu item (${m2})`);
  await page.keyboard.press('Escape');
  const m3 = await page.evaluate(() => ({ closed: !document.querySelector('.pcap-row .menu:not([hidden])'), onBtn: document.activeElement && document.activeElement.classList.contains('menu-btn'), exp: document.activeElement && document.activeElement.getAttribute('aria-expanded') }));
  check(m3.closed && m3.onBtn && m3.exp === 'false', `Escape closes the menu and returns focus to its button (${JSON.stringify(m3)})`);
}

// Configure: scenario presets and the "what will run" summary.
async function configureChecks(page, viewport) {
  await page.click('#preset-scada');
  const a = await page.evaluate(() => ({ role: radio('role'), pacing: radio('pacing'), fresh: el('cfg-fresh-ts').checked, pressed: el('preset-scada').getAttribute('aria-pressed'), sum: el('cfg-sum-list').textContent }));
  check(a.role === 'slave' && a.pacing === 'original' && a.fresh && a.pressed === 'true' && /simulate the RTUs/.test(a.sum),
    `"Test a SCADA master" fills slave role, captured pace, fresh timestamps (${JSON.stringify({ role: a.role, pacing: a.pacing, fresh: a.fresh, pressed: a.pressed })})`);
  await page.click('#preset-rtu');
  const b = await page.evaluate(() => ({ role: radio('role'), port: el('cfg-target-port').value, sum: el('cfg-sum-list').textContent, pressed: el('preset-rtu').getAttribute('aria-pressed') }));
  check(b.role === 'master' && b.port === '2404' && /act as the master/.test(b.sum) && b.pressed === 'true', `"Test an RTU" fills master role on port 2404 (${b.role}, ${b.port})`);
  const sm = await page.evaluate(() => {
    const t = el('cfg-sum-list').textContent;
    return { pos: getComputedStyle(document.querySelector('.cfg-aside')).position, open: el('cfg-summary').open, keys: ['Role', 'Target', 'Pacing', 'Iterations', 'Link', 'Faults'].filter(k => !t.includes(k)) };
  });
  if (viewport.width >= 1100) check(sm.pos === 'sticky' && sm.open, `summary is sticky beside the form (${sm.pos})`);
  else check(sm.pos !== 'sticky' && !sm.open, `summary is collapsed and not sticky on a narrow screen (${sm.pos}, open ${sm.open})`);
  check(!sm.keys.length, `summary lists role, target, pacing, iterations, link and faults${sm.keys.length ? ' — missing ' + sm.keys : ''}`);
  await gatewayRoleChecks(page);
}

// T20b: SCADA-gateway mode is slave-only (the server answers 400
// gateway_requires_slave). In master role the section is disabled with
// a note and the request carries no gateway field, also after a preset
// or a profile set them; in slave role they are sent.
async function gatewayRoleChecks(page) {
  const r = await page.evaluate(() => {
    const keys = b => ['scada_gateway_ip', 'scada_gateway_iface', 'upstream_nat_iface'].filter(k => k in b);
    const look = () => ({ note: !el('scada-gw-note').hidden, disabled: el('scada-gw-fields').disabled, sent: keys(buildBody(false)) });
    el('cfg-scada-gw').checked = true;
    el('cfg-scada-gw-ip').value = '10.0.0.1';
    const nic = [...el('cfg-scada-gw-iface').options].find(o => o.value);
    if (nic) el('cfg-scada-gw-iface').value = nic.value;
    applyPreset('rtu');
    const master = look();
    const presetMsg = el('preset-status').textContent;
    const errs = Object.keys(validators()).filter(k => /scada-gw/.test(k));
    applyPreset('scada');
    const slave = look();
    const notes = applyRequestToForm({ mode: 'benchmark', role: 'master', target_ip: '192.0.2.10', scada_gateway_ip: '10.0.0.1' });
    const profile = { ...look(), notes };
    // Leave the form as it was: gateway off.
    el('cfg-scada-gw').checked = false;
    el('cfg-scada-gw-ip').value = '';
    applyPreset('rtu');
    return { master, presetMsg, errs, slave, profile, hasNic: !!nic };
  }).catch(e => ({ error: String(e) }));
  if (r.error) { check(false, `gateway role checks ran (${r.error})`); return; }
  check(r.master.note && r.master.disabled && !r.master.sent.length,
    `master role: gateway section disabled with a note, nothing sent (${JSON.stringify(r.master)})`);
  check(/slave role only/.test(r.presetMsg), `the RTU preset says gateway mode is slave-only (${r.presetMsg.slice(-70)})`);
  check(!r.errs.length, `master role does not validate the gateway fields (${r.errs})`);
  check(!r.slave.note && !r.slave.disabled && r.slave.sent.includes('scada_gateway_ip'),
    `slave role: gateway section enabled and sent (${JSON.stringify(r.slave)})`);
  check(r.profile.disabled && !r.profile.sent.length && r.profile.notes.some(n => /slave role only/.test(n)),
    `a master-role profile with gateway fields loads them disabled, unsent, with a note (${JSON.stringify(r.profile.notes)})`);
}

// A synthetic report of N endpoints with mixed outcomes and timelines.
function synthReport(n) {
  const slaves = [];
  for (let i = 0; i < n; i++) {
    const kind = i % 37 === 5 ? 'fail' : (i % 23 === 3 ? 'warn' : (i % 91 === 7 ? 'muted' : 'ok'));
    const verdict = { ok: 'good_delivery', warn: 'partial_delivery', fail: 'no_delivery', muted: 'never_connected' }[kind];
    slaves.push({ slave_ip: `10.${100 + (i >> 16)}.${(i >> 8) & 255}.${i & 255}`, outcome: kind === 'ok' ? 'pass' : (kind === 'muted' ? 'not_attempted' : 'fail'), verdict,
      score_pct: kind === 'ok' ? 100 : (kind === 'warn' ? 62.5 : 0), packets: kind === 'muted' ? 0 : 40, delivered_iframes: kind === 'ok' ? 10 : (kind === 'warn' ? 6 : 0),
      expected_iframes: 10, startdt_handshake_ok: kind !== 'muted' && kind !== 'fail', sessions: kind === 'muted' ? 0 : 1, verdict_reason: 'synthetic' });
  }
  const samples = Array.from({ length: 400 }, (_, i) => [i * 50, Math.sin(i / 20) * 3]);
  return {
    run_id: 999998, verdict: 'partial', score_pct: 91.2, verdict_reason: 'synthetic overview', protocol: 'iec104', role: 'slave', mode: 'generic', notes: ['a note'],
    fleet: { slave_count: n, fully_correct: slaves.filter(s => s.outcome === 'pass').length, partial: 0, failed: 0, not_attempted: 0, reconnects: 2, aggregate_score_pct: 91.2, frame_weighted_score_pct: 90.1 },
    slaves, fleet_pacing_timeline: { samples, total_samples: samples.length, iteration_starts_ms: [] },
    fleet_gi_ci_audit: { gi_total: n, gi_compliant: n - 3, gi_partial: 2, gi_non_compliant: 1, ci_total: 0, endpoints_with_events: n },
  };
}

// Analysis overview: hero, heatmap (keyboard path, text alternative),
// dimension summary; detail sections collapsed; one screen at 1440x900;
// fast at 800 endpoints.
async function heatmapChecks(page, viewport) {
  const rep200 = synthReport(200);
  const m = await page.evaluate(rep => {
    an.report = rep; an.analysisId = null; an.details = new Map();
    renderAnalysis();
    const res = el('an-result');
    const hero = res.querySelector('.an-hero').getBoundingClientRect();
    const ov = res.querySelector('.an-overview').getBoundingClientRect();
    return {
      height: Math.round(ov.bottom - hero.top), tiles: res.querySelectorAll('#an-hm .hm-t').length, tab0: res.querySelectorAll('#an-hm .hm-t[tabindex="0"]').length,
      dims: res.querySelectorAll('.dim-row').length, label: el('an-hm').getAttribute('aria-label'), closed: [...res.querySelectorAll('details.an-sec')].every(d => !d.open),
      legend: res.querySelectorAll('.hm-legend li').length,
    };
  }, rep200);
  check(m.tiles === 200 && m.tab0 === 1, `heatmap has one tile per endpoint and a single tab stop (${m.tiles} tiles, ${m.tab0} in tab order)`);
  check(/200 endpoints: .*pass/.test(m.label || '') && m.legend >= 3, `heatmap has a text alternative with outcome counts (${(m.label || '').slice(0, 70)})`);
  check(m.dims >= 6 && m.closed, `dimension summary shown, detail sections collapsed (${m.dims} rows)`);
  if (viewport.width >= 1400) check(m.height <= 760, `overview (hero, heatmap, dimensions) fits one 1440x900 screen (${m.height}px)`);
  await audit(page, 'analysis (overview)', 'analysis-overview');
  // Keyboard: Tab reaches the map, arrows move, Enter opens the row.
  const miss = await tabWalk(page, 80, ['#an-hm .hm-t']);
  check(!miss.length, 'keyboard reaches the heatmap');
  await page.keyboard.press('ArrowRight');
  const k1 = await page.evaluate(() => [...el('an-hm').children].indexOf(document.activeElement));
  await page.keyboard.press('ArrowDown');
  const k2 = await page.evaluate(() => ({ i: [...el('an-hm').children].indexOf(document.activeElement), cols: hmColumns(el('an-hm')) }));
  check(k1 === 1 && k2.i === 1 + k2.cols, `arrow keys move across and down the heatmap (${k1}, ${k2.i}, ${k2.cols} columns)`);
  await page.keyboard.press('Enter');
  await page.waitForTimeout(300);
  const k3 = await page.evaluate(() => {
    const a = document.activeElement;
    const row = a && a.closest('.an-slave-row');
    return { open: el('an-sec-endpoints').open, row: row ? row.dataset.ip : null, rowOpen: !!(row && row.open) };
  });
  check(k3.open && k3.rowOpen && k3.row === rep200.slaves.slice().sort((x, y) => ipToIntN(x.slave_ip) - ipToIntN(y.slave_ip))[1 + k2.cols].slave_ip,
    `Enter on a tile opens that endpoint in the table and focuses it (${JSON.stringify(k3)})`);
  // Fleet charts render when their section opens, with the page theme.
  await page.evaluate(() => { el('an-sec-timing').open = true; });
  await page.waitForTimeout(400);
  const ch = await page.evaluate(() => {
    const n = el('an-fleet-pacing-chart');
    const c = n && echarts.getInstanceByDom(n);
    let legend = null;
    try { legend = c && c._theme && c._theme.legend.textStyle.color; } catch (_) { /* internal */ }
    return { ok: !!c, legend, want: getCssVar('--ink-2') };
  });
  check(ch.ok && ch.legend === ch.want, `fleet charts use the page theme (${ch.legend} vs ${ch.want})`);
  // 800 endpoints: rendering stays fast.
  const t = await page.evaluate(rep => {
    const t0 = performance.now();
    an.report = rep; an.details = new Map();
    renderAnalysis();
    const ms = performance.now() - t0;
    return { ms: Math.round(ms), tiles: document.querySelectorAll('#an-hm .hm-t').length };
  }, synthReport(800));
  check(t.tiles === 800 && t.ms < 400, `800-endpoint report renders quickly (${t.ms} ms, ${t.tiles} tiles)`);
  await audit(page, 'analysis (800 endpoints)', 'analysis-800');
  await page.evaluate(() => { _resetAnalysisCharts(); el('an-result').innerHTML = ''; an.report = null; });
}
function ipToIntN(ip) { return ip.split('.').reduce((a, o) => a * 256 + Number(o), 0); }

// First-run guidance on an empty server: upload → configure → run.
async function firstRunChecks(browser) {
  current = 'first-run';
  console.log('\n== first-run empty states ==');
  const lib = await apiGet('/api/pcaps');
  const runs = await apiGet('/api/runs');
  if (lib.length || runs.length) { notes.push('first-run empty states not checked: the server already has pcaps or runs'); return; }
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  trackConsole(page, errors);
  for (const [view, sel, want] of [['library', '#lib-empty', /Upload a capture/], ['configure', '#cfg-empty', /Go to the Library/], ['runs', '#runs-empty', /Upload a capture/], ['analysis', '#an-empty', /Upload a capture/]]) {
    await go(page, view);
    const g = await page.evaluate(s => {
      const n = document.querySelector(s);
      return n && !n.hidden ? { text: n.textContent, cur: (n.querySelector('.step-current') || {}).textContent || '' } : null;
    }, sel);
    check(g && want.test(g.text) && /Upload a capture/.test(g.cur), `${view}: first-run guide points at the next step (${g ? g.cur.trim() : 'not shown'})`);
    await audit(page, `${view} (empty)`, `${view}-empty`);
  }
  check(!errors.length, `no console errors${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  await ctx.close();
}

// Theme toggle (persisted) and keyboard shortcuts.
async function themeAndShortcutChecks(browser, pcapId) {
  current = 'theme-keys';
  console.log('\n== theme toggle, keyboard shortcuts ==');
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'light' });
  const page = await ctx.newPage();
  const errors = [];
  trackConsole(page, errors);
  await go(page, 'library');
  await page.click('#theme-btn');
  await page.click('#theme-btn');
  const t1 = await page.evaluate(() => ({ th: document.documentElement.dataset.theme, bg: getComputedStyle(document.body).backgroundColor, lbl: el('theme-btn').getAttribute('aria-label') }));
  check(t1.th === 'dark' && /\b(18|1[0-9]|2[0-9]), /.test(t1.bg) && /Dark/.test(t1.lbl), `the toggle switches to dark (${t1.th}, ${t1.bg}, "${t1.lbl}")`);
  await page.reload();
  await page.waitForTimeout(600);
  const t2 = await page.evaluate(() => document.documentElement.dataset.theme);
  check(t2 === 'dark', `the theme choice persists across a reload (${t2})`);
  await audit(page, 'library (toggled dark)', 'library-toggled-dark');
  await page.click('#theme-btn');
  const t3 = await page.evaluate(() => ({ th: document.documentElement.dataset.theme, stored: localStorage.getItem('outstation.theme') }));
  check(t3.th === 'light' && t3.stored === null, `back to automatic: follows the system again (${JSON.stringify(t3)})`);
  // Shortcuts.
  const hash = () => page.evaluate(() => location.hash);
  for (const [k, v] of [['r', 'runs'], ['a', 'analysis'], ['m', 'compare'], ['c', 'configure'], ['l', 'library']]) {
    await page.keyboard.press('g');
    await page.keyboard.press(k);
    await page.waitForTimeout(150);
    check((await hash()) === `#/${v}`, `g ${k} opens ${v} (${await hash()})`);
  }
  await go(page, 'configure');
  if (pcapId) await page.selectOption('#cfg-pcap', pcapId);
  await page.click('#cfg-target-ip');
  await page.keyboard.type('gr');
  await page.waitForTimeout(150);
  check((await hash()) === '#/configure' && (await page.inputValue('#cfg-target-ip')).endsWith('gr'), 'shortcuts do not fire while typing in a field');
  await page.fill('#cfg-target-ip', '');
  await page.evaluate(() => document.activeElement.blur());
  await page.keyboard.press('/');
  const f = await page.evaluate(() => document.activeElement && document.activeElement.id);
  check(f === 'rtu-filter', `"/" focuses the current view's filter (${f})`);
  await page.evaluate(() => document.activeElement.blur());
  await page.keyboard.press('?');
  check(await page.isVisible('#kbd-dlg[open]'), '"?" opens the shortcut help');
  await audit(page, 'shortcut help', 'kbd-help');
  await page.keyboard.press('Escape');
  check(!(await page.isVisible('#kbd-dlg[open]')), 'Escape closes the shortcut help');
  check(!errors.length, `no console errors${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  await ctx.close();
}

// Run cards: a clear status line, the ⋯ menu from the keyboard, and
// delete with Undo (deferred).
async function runCardChecks(browser, pcapId) {
  current = 'run-cards';
  console.log('\n== run cards ==');
  if (NO_RUNS) return;
  if (await activeRun()) { notes.push('run card checks skipped: a run is active'); return; }
  const D = await stoppedSlaveRun(pcapId);
  if (!D) { check(false, 'could not create a stopped run'); return; }
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  trackConsole(page, errors);
  await page.goto(`${BASE}/?undo_ms=${UNDO_MS}#/runs`);
  const card = `#runs-list > li[data-key="${D}"]`;
  await page.waitForSelector(card);
  await page.waitForTimeout(600);
  const c = await page.evaluate(sel => {
    const n = document.querySelector(sel);
    return { line: n.querySelector('.run-line').textContent, text: n.textContent, buttons: n.querySelectorAll('.run-actions .btn-row > .btn, .run-actions .btn-row > a.btn').length };
  }, card);
  check(!/listening/.test(c.line), `a stopped slave run does not say "listening" (${c.line.trim().slice(0, 90)})`);
  check(!/0% · 0 \/ 0/.test(c.text), 'no meaningless "0% · 0 / 0" progress');
  check(c.buttons <= 3, `the card has at most a primary action, Details and the ⋯ menu (${c.buttons} buttons)`);
  const missMenu = await tabWalk(page, 80, [`#run-menu-${D}-btn`]);
  check(!missMenu.length, 'keyboard reaches the run card menu');
  await page.keyboard.press('ArrowDown');
  const items = await page.evaluate(id => [...document.querySelectorAll(`#run-menu-${id} [role="menuitem"]`)].map(x => x.textContent.trim()), D);
  const first = await page.evaluate(() => document.activeElement && document.activeElement.textContent.trim());
  check(first === items[0] && items.includes('Delete run') && items.includes('Re-run…'), `ArrowDown opens the run menu on its first item (${items.join(', ')})`);
  await page.keyboard.press('End');
  const last = await page.evaluate(() => document.activeElement && document.activeElement.textContent.trim());
  check(last === items[items.length - 1], `End moves to the last item (${last})`);
  await page.keyboard.press('Enter');   // Delete run
  await page.waitForTimeout(300);
  check(!(await page.isVisible('#dlg[open]')) && !(await page.$(card)), 'deleting a finished run asks no confirmation and hides the card');
  const undoSel = `.toast [data-fk="undo-run-${D}"]`;
  check(await page.isVisible(undoSel), 'an Undo toast is offered for the run');
  await page.click(undoSel);
  await page.waitForTimeout(UNDO_MS + 800);
  check(!!(await page.$(card)) && (await apiGet('/api/runs')).some(r => r.id === D), 'Undo brings the run back and it is not deleted');
  await runMenu(page, D, `run-${D}-delete`);
  await page.waitForTimeout(UNDO_MS + 2000);
  check(!(await apiGet('/api/runs')).some(r => r.id === D), 'the deferred delete is committed when the toast ends');
  check(!errors.length, `no console errors${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  await ctx.close();
}

// ---------------------------------------------------------------------------
// Wave 3 (T19).

async function healthChecks(browser) {
  current = 'health';
  console.log('\n== health, metrics ==');
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  trackConsole(page, errors);
  await go(page, 'library');
  const st = await apiGet('/api/status');
  const detail = st.degraded_detail || [];
  if (detail.length) {
    const chip = await page.textContent('#health-chip').catch(() => '');
    check(/health issue/.test(chip), `health chip shown for degraded server (${chip.trim()})`);
    const items = await page.locator('#degraded-text li').count();
    check(items === detail.length, `banner lists every degraded_detail entry (${items}/${detail.length})`);
    if (detail.some(d => d.code === 'missing_capabilities')) {
      const t = await page.textContent('#degraded-text');
      check(/Runs will fail at network setup/.test(t) && /systemd unit/.test(t), 'missing_capabilities gets its own advice');
    }
    await page.click('#degraded-banner [data-act="dismiss-banner"]');
    await page.click('#health-chip');
    check(await page.isVisible('#degraded-banner'), 'the health chip re-opens a dismissed banner');
  } else notes.push('server is healthy: health banner checks skipped');
  // Page-relative, so it also works under a reverse-proxy prefix.
  const href = await page.getAttribute('footer a[href="metrics"]', 'href').catch(() => null);
  check(href === 'metrics', 'footer links to metrics (page-relative)');
  const m = await fetch(BASE + '/metrics');
  const body = await m.text();
  check(m.ok && /^# (HELP|TYPE) /m.test(body), `/metrics serves Prometheus text (${m.status})`);
  check(!errors.length, `no console errors${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  await ctx.close();
}

// Open the ⋯ menu of a run card and pick an item.
async function runMenu(page, id, fk) {
  await page.click(`#run-menu-${id}-btn`);
  await page.waitForSelector(`#run-menu-${id}:not([hidden])`);
  await page.click(`[data-fk="${fk}"]`);
}

async function dialogInput(page, value) {
  await page.waitForSelector('#dlg[open] #dlg-input');
  await page.fill('#dlg-input', value);
  await page.click('#dlg-ok');
}
async function dialogConfirm(page) {
  await page.waitForSelector('#dlg[open]');
  await page.click('#dlg-ok');
}

async function profileFlow(browser, pcapId) {
  current = 'profiles';
  console.log('\n== profiles ==');
  for (const p of await apiGet('/api/profiles')) {
    if (p.name.startsWith(SMOKE_PROFILE)) await apiSend(`/api/profiles/${p.id}`, 'DELETE');
  }
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  trackConsole(page, errors);
  await page.goto(`${BASE}/?undo_ms=${UNDO_MS}#/configure`);
  await page.waitForSelector('#view-configure:not([hidden])');
  await page.waitForTimeout(900);
  await page.selectOption('#cfg-pcap', pcapId);
  await page.click('label[for="mode-benchmark"]');
  await page.click('label[for="role-master"]');
  await page.fill('#cfg-target-ip', '10.20.30.40');
  await page.fill('#cfg-iterations', '3');

  await page.click('#prof-save');
  await dialogInput(page, SMOKE_PROFILE);
  await page.waitForFunction(() => /Saved profile/.test(document.querySelector('#prof-status').textContent), null, { timeout: 10000 }).catch(() => {});
  const opt = await page.textContent('#prof-select');
  check(opt.includes(SMOKE_PROFILE), 'profile saved and listed');
  const stored = (await apiGet('/api/profiles')).find(p => p.name === SMOKE_PROFILE);
  check(stored && stored.request.target_ip === '10.20.30.40' && stored.request.iterations === 3 && !stored.request.force,
    `stored request matches the form, without the override (${stored && JSON.stringify({ ip: stored.request.target_ip, it: stored.request.iterations, force: stored.request.force })})`);

  // Duplicate name: 409 profile_exists, shown clearly.
  await page.click('#prof-save');
  await dialogInput(page, SMOKE_PROFILE);
  await page.waitForFunction(() => document.querySelector('#prof-error').textContent.trim(), null, { timeout: 10000 }).catch(() => {});
  const dup = await page.textContent('#prof-error');
  check(/already exists/.test(dup) && dup.includes(SMOKE_PROFILE), `409 profile_exists is explained (${dup.trim().slice(0, 100)})`);

  // Load restores the form.
  await page.fill('#cfg-iterations', '7');
  await page.fill('#cfg-target-ip', '10.0.0.99');
  await page.click('#prof-load');
  await page.waitForFunction(() => /Loaded profile/.test(document.querySelector('#prof-status').textContent), null, { timeout: 10000 }).catch(() => {});
  const it = await page.inputValue('#cfg-iterations');
  const ip = await page.inputValue('#cfg-target-ip');
  check(it === '3' && ip === '10.20.30.40', `Load fills the form from the profile (iterations ${it}, target ${ip})`);

  // Rename.
  await page.click('#prof-rename');
  await dialogInput(page, SMOKE_PROFILE + '-renamed');
  await page.waitForFunction(() => /Renamed/.test(document.querySelector('#prof-status').textContent), null, { timeout: 10000 }).catch(() => {});
  check((await page.textContent('#prof-select')).includes(SMOKE_PROFILE + '-renamed'), 'rename is listed');

  // Overwrite (with confirmation).
  await page.fill('#cfg-iterations', '9');
  await page.click('#prof-overwrite');
  await dialogConfirm(page);
  await page.waitForFunction(() => /Overwrote/.test(document.querySelector('#prof-status').textContent), null, { timeout: 10000 }).catch(() => {});
  const ow = (await apiGet('/api/profiles')).find(p => p.name === SMOKE_PROFILE + '-renamed');
  check(ow && ow.request.iterations === 9, `overwrite stores the current form (iterations ${ow && ow.request.iterations})`);
  await audit(page, 'configure (profiles)', 'profiles');

  // Delete with Undo (no confirmation dialog): Undo keeps it, a second
  // delete is committed when the toast ends.
  await page.click('#prof-delete');
  check(!(await page.isVisible('#dlg[open]')), 'deleting a profile asks no confirmation');
  const undoSel = '.toast [data-fk^="undo-profile-"]';
  await page.waitForSelector(undoSel, { timeout: 5000 }).catch(() => {});
  check(await page.isVisible(undoSel), 'an Undo toast is offered');
  check(!(await page.textContent('#prof-select')).includes(SMOKE_PROFILE), 'the profile leaves the list at once');
  await page.click(undoSel);
  await page.waitForTimeout(UNDO_MS + 800);
  const kept = (await apiGet('/api/profiles')).some(p => p.name.startsWith(SMOKE_PROFILE));
  check(kept && (await page.textContent('#prof-select')).includes(SMOKE_PROFILE), 'Undo keeps the profile (on the server and in the list)');
  await page.selectOption('#prof-select', { label: (await page.locator('#prof-select option', { hasText: SMOKE_PROFILE }).first().textContent()).trim() });
  await page.click('#prof-delete');
  await page.waitForTimeout(UNDO_MS + 1500);
  const gone = !(await apiGet('/api/profiles')).some(p => p.name.startsWith(SMOKE_PROFILE));
  check(gone, 'delete is committed when the Undo toast ends');
  await page.fill('#cfg-iterations', '1');
  await page.fill('#cfg-target-ip', '10.9.8.7');
  check(!errors.length, `no console errors${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  await ctx.close();
}

async function faultEditorFlow(browser, pcapId, viewport, label) {
  current = `faults-${label}`;
  console.log(`\n== fault and command editors (${label}) ==`);
  const ctx = await browser.newContext({ viewport });
  const page = await ctx.newPage();
  const errors = [];
  trackConsole(page, errors);
  const runPosts = [];
  page.on('request', r => { if (r.url().endsWith('/api/run') && r.method() === 'POST') runPosts.push(r); });
  await go(page, 'configure');
  await page.selectOption('#cfg-pcap', pcapId);
  await page.click('label[for="mode-benchmark"]');
  await page.click('label[for="role-slave"]');
  await page.click('#fault-params > summary');
  check(/deliberately break/i.test(await page.textContent('#fault-params .fault-warn')), 'fault editor warns that faults break the session');
  await page.click('#fault-add');
  const row = page.locator('#fault-rows > li').first();
  await row.locator('[data-flt="kind"]').selectOption('drop_iframes');
  await row.locator('[data-flt="pct"]').fill('150');
  await row.locator('[data-flt="duration_ms"]').fill('2000');
  const before = runPosts.length;
  await page.click('#start-btn');
  await page.waitForTimeout(300);
  const pctErr = await row.locator('[data-flt="pct"] ~ .field-err').textContent();
  check(/more than 0 and at most 100/.test(pctErr) && runPosts.length === before, `pct 150 is rejected inline and blocks start (${pctErr.trim()})`);
  const focused = await page.evaluate(() => document.activeElement && document.activeElement.dataset.flt);
  check(focused === 'pct', `focus moves to the invalid fault field (${focused})`);
  await row.locator('[data-flt="pct"]').fill('25');
  await row.locator('[data-flt="atType"]').selectOption('frame');
  await row.locator('[data-flt="at"]').fill('10');
  await page.fill('#cfg-fault-seed', '42');
  await page.click('#cmd-params > summary');
  await page.selectOption('#cfg-cmd-return-info', 'retrem');
  await page.fill('#cfg-cmd-max-age', '86400001');
  await page.click('#start-btn');
  await page.waitForTimeout(300);
  const maErr = await page.textContent('#cfg-cmd-max-age-err');
  check(/0 to 86,400,000/.test(maErr), `command max age is range-checked (${maErr.trim()})`);
  await page.fill('#cfg-cmd-max-age', '5000');
  const pc = JSON.parse(await page.evaluate(() => buildProtoConfig()) || '{}');
  const f0 = (pc.faults || [])[0] || {};
  check(f0.kind === 'drop_iframes' && f0.at && f0.at.frame === 10 && f0.pct === 25 && f0.duration_ms === 2000 && pc.fault_seed === 42,
    `fault plan serialises into proto_config (${JSON.stringify(pc.faults)}, seed ${pc.fault_seed})`);
  check(pc.commands && pc.commands.return_info === 'retrem' && pc.commands.max_age_ms === 5000 && !('enabled' in pc.commands),
    `commands serialise with only the changed keys (${JSON.stringify(pc.commands)})`);
  // Kind-specific params: slow_ack needs extra_ms, its duration is optional.
  await page.click('#fault-add');
  const row2 = page.locator('#fault-rows > li').nth(1);
  await row2.locator('[data-flt="kind"]').selectOption('slow_ack');
  await row2.locator('[data-flt="extra_ms"]').fill('');
  await row2.locator('[data-flt="duration_ms"]').fill('');
  await page.click('#start-btn');
  await page.waitForTimeout(300);
  const exErr = await row2.locator('[data-flt="extra_ms"] ~ .field-err').textContent();
  check(/Enter ack delay/.test(exErr), `slow_ack requires extra_ms (${exErr.trim()})`);
  await row2.locator('[data-flt="extra_ms"]').fill('500');
  const pc2 = JSON.parse(await page.evaluate(() => buildProtoConfig()));
  check(pc2.faults[1] && pc2.faults[1].extra_ms === 500 && !('duration_ms' in pc2.faults[1]), `optional duration is left out (${JSON.stringify(pc2.faults[1])})`);
  const sum = await page.textContent('#start-summary');
  check(/2 faults planned/.test(sum), `start summary flags the fault plan (${sum.trim().slice(0, 120)})`);
  await audit(page, `configure (fault editor, ${label})`, 'fault-editor');
  // Persistence across reload.
  await page.waitForTimeout(400);
  await page.reload();
  await page.waitForSelector('#view-configure:not([hidden])');
  await page.waitForTimeout(500);
  const kept = await page.locator('#fault-rows > li').count();
  const pc3 = JSON.parse(await page.evaluate(() => buildProtoConfig()) || '{}');
  check(kept === 2 && JSON.stringify(pc3.faults) === JSON.stringify(pc2.faults), `fault plan survives a reload (${kept} rows)`);
  // Server-side error mapped onto its row.
  await page.evaluate(() => showIec104ConfigError('proto_config (faults): faults[1] (slow_ack): "extra_ms" must be 1..=600000, got 0'));
  const srv = await page.locator('#fault-rows > li').nth(1).locator('[data-flt="extra_ms"] ~ .field-err').textContent();
  check(/^Server: faults\[1\]/.test(srv), `server fault error lands on its row (${srv.trim().slice(0, 80)})`);
  // Remove both rows; the plan is empty again.
  await page.locator('#fault-rows [data-act="fault-remove"]').first().click();
  await page.locator('#fault-rows [data-act="fault-remove"]').first().click();
  const left = await page.locator('#fault-rows > li').count();
  const pc4 = JSON.parse(await page.evaluate(() => buildProtoConfig()) || '{}');
  check(left === 0 && !pc4.faults, `removing every fault empties the plan (${left} rows)`);
  await page.fill('#cfg-fault-seed', '');
  await page.selectOption('#cfg-cmd-return-info', 'none');
  await page.fill('#cfg-cmd-max-age', '');
  await page.click('label[for="role-master"]');
  await page.waitForTimeout(400);
  check(!errors.length, `no console errors${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  await ctx.close();
}

async function rerunFlow(browser) {
  current = 'rerun';
  console.log('\n== re-run, load into Configure, auto-analysis ==');
  if (!flow.firstId) { notes.push('re-run flow skipped: no finished run from the run flows'); return; }
  if (await activeRun()) { notes.push('re-run flow skipped: a run is active'); return; }
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  trackConsole(page, errors);
  await go(page, 'runs');
  const id = flow.firstId;
  const card = `#runs-list > li[data-key="${id}"]`;
  await page.waitForSelector(card);
  const st = await page.textContent(`${card} .run-analysis`);
  const runRow = (await apiGet('/api/runs')).find(r => r.id === id);
  if (runRow && runRow.auto_analysis) check(new RegExp(`Auto-analysis ${runRow.auto_analysis.state}`).test(st), `card shows the auto-analysis state (${st.trim().slice(0, 80)})`);
  await runMenu(page, id, `run-${id}-card-rerun`);
  await page.waitForSelector('#dlg[open]');
  const dlgText = await page.textContent('#dlg');
  check(new RegExp(`Re-run #${id}`).test(dlgText) && dlgText.includes(MASTER_TARGET), `re-run asks for confirmation with the settings (${dlgText.trim().replace(/\s+/g, ' ').slice(0, 100)})`);
  await page.click('#dlg-ok');
  await page.waitForFunction(sel => /Re-run RUN·\d+ (failed|completed|stopped|partial)|refused/.test((document.querySelector(sel + ' .run-msg') || {}).textContent || ''), card, { timeout: 40000 }).catch(() => {});
  const msg = await page.textContent(`${card} .run-msg`).catch(() => '');
  const m = msg.match(/RUN·0*(\d+)/);
  if (m) startedRuns.push(Number(m[1]));
  if (/failed|refused/.test(msg)) {
    check(/privileges|CAP_NET|protected|override/i.test(msg), `re-run failure is explained on the card (${msg.trim().slice(0, 160)})`);
  } else {
    check(/Re-run RUN·\d+/.test(msg), `re-run result shown on the card (${msg.trim().slice(0, 120)})`);
    notes.push('re-run did not fail (privileged server?)');
  }
  if (m) {
    const nr = (await apiGet('/api/runs')).find(r => r.id === Number(m[1]));
    check(nr && nr.rerun_of === id, `new run records rerun_of (${nr && nr.rerun_of})`);
    await page.waitForSelector(`#runs-list > li[data-key="${m[1]}"] .submeta a[href="#/runs/${id}"]`, { timeout: 10000 }).catch(() => {});
    check(await page.isVisible(`#runs-list > li[data-key="${m[1]}"] .submeta a[href="#/runs/${id}"]`), 'new card links to the run it re-ran');
  }
  await page.screenshot({ path: path.join(OUT, 'flow-rerun.png'), fullPage: false });
  // Load into Configure.
  await runMenu(page, id, `run-${id}-card-load`);
  await page.waitForSelector('#view-configure:not([hidden])', { timeout: 10000 });
  await page.waitForTimeout(500);
  const ip = await page.inputValue('#cfg-target-ip');
  const role = await page.evaluate(() => radio('role'));
  const status = await page.textContent('#prof-status');
  check(ip === MASTER_TARGET && role === 'master' && new RegExp(`run #${id}`).test(status), `Load into Configure fills the form (${ip}, ${role}; ${status.trim()})`);
  check(!errors.length, `no console errors${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  await ctx.close();
}

async function compareFlow(browser, pcapId) {
  current = 'compare';
  console.log('\n== compare ==');
  if (!flow.slaveId) { notes.push('compare flow skipped: no slave run from the run flows'); return; }
  if (await activeRun()) { notes.push('compare flow skipped: a run is active'); return; }
  const A = flow.slaveId;
  const runs = await apiGet('/api/runs');
  if (!(runs.find(r => r.id === A) || {}).latest_analysis) await uploadAnalysis(A);
  const B = await stoppedSlaveRun(pcapId);
  if (!B) { check(false, 'could not create a second benchmark run'); return; }
  // With auto-analysis on (the server default) every finished
  // benchmark run that has a capture is analysed by itself, so the
  // comparison must render without any user action. The
  // analysis_missing -> "Analyze run" -> retry path is only reachable
  // on a server started with --no-auto-analyze; run the smoke against
  // one of those as well to cover it.
  const st = await apiGet('/api/status');
  if (st.auto_analyze) {
    const done = await waitRun(B, x => x.auto_analysis && x.auto_analysis.state !== 'queued' && x.auto_analysis.state !== 'running', 60000);
    const aa = done && done.auto_analysis;
    check(!!aa, `auto-analysis of run ${B} reached a final state (${aa ? aa.state : 'timeout'})`);
    const ctxA = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const pageA = await ctxA.newPage();
    const errsA = [];
    trackConsole(pageA, errsA);
    await pageA.goto(`${BASE}/#/compare/${A}/${B}?score_drop=2`);
    await pageA.waitForSelector('#view-compare:not([hidden])');
    await pageA.waitForSelector('.cmp-fleet', { timeout: 30000 }).catch(() => {});
    check(await pageA.isVisible('.cmp-fleet'), 'with auto-analysis on, the comparison renders without an Analyze step');
    check(await pageA.inputValue('#cmp-th-score_drop') === '2', 'threshold from the hash fills its input');
    await audit(pageA, 'compare (auto-analysed)', 'compare-auto');
    if (await pageA.isVisible('.cmp-fleet')) await compareLabelChecks(pageA, A, B);
    check(!errsA.length, `no console errors${errsA.length ? ': ' + errsA.slice(0, 3).join(' | ') : ''}`);
    notes.push('compare: analysis_missing/Analyze path not exercised (server has auto-analysis on; rerun against a --no-auto-analyze server to cover it)');
    await ctxA.close();
    return;
  }
  let liveCapture = false;
  if (CAPTURES_DIR) {
    try { fs.copyFileSync(PCAP, path.join(CAPTURES_DIR, `run_${B}.pcap`)); liveCapture = true; } catch (e) { notes.push(`could not seed a capture: ${e.message}`); }
  }
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  trackConsole(page, errors);
  const analyzePosts = [];
  page.on('request', r => { if (/\/api\/runs\/\d+\/analyze$/.test(r.url()) && r.method() === 'POST') analyzePosts.push(r.url()); });

  // "Compare with…" on B's card pre-selects a baseline and B.
  await go(page, 'runs');
  await runMenu(page, B, `run-${B}-card-compare`);
  await page.waitForSelector('#view-compare:not([hidden])');
  const h1 = await page.evaluate(() => location.hash);
  check(new RegExp(`^#/compare/\\d+/${B}$`).test(h1), `"Compare with…" opens the compare view with B preselected (${h1})`);

  // Shared link with a threshold: analysis_missing for B.
  await page.goto(`${BASE}/#/compare/${A}/${B}?score_drop=2`);
  await page.waitForSelector('#view-compare:not([hidden])');
  await page.waitForFunction(() => /has no stored analysis/.test(document.querySelector('#cmp-error').textContent), null, { timeout: 15000 }).catch(() => {});
  const miss = await page.textContent('#cmp-error');
  check(new RegExp(`Run #${B} \\(candidate B\\) has no stored analysis`).test(miss), `analysis_missing is explained (${miss.trim().slice(0, 90)})`);
  check(await page.inputValue('#cmp-a') === String(A) && await page.inputValue('#cmp-b') === String(B), 'pickers follow the hash');
  check(await page.inputValue('#cmp-th-score_drop') === '2', 'threshold from the hash fills its input');
  await audit(page, 'compare (analysis missing)', 'compare-missing');
  const btn = `[data-act="cmp-analyze"][data-id="${B}"]`;
  if (liveCapture) {
    check(await page.isVisible(btn), 'an "Analyze run" button is offered for a run with a capture');
    await page.click(btn);
    const busy = await page.textContent(btn).catch(() => '');
    check(/Analysing/.test(busy) || analyzePosts.length > 0, `analyze button shows it is busy (${busy.trim()})`);
    await page.waitForSelector('#cmp-tbody tr', { timeout: 180000 }).catch(() => {});
    check(analyzePosts.length === 1 && await page.isVisible('.cmp-fleet'), `after POST analyze the comparison retries by itself (${analyzePosts.length} POST)`);
  } else {
    check(/no replay capture/.test(miss) && await page.isVisible(`#cmp-error a[href="#/analysis/${B}"]`), 'without a capture it points to Analysis to upload one');
    // The Analyze button's error path, against the real server: pretend
    // the run has a capture; the server then answers 409 capture_missing.
    await page.route(`**/api/runs/${A}/compare/${B}**`, async route => {
      const resp = await route.fetch();
      const body = await resp.json();
      if (body.code === 'analysis_missing') body.has_capture = true;
      await route.fulfill({ response: resp, json: body });
    });
    await page.click('[data-act="cmp-retry"]');
    await page.waitForSelector(btn, { timeout: 10000 });
    await page.click(btn);
    await page.waitForFunction(() => /Analysis of run #\d+ failed/.test(document.querySelector('#cmp-error').textContent), null, { timeout: 30000 }).catch(() => {});
    const ae = await page.textContent('#cmp-error');
    check(/no replay capture/.test(ae) && analyzePosts.length === 1, `POST analyze failure is explained (${ae.trim().slice(0, 120)})`);
    await page.unroute(`**/api/runs/${A}/compare/${B}**`);
    notes.push('compare: live analyze → retry path needs --captures-dir; used an uploaded analysis instead');
    await uploadAnalysis(B);
    await page.click('[data-act="cmp-retry"]');
  }
  await page.waitForSelector('#cmp-tbody tr', { timeout: 30000 }).catch(() => {});
  const nrows = await page.locator('#cmp-tbody tr').count();
  check(await page.isVisible('.cmp-fleet') && nrows > 0, `fleet summary and per-RTU table render (${nrows} rows)`);
  const used = await page.textContent('.cmp-th-used').catch(() => '');
  check(/score drop &gt; 2|score drop > 2/.test(used), `the threshold reached the server (${used.trim().slice(0, 60)})`);
  const verdictBox = await page.textContent('.cmp-verdict');
  check(/regression/i.test(verdictBox), `regressed / not regressed is stated (${verdictBox.trim()})`);
  await compareLabelChecks(page, A, B);
  // Sort and filter.
  await page.click('[data-act="cmp-sort"][data-key="rtu"]');
  const sorted = await page.getAttribute('#cmp-thead th:first-child', 'aria-sort');
  check(sorted === 'ascending', `RTU column sorts (${sorted})`);
  const firstIp = (await page.textContent('#cmp-tbody tr:first-child th')).trim();
  await page.fill('#cmp-q', firstIp);
  const filtered = await page.locator('#cmp-tbody tr').count();
  check(filtered >= 1 && filtered < Math.max(2, nrows), `filter narrows the RTU table (${filtered})`);
  await page.fill('#cmp-q', 'no-such-rtu');
  check(/No RTU matches/.test(await page.textContent('#cmp-tbody')), 'filter with no match says so');
  await page.fill('#cmp-q', '');
  // Changing a threshold updates the shareable hash.
  await page.fill('#cmp-th-p99_increase_pct', '50');
  await page.click('#cmp-btn');
  await page.waitForTimeout(800);
  const h2 = await page.evaluate(() => location.hash);
  check(h2.includes(`/compare/${A}/${B}?`) && /score_drop=2/.test(h2) && /p99_increase_pct=50/.test(h2), `hash keeps runs and thresholds (${h2})`);
  // Invalid threshold is caught before the request.
  await page.fill('#cmp-th-score_drop', '-1');
  await page.click('#cmp-btn');
  const thErr = await page.textContent('#cmp-th-score_drop-err');
  check(/0 or more/.test(thErr), `negative threshold rejected inline (${thErr.trim()})`);
  await page.fill('#cmp-th-score_drop', '2');
  await audit(page, 'compare (result)', 'compare-result');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(500);
  await audit(page, 'compare (result, 390px)', 'compare-result-390');
  flow.cmpA = A;
  flow.cmpB = B;
  // The analysis picker shows the latest analysis of a run.
  await page.setViewportSize({ width: 1440, height: 900 });
  await go(page, `analysis/${B}`);
  const optText = await page.textContent(`#an-run option[value="${B}"]`);
  check(/analysed:/.test(optText), `analysis run picker shows latest_analysis (${optText.trim().slice(-40)})`);
  check(!errors.length, `no console errors${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  await ctx.close();
}

// T20b: regressions read "Ack p99 rose from 245.2 ms to 396.8 ms", not
// "p99_us rose from 245242 µs": the server's own regressions (if any)
// carry a label and no raw ids, and the list, the per-RTU headers and
// the Regressed column show friendly names and ms.
async function compareLabelChecks(page, A, B) {
  const real = await apiGet(`/api/runs/${A}/compare/${B}?score_drop=0&delivered_drop=0`).catch(() => ({}));
  const regs = real.regressions || [];
  check(regs.every(r => r.label && !/_us\b|_pct\b| µs/.test(r.message)), `server regressions carry labels and no raw ids (${regs.length} regression(s))`);
  // A response with the latency regressions of the bug report, fleet
  // and per RTU, rendered by the real client.
  await page.route(`**/api/runs/${A}/compare/${B}**`, async route => {
    const resp = await route.fetch();
    const body = await resp.json();
    if (Array.isArray(body.rtus) && body.rtus.length) {
      const ip = body.rtus[0].rtu;
      body.regressions = [
        { scope: 'fleet', rtu: null, metric: 'p99_us', label: 'Ack p99', a: 245242, b: 396787, threshold: 20, message: 'Ack p99 rose from 245.2 ms to 396.8 ms (more than 20%)' },
        { scope: 'rtu', rtu: ip, metric: 'p50_us', label: 'Ack p50', a: 1000, b: 9000, threshold: 20, message: `RTU ${ip}: Ack p50 rose from 1.0 ms to 9.0 ms (more than 20%)` },
      ];
      body.regressed = true;
      body.rtus[0].regressions = ['p50_us', 'delivered_pct'];
      body.rtus[0].a.p50_us = 1000;
      body.rtus[0].b.p50_us = 9000;
      body.rtus[0].delta.p50_us = 8000;
    }
    await route.fulfill({ response: resp, json: body }).catch(() => {});
  });
  await page.click('#cmp-btn');
  // The real result may already list regressions: wait for these.
  await page.waitForFunction(() => /245\.2 ms/.test((document.querySelector('.cmp-regs') || {}).textContent || ''), null, { timeout: 15000 }).catch(() => {});
  const v = await page.evaluate(() => ({
    list: (document.querySelector('.cmp-regs') || {}).textContent || '',
    head: document.querySelector('#cmp-thead').textContent,
    row: (document.querySelector('#cmp-tbody tr .reg-tag') || {}).textContent || '',
    cell: [...document.querySelectorAll('#cmp-tbody tr')].map(r => r.textContent).join(' '),
  }));
  await page.unroute(`**/api/runs/${A}/compare/${B}**`);
  check(/Ack p99 rose from 245\.2 ms to 396\.8 ms/.test(v.list) && !/p99[ _]us|µs/.test(v.list), `regression list uses labels and ms (${v.list.replace(/\s+/g, ' ').slice(0, 100)})`);
  check(/Ack p50/.test(v.head) && /Ack p99/.test(v.head) && !/_us|µs/.test(v.head), `per-RTU headers are friendly (${v.head.replace(/\s+/g, ' ').slice(0, 100)})`);
  check(/Ack p50/.test(v.row) && /Delivered/.test(v.row) && !/_/.test(v.row), `Regressed column names metrics (${v.row})`);
  check(/1\.0 ms → 9\.0 ms/.test(v.cell), `per-RTU latency cells in ms with one decimal`);
  await page.click('#cmp-btn');
  await page.waitForTimeout(500);
}

async function cleanup() {
  for (const p of await apiGet('/api/profiles').catch(() => [])) {
    if (p.name.startsWith(SMOKE_PROFILE)) await apiSend(`/api/profiles/${p.id}`, 'DELETE').catch(() => {});
  }
  for (const id of startedRuns) {
    await apiSend(`/api/runs/${id}/stop`, 'POST').catch(() => {});
  }
  await sleep(1500);
  for (const id of startedRuns) {
    await apiSend(`/api/runs/${id}`, 'DELETE').catch(() => {});
  }
}

(async () => {
  console.log(`outstation UI smoke against ${BASE}; screenshots in ${OUT}`);
  let pcapId = null;
  try {
    const cr = await chromium.launch();
    await firstRunChecks(cr);
    pcapId = await engineWalk(cr, 'chromium-1440', { width: 1440, height: 900 }, true);
    await engineWalk(cr, 'chromium-1440-dark', { width: 1440, height: 900 }, false, 'dark');
    await engineWalk(cr, 'chromium-390', { width: 390, height: 844 }, false);
    await engineWalk(cr, 'chromium-390-dark', { width: 390, height: 844 }, false, 'dark');
    await healthChecks(cr);
    await themeAndShortcutChecks(cr, pcapId);
    if (pcapId) {
      await profileFlow(cr, pcapId);
      await faultEditorFlow(cr, pcapId, { width: 1440, height: 900 }, '1440');
      await faultEditorFlow(cr, pcapId, { width: 390, height: 844 }, '390');
      await runFlows(cr, pcapId);
      if (!NO_RUNS) {
        await runCardChecks(cr, pcapId);
        await rerunFlow(cr);
        await compareFlow(cr, pcapId);
        await paginationFlow(cr);
      }
    }
    await cr.close();
    const wk = await webkit.launch();
    await engineWalk(wk, 'webkit-1440', { width: 1440, height: 900 }, false);
    await engineWalk(wk, 'webkit-1440-dark', { width: 1440, height: 900 }, false, 'dark');
    await wk.close();
  } catch (e) {
    failures.push(`[${current}] crashed: ${e.stack || e}`);
    console.log(e);
  } finally {
    await cleanup();
  }
  for (const n of notes) console.log(`note: ${n}`);
  console.log(failures.length ? `\n${failures.length} check(s) failed:\n- ${failures.join('\n- ')}` : '\nall checks passed');
  process.exit(failures.length ? 1 : 0);
})();
