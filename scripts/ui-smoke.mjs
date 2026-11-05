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

async function engineWalk(browser, name, viewport, deep) {
  current = name;
  console.log(`\n== ${name} ==`);
  const ctx = await browser.newContext({ viewport });
  await ctx.addInitScript(INIT);
  const page = await ctx.newPage();
  const errors = [];
  trackConsole(page, errors);
  const runPosts = [];
  page.on('request', r => { if (r.url().endsWith('/api/run') && r.method() === 'POST') runPosts.push(r); });

  const pcapId = await ensurePcap(page);
  check(!!pcapId, 'pcap is in the library');

  await go(page, 'library');
  await audit(page, 'library', 'library');
  const missLib = await tabWalk(page, 40, ['#dropzone', '.pcap-select']);
  check(!missLib.length, `keyboard reaches the upload button and the pcap rows${missLib.length ? ' — missing ' + missLib : ''}`);
  const dz = await page.evaluate(() => getComputedStyle(document.querySelector('#dropzone')).display);
  check(dz !== 'inline', `drop zone is a block-level box (${dz})`);

  await go(page, 'configure');
  await page.selectOption('#cfg-pcap', pcapId);
  await page.click('label[for="mode-benchmark"]');
  await page.waitForSelector('#rtu-tbody tr');
  await audit(page, 'configure', 'configure');
  await chromeChecks(page, viewport);
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
  await go(page, 'library');
  const selBg = await page.evaluate(() => { const r = document.querySelector('.pcap-row.selected'); return r ? getComputedStyle(r).backgroundColor : null; });
  if (selBg) check(/\b31, 74, 120\b/.test(selBg), `selected pcap row is tinted neutral blue, not the error family (${selBg})`);
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
  const legend = await b.textContent('#diagram-legend');
  check(/pending/.test(legend), `diagram legend has state counts (${legend.trim().slice(0, 60)})`);
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
    await a.click('#an-result .an-slave-row > summary');
    await a.waitForFunction(() => document.querySelector('#an-result .an-slave-row .an-slave-detail').textContent.trim().length > 0, null, { timeout: 10000 }).catch(() => {});
    const filled = await a.evaluate(() => [...document.querySelectorAll('#an-result .an-slave-detail')].filter(d => d.textContent.trim()).length);
    check(filled === 1, `endpoint drill-down rendered only for the opened row (${filled})`);
  }
  // F131: the stored analysis exports as one self-contained HTML page.
  const rep = await a.getAttribute('#an-report-html', 'href').catch(() => null);
  check(!!rep, 'analysis offers "Download HTML report"');
  if (rep) {
    const r = await fetch(BASE + rep);
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
  const href = await page.getAttribute('footer a[href="/metrics"]', 'href').catch(() => null);
  check(href === '/metrics', 'footer links to /metrics');
  const m = await fetch(BASE + '/metrics');
  const body = await m.text();
  check(m.ok && /^# (HELP|TYPE) /m.test(body), `/metrics serves Prometheus text (${m.status})`);
  check(!errors.length, `no console errors${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  await ctx.close();
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
  await go(page, 'configure');
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

  // Delete (with confirmation).
  await page.click('#prof-delete');
  await dialogConfirm(page);
  await page.waitForFunction(() => /Deleted/.test(document.querySelector('#prof-status').textContent), null, { timeout: 10000 }).catch(() => {});
  const gone = !(await apiGet('/api/profiles')).some(p => p.name.startsWith(SMOKE_PROFILE));
  check(gone, 'delete removes the profile');
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
  await page.click(`[data-fk="run-${id}-card-rerun"]`);
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
  await page.click(`[data-fk="run-${id}-card-load"]`);
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
  await page.click(`[data-fk="run-${B}-card-compare"]`);
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
    pcapId = await engineWalk(cr, 'chromium-1440', { width: 1440, height: 900 }, true);
    await engineWalk(cr, 'chromium-390', { width: 390, height: 844 }, false);
    await healthChecks(cr);
    if (pcapId) {
      await profileFlow(cr, pcapId);
      await faultEditorFlow(cr, pcapId, { width: 1440, height: 900 }, '1440');
      await faultEditorFlow(cr, pcapId, { width: 390, height: 844 }, '390');
      await runFlows(cr, pcapId);
      if (!NO_RUNS) {
        await rerunFlow(cr);
        await compareFlow(cr, pcapId);
        await paginationFlow(cr);
      }
    }
    await cr.close();
    const wk = await webkit.launch();
    await engineWalk(wk, 'webkit-1440', { width: 1440, height: 900 }, false);
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
