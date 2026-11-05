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

  const live = await page.evaluate(() => (window.__ws || []).filter(s => s.readyState <= 1).length);
  check(live <= 1, `at most one live WebSocket (${live})`);
  check(!errors.length, `no console errors${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  await ctx.close();
  return pcapId;
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
  await a.fill('#cfg-target-ip', '127.0.0.1');
  await a.fill('#cfg-warmup', '0');
  await a.click('#start-btn');
  await a.waitForFunction(() => /Run #\d+/.test(document.querySelector('#run-result').textContent) || document.querySelector('#run-error').textContent.trim(), null, { timeout: 15000 });
  const m1 = (await a.textContent('#run-result')).match(/Run #(\d+)/);
  const firstId = m1 ? Number(m1[1]) : null;
  if (firstId) startedRuns.push(firstId);
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
  current = 'runs-flow';
  await audit(a, 'analysis (result)', 'analysis-result');
  check(!errors.length, `no console errors in the run flows${errors.length ? ': ' + errors.slice(0, 3).join(' | ') : ''}`);
  await ctxA.close();
  await ctxB.close();
}

async function cleanup() {
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
    if (pcapId) await runFlows(cr, pcapId);
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
