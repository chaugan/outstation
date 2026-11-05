#!/usr/bin/env node
// Screenshots of the web UI for the README (doc/images/ui-*.jpg),
// taken from a server with real runs. Driven by
// scripts/netns-screenshots.sh, which starts the server and the runs.
//
// Usage:
//   node scripts/ui-screenshots.mjs live  BASE OUT RUN_ID
//       the Runs view of an active run, with its live diagram
//   node scripts/ui-screenshots.mjs final BASE OUT RUN_A RUN_B PCAP_ID [ANALYSIS_ID]
//       Library, Configure (PCAP_ID, slave role), Runs (RUN_A),
//       Analysis (RUN_A) and Compare (RUN_A vs RUN_B)
//
// Chromium at 1440x900 (device scale 1), JPEG quality 80, light theme.
// Playwright is loaded from $PLAYWRIGHT_DIR (default
// /opt/code/tools/browser/node_modules/playwright).

import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';

const [mode, BASE0, OUT, ...ids] = process.argv.slice(2);
if (!['live', 'final'].includes(mode) || !BASE0 || !OUT) {
  console.error('usage: ui-screenshots.mjs live|final BASE OUT IDS...');
  process.exit(2);
}
const BASE = BASE0.replace(/\/$/, '');
const PW = process.env.PLAYWRIGHT_DIR || '/opt/code/tools/browser/node_modules/playwright';
const { chromium } = createRequire(import.meta.url)(PW);
fs.mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch({ args: ['--no-sandbox'] });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'light' });
const page = await ctx.newPage();
const errors = [];
page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });

async function shot(name, { fullPage = false, maxHeight = 1600 } = {}) {
  await page.waitForTimeout(400);
  const file = path.join(OUT, name);
  if (fullPage) {
    // A taller viewport rather than a full-page capture, so the sticky
    // header and footer stay where they belong.
    await page.evaluate(() => window.scrollTo(0, 0));
    const h = await page.evaluate(() => document.documentElement.scrollHeight);
    await page.setViewportSize({ width: 1440, height: Math.min(h, maxHeight) });
    await page.waitForTimeout(400);
    await page.screenshot({ path: file, type: 'jpeg', quality: 80 });
    await page.setViewportSize({ width: 1440, height: 900 });
  } else {
    await page.screenshot({ path: file, type: 'jpeg', quality: 80 });
  }
  console.log(`${file} ${fs.statSync(file).size} bytes`);
}

async function open(hash) {
  await page.goto(`${BASE}/${hash}`);
  await page.waitForLoadState('networkidle').catch(() => {});
}

if (mode === 'live') {
  const [run] = ids;
  await open(`#/runs/${run}`);
  await page.waitForSelector('#diagram-section:not([hidden])', { timeout: 30000 });
  await page.waitForTimeout(4000); // a few diagram frames
  // The strip's ack-latency tile shows live p50 / p99 once the
  // sessions have acknowledgements (T20b).
  await page.waitForFunction(() => {
    const t = [...document.querySelectorAll('#live-strip .ls-tile')].find(n => /Ack latency/.test(n.textContent));
    return t && /acks so far/.test(t.textContent);
  }, null, { timeout: 60000 }).catch(() => {});
  const latTile = await page.evaluate(() => ([...document.querySelectorAll('#live-strip .ls-tile')].find(n => /Ack latency/.test(n.textContent)) || {}).textContent || '');
  console.log(`live ack latency tile: ${latTile.replace(/\s+/g, ' ').trim()}`);
  if (!/acks so far/.test(latTile)) {
    console.error('the live strip shows no live ack latency');
    process.exitCode = 1;
  }
  // The live dashboard strip and the diagram below it.
  await page.evaluate(() => (document.querySelector('#live-strip:not([hidden])') || document.getElementById('diagram-section')).scrollIntoView({ block: 'start' }));
  await page.evaluate(() => window.scrollBy(0, -64));
  await shot('ui-runs-live.jpg');
} else {
  const [a, b, pcapId, analysisId] = ids;
  await open('#/library');
  await page.waitForSelector(`#view-library:not([hidden])`);
  await page.waitForTimeout(1000);
  await shot('ui-library.jpg', { fullPage: true, maxHeight: 1100 });

  await open('#/configure');
  await page.waitForSelector('#cfg-pcap option', { state: 'attached' });
  await page.selectOption('#cfg-pcap', pcapId);
  await page.check('#role-slave');
  await page.waitForTimeout(1500);
  await shot('ui-configure.jpg', { fullPage: true, maxHeight: 1500 });

  await open(`#/runs/${a}`);
  await page.waitForTimeout(1500);
  // The run card, its auto-analysis state and per-session results.
  await page.evaluate(() => window.scrollTo(0, 0));
  await shot('ui-runs.jpg', { fullPage: true, maxHeight: 1400 });

  await open(`#/analysis/${a}${analysisId ? '/' + analysisId : ''}`);
  await page.waitForSelector('#an-result :is(table, .verdict, h3)', { timeout: 30000 }).catch(() => {});
  await page.waitForTimeout(1500);
  await shot('ui-analysis.jpg', { fullPage: true, maxHeight: 1600 });

  await open(`#/compare/${a}/${b}`);
  await page.waitForTimeout(3000);
  await shot('ui-compare.jpg', { fullPage: true, maxHeight: 1500 });
}
await browser.close();
if (errors.length) {
  console.error(`console errors:\n  ${errors.join('\n  ')}`);
}
