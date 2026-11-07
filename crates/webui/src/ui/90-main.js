// 90-main.js — boot: wire every view, apply the route, then start the
// runs poller, the run-event stream and the periodic status refresh.
'use strict';

function boot() {
  initShell();
  initLibrary();
  initConfigure();
  initRuns();
  initDiagram();
  initAnalysis();
  initCompare();
  applyRoute(false);
  startRunEvents();
  loadStatus();
  loadProtocols();
  loadNics();
  refreshLibrary();
  pollRuns();
  setInterval(loadStatus, 30000);
}

boot();
