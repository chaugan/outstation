// 90-main.js — polling and boot
// Spliced into the served page by crates/webui/build.rs (classic script,
// shared global scope with the other ui/*.js files, loaded in file-name order).

// =========================================================================
//  polling
// =========================================================================
let pollTimer = null;
function schedulePoll() {
  if (pollTimer) clearTimeout(pollTimer);
  const anyRunning = document.querySelectorAll('.run.running').length > 0;
  const delay = anyRunning ? 800 : 3000;
  pollTimer = setTimeout(async () => {
    await refreshRuns();
    schedulePoll();
  }, delay);
}

loadStatus();
startRunEvents();
loadProtocols();
loadNics();
refreshLibrary();
refreshRuns().then(schedulePoll);
applyProtoVisibility();
