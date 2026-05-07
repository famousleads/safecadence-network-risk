// SafeCadence Quick Console — service worker.
//
// Minimal scaffold. Future: WebSocket subscription to /api/execute/audit
// so the badge shows pending approval count without the user opening the
// popup. For v7.1 we keep it simple — the popup polls when opened.

chrome.runtime.onInstalled.addListener(() => {
  // Reasonable default badge
  chrome.action.setBadgeBackgroundColor({color: "#6366f1"});
});
