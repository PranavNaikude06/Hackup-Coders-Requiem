// ThreatLens Scanner — Popup Script (popup.js)
// Phase 18 will implement the full popup dashboard UI.

chrome.storage.local.get('lastScanResult', (data) => {
  const result = data.lastScanResult;
  if (result) {
    console.log('[ThreatLens] Last scan result:', result);
  } else {
    console.log('[ThreatLens] No scan result cached yet.');
  }
});
