// ThreatLens Scanner — Background Service Worker (Manifest V3)
// Handles all API calls to avoid CORS issues in content scripts.
// Caches last scan result in chrome.storage.local for popup display.

const BACKEND_URL = 'http://localhost:8000';
const COMBINED_ENDPOINT = `${BACKEND_URL}/analyze/combined`;
const STREAM_ENDPOINT = `${BACKEND_URL}/analyze/stream`;

/**
 * Central message listener.
 * Routes messages from content scripts and popup.
 *
 * Supported message types:
 *   { type: 'SCAN_EMAIL', email_body, urls, client }   → runs combined analysis
 *   { type: 'RESCAN' }                                 → signals active tab to rescan
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAN_EMAIL') {
    handleScanEmail(message, sender)
      .then(sendResponse)
      .catch(err => {
        console.error('[ThreatLens] Unexpected scan error:', err);
        sendResponse(buildOfflineResult());
      });
    return true; // Keep channel open for async sendResponse
  }

  if (message.type === 'RESCAN') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, { type: 'TRIGGER_RESCAN' });
      }
    });
    return false;
  }
});

/**
 * Main scan handler.
 * Calls /analyze/combined, caches result, returns analysis object.
 *
 * @param {object} message - { email_body, urls, client }
 * @param {object} sender  - chrome.runtime sender (has sender.tab.id)
 * @returns {Promise<object>} - backend analysis result or OFFLINE fallback
 */
async function handleScanEmail(message, sender) {
  const { email_body = '', urls = [], client = 'unknown' } = message;

  try {
    const response = await fetch(COMBINED_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url_list: urls,
        email_body: email_body
      })
    });

    if (!response.ok) {
      throw new Error(`Backend returned HTTP ${response.status}: ${response.statusText}`);
    }

    const result = await response.json();

    // Persist to chrome.storage.local for popup to read
    await chrome.storage.local.set({
      lastScanResult: {
        ...result,
        timestamp: Date.now(),
        client: client,
        tabId: sender?.tab?.id ?? null
      }
    });

    return result;

  } catch (err) {
    console.error('[ThreatLens] Backend unreachable:', err.message);
    const offlineResult = buildOfflineResult();

    // Cache the OFFLINE state too so popup can surface it
    await chrome.storage.local.set({
      lastScanResult: {
        ...offlineResult,
        timestamp: Date.now(),
        client: client,
        tabId: sender?.tab?.id ?? null
      }
    });

    return offlineResult;
  }
}

/**
 * Builds a standardised OFFLINE result object.
 * Returned when the backend is unreachable.
 */
function buildOfflineResult() {
  return {
    verdict: 'OFFLINE',
    score: null,
    flags: ['Backend Unreachable'],
    recommended_action: 'Ensure the ThreatLens server is running on localhost:8000.'
  };
}
