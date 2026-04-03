// ThreatLens Scanner — Background Service Worker (Manifest V3)
// Handles all API calls to avoid CORS issues in content scripts.
// Caches last scan result in chrome.storage.local for popup display.
// Phase 17: SSE streaming support added — forwards progress events to content scripts.

const BACKEND_URL       = 'http://127.0.0.1:8000';
const COMBINED_ENDPOINT = `${BACKEND_URL}/analyze/combined`;
const STREAM_ENDPOINT   = `${BACKEND_URL}/analyze/stream`;

/**
 * Central message listener.
 * Routes messages from content scripts and popup.
 *
 * Supported message types:
 *   { type: 'SCAN_EMAIL', email_body, urls, client }   → runs combined analysis (with SSE if available)
 *   { type: 'RESCAN' }                                 → signals active tab to rescan
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAN_EMAIL') {
    handleScanEmailWithStream(message, sender)
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
 * Main scan handler with SSE streaming.
 * 1. Starts SSE stream from /analyze/stream — forwards progress events to tab
 * 2. Falls back to /analyze/combined for the final result
 *
 * @param {object} message - { email_body, urls, client }
 * @param {object} sender  - chrome.runtime sender (has sender.tab.id)
 * @returns {Promise<object>} - backend analysis result or OFFLINE fallback
 */
async function handleScanEmailWithStream(message, sender) {
  const { email_body = '', urls = [], client = 'unknown' } = message;
  const tabId = sender?.tab?.id ?? null;

  // Fire SSE stream in parallel (non-blocking) for live progress updates
  if (tabId) {
    connectSSEStream(tabId, { 
      email_text: email_body, 
      url: urls.length > 0 ? urls[0] : '' 
    }).catch(() => {
      // SSE is best-effort — failure doesn't block the final result
    });
  }

  // Run combined analysis (primary result)
  return await handleScanEmail(message, sender);
}

/**
 * Connect to the SSE stream endpoint and forward progress events to the content script.
 * Uses EventSource API.
 *
 * @param {number} tabId   - Chrome tab ID to forward messages to
 * @param {object} payload - { email_body, url_list }
 */
async function connectSSEStream(tabId, payload) {
  // SSE requires a GET URL or POST via fetch with streaming.
  // The backend exposes /analyze/stream — we use fetch with ReadableStream.
  let response;
  try {
    response = await fetch(STREAM_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch {
    return; // Backend unreachable — SSE silently skipped
  }

  if (!response.ok || !response.body) return;

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });

    // Parse SSE lines: "data: {...}\n\n"
    const lines = buffer.split('\n');
    buffer = lines.pop(); // Keep incomplete line buffered

    for (const line of lines) {
      if (!line.startsWith('data:')) continue;
      const raw = line.slice(5).trim();
      if (!raw || raw === '[DONE]') continue;

      try {
        const event = JSON.parse(raw);
        // Forward progress event to content script in the tab
        chrome.tabs.sendMessage(tabId, {
          type: 'SSE_PROGRESS',
          event
        }).catch(() => {}); // Tab may have navigated — safe to ignore
      } catch {
        // Malformed JSON in SSE event — skip
      }
    }
  }
}

/**
 * Primary scan handler.
 * Calls /analyze/combined, caches result, returns analysis object.
 */
async function handleScanEmail(message, sender) {
  const { email_body = '', urls = [], client = 'unknown' } = message;

  try {
    const response = await fetch(COMBINED_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: urls.length > 0 ? urls[0] : '',
        email_text: email_body
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
 */
function buildOfflineResult() {
  return {
    verdict: 'OFFLINE',
    score: null,
    flags: ['Backend Unreachable'],
    recommended_action: 'Ensure the ThreatLens server is running on localhost:8000.'
  };
}
