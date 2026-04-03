// ThreatLens Scanner — Gmail Content Script (content_gmail.js)
// Injected into mail.google.com
// Uses MutationObserver to detect when a Gmail thread is opened,
// extracts email text + URLs, sends to background.js for analysis,
// and injects the result overlay using shared ThreatLens.* utilities.

(function () {
  'use strict';

  // ─── Selectors ──────────────────────────────────────────────────────────────
  // Primary: Gmail email body container
  const BODY_SELECTOR     = 'div.ii.gt';
  // Thread open signal: data-legacy-thread-id attribute on message root
  const THREAD_SELECTOR   = 'div[data-legacy-thread-id]';
  // Fallback: individual message containers
  const MESSAGE_SELECTOR  = 'div[data-message-id]';

  // ─── State ──────────────────────────────────────────────────────────────────
  const scannedKeys = new Set(); // Prevents duplicate scans in same session
  let debounceTimer = null;

  // ─── Helpers ────────────────────────────────────────────────────────────────

  /**
   * Extract the email body element from the currently open thread.
   * Tries selectors in priority order.
   */
  function getEmailBodyEl() {
    // Prefer the deepest open message body
    const all = document.querySelectorAll(BODY_SELECTOR);
    if (all.length > 0) return all[all.length - 1]; // Last = most recent open
    // Fallback: last message container
    const msgs = document.querySelectorAll(MESSAGE_SELECTOR);
    return msgs.length > 0 ? msgs[msgs.length - 1] : null;
  }

  /**
   * Extract a deduplication cache key from Gmail DOM.
   * Uses subject line + sender address.
   */
  function buildGmailCacheKey() {
    const subject  = document.querySelector('h2.hP')?.innerText?.trim() ?? '';
    const sender   = document.querySelector('.gD')?.getAttribute('email') ?? '';
    return ThreatLens.buildCacheKey(subject, sender);
  }

  /**
   * Extract all href URLs from the email body element.
   */
  function extractUrls(bodyEl) {
    const anchors = Array.from(bodyEl.querySelectorAll('a[href]'));
    const hrefs   = anchors.map(a => a.getAttribute('href')).filter(Boolean);
    return ThreatLens.filterUrls(hrefs, 'gmail');
  }

  // ─── Core Scan Logic ────────────────────────────────────────────────────────

  function runScan() {
    const bodyEl = getEmailBodyEl();
    if (!bodyEl) return;

    const subject  = document.querySelector('h2.hP')?.innerText?.trim() ?? '';
    const sender   = document.querySelector('.gD')?.getAttribute('email') ?? '';
    const cacheKey = ThreatLens.buildCacheKey(subject, sender);

    // Skip if already scanned in this session
    if (scannedKeys.has(cacheKey)) return;
    scannedKeys.add(cacheKey);

    const emailText = bodyEl.innerText?.trim() ?? '';
    const urls      = extractUrls(bodyEl);

    // Inject loading banner immediately
    ThreatLens.injectLoadingBanner(bodyEl);

    // Send to background service worker for analysis
    chrome.runtime.sendMessage(
      { type: 'SCAN_EMAIL', email_body: emailText, urls, client: 'gmail', sender, subject },
      (result) => {
        if (chrome.runtime.lastError) {
          console.error('[ThreatLens] Message error:', chrome.runtime.lastError.message);
          ThreatLens.injectResultOverlay(bodyEl, {
            verdict: 'OFFLINE', score: null,
            flags: ['Extension error'],
            recommended_action: 'Try reloading the page.'
          });
          return;
        }
        ThreatLens.injectResultOverlay(bodyEl, result);
      }
    );
  }

  // Debounced version to absorb Gmail's incremental rendering
  const debouncedScan = ThreatLens.debounce(runScan, 800);

  // ─── MutationObserver ───────────────────────────────────────────────────────

  function startObserver() {
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (!(node instanceof HTMLElement)) continue;

          // Detect thread open: new thread ID wrapper or message body appeared
          const isThreadOpen = node.matches?.(THREAD_SELECTOR)
            || node.querySelector?.(THREAD_SELECTOR)
            || node.matches?.(BODY_SELECTOR)
            || node.querySelector?.(BODY_SELECTOR);

          if (isThreadOpen) {
            debouncedScan();
            return;
          }
        }
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });

    console.log('[ThreatLens] Gmail observer started');
  }

  // ─── Rescan trigger from popup ──────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'TRIGGER_RESCAN') {
      const bodyEl = getEmailBodyEl();
      if (!bodyEl) return;
      // Clear cached key so rescan is allowed
      const key = buildGmailCacheKey();
      scannedKeys.delete(key);
      runScan();
    }
  });

  // ─── Init ───────────────────────────────────────────────────────────────────

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startObserver);
  } else {
    startObserver();
  }

})();
