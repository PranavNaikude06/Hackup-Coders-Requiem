// ThreatLens Scanner — Outlook Content Script (content_outlook.js)
// Injected into outlook.live.com and outlook.office.com
// Uses MutationObserver to detect when an email reading pane opens,
// extracts email text + URLs, sends to background.js for analysis,
// and injects the result overlay using shared ThreatLens.* utilities.

(function () {
  'use strict';

  // ─── Selectors ──────────────────────────────────────────────────────────────
  // Priority 1: Classic Outlook Web reading pane
  const BODY_SELECTOR_CLASSIC = 'div[aria-label="Message body"]';
  // Priority 2: New Outlook reading pane
  const BODY_SELECTOR_NEW     = '.ReadingPaneContents';
  // Fallback: broad content area
  const BODY_SELECTOR_FALLBACK = 'div[role="main"]';

  // ─── State ──────────────────────────────────────────────────────────────────
  const scannedKeys = new Set();

  // ─── Helpers ────────────────────────────────────────────────────────────────

  /**
   * Get the active email reading pane element.
   * Tries selectors in priority order.
   */
  function getEmailBodyEl() {
    return document.querySelector(BODY_SELECTOR_CLASSIC)
      || document.querySelector(BODY_SELECTOR_NEW)
      || null;
  }

  /**
   * Build a dedup cache key using Outlook's subject + sender DOM.
   */
  function buildOutlookCacheKey() {
    // Outlook Classic subject
    const subject = document.querySelector('[aria-label="Message subject"]')?.innerText?.trim()
      ?? document.querySelector('.SubjectLine')?.innerText?.trim()
      ?? '';
    // Outlook Classic sender span
    const sender  = document.querySelector('.lvHighlight')?.innerText?.trim()
      ?? document.querySelector('[aria-label*="From"]')?.innerText?.trim()
      ?? '';
    return ThreatLens.buildCacheKey(subject, sender);
  }

  /**
   * Extract all href URLs from the email body element.
   */
  function extractUrls(bodyEl) {
    const anchors = Array.from(bodyEl.querySelectorAll('a[href]'));
    const hrefs   = anchors.map(a => a.getAttribute('href')).filter(Boolean);
    return ThreatLens.filterUrls(hrefs, 'outlook');
  }

  // ─── Core Scan Logic ────────────────────────────────────────────────────────

  function runScan() {
    const bodyEl = getEmailBodyEl();
    if (!bodyEl) return;

    // Outlook Classic subject
    const subject = document.querySelector('[aria-label="Message subject"]')?.innerText?.trim()
      ?? document.querySelector('.SubjectLine')?.innerText?.trim()
      ?? '';
    // Outlook Classic sender span
    const sender  = document.querySelector('.lvHighlight')?.innerText?.trim()
      ?? document.querySelector('[aria-label*="From"]')?.innerText?.trim()
      ?? '';
      
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
      { type: 'SCAN_EMAIL', email_body: emailText, urls, client: 'outlook', sender, subject },
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

  // Debounced version — 800ms matches Outlook's rendering delays
  const debouncedScan = ThreatLens.debounce(runScan, 800);

  // ─── MutationObserver ───────────────────────────────────────────────────────

  function startObserver() {
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (!(node instanceof HTMLElement)) continue;

          // Detect reading pane: classic or new Outlook body selectors
          const isReadingPane =
            node.matches?.(BODY_SELECTOR_CLASSIC) ||
            node.querySelector?.(BODY_SELECTOR_CLASSIC) ||
            node.matches?.(BODY_SELECTOR_NEW) ||
            node.querySelector?.(BODY_SELECTOR_NEW);

          if (isReadingPane) {
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

    console.log('[ThreatLens] Outlook observer started');
  }

  // ─── Rescan trigger from popup ──────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'TRIGGER_RESCAN') {
      const bodyEl = getEmailBodyEl();
      if (!bodyEl) return;
      const key = buildOutlookCacheKey();
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
