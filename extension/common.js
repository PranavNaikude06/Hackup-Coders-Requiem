// ThreatLens Scanner — Shared Overlay Logic (common.js)
// Injected into both Gmail and Outlook Web content scripts.
// All functions live on the window.ThreatLens namespace to avoid collisions.

(function () {
  'use strict';

  const TL = window.ThreatLens = window.ThreatLens || {};

  // ─── Constants ─────────────────────────────────────────────────────────────
  TL.BANNER_ID = 'threatlens-banner';

  // ─── Utilities ─────────────────────────────────────────────────────────────

  /**
   * Standard debounce utility.
   * @param {Function} fn
   * @param {number} ms
   * @returns {Function}
   */
  TL.debounce = function (fn, ms) {
    let timer;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), ms);
    };
  };

  /**
   * Build a simple cache key from subject + sender.
   * Used to prevent re-scanning the same email.
   * @param {string} subject
   * @param {string} sender
   * @returns {string}
   */
  TL.buildCacheKey = function (subject, sender) {
    return `${sender}::${subject}`;
  };

  /**
   * Filter and deduplicate a list of hrefs.
   * Removes protocol-level noise and client-specific internal links.
   * @param {string[]} hrefs
   * @param {'gmail'|'outlook'} clientType
   * @returns {string[]}
   */
  TL.filterUrls = function (hrefs, clientType) {
    const GMAIL_INTERNALS = [
      'google.com', 'accounts.google.com', 'support.google.com', 'gstatic.com',
      'googleapis.com', 'googleusercontent.com'
    ];
    const OUTLOOK_INTERNALS = [
      'microsoft.com', 'outlook.com', 'office.com', 'live.com',
      'microsoftonline.com', 'windows.net'
    ];

    const filtered = hrefs.filter(href => {
      if (!href || href.trim() === '') return false;
      if (/^(mailto:|tel:|#|javascript:)/i.test(href)) return false;

      if (clientType === 'gmail') {
        return !GMAIL_INTERNALS.some(d => href.includes(d));
      }
      if (clientType === 'outlook') {
        return !OUTLOOK_INTERNALS.some(d => href.includes(d));
      }
      return true;
    });

    return [...new Set(filtered)];
  };

  // ─── Color Helpers ──────────────────────────────────────────────────────────

  function _getVerdictColors(verdict) {
    switch (verdict) {
      case 'SAFE':       return { color: '#22c55e', bg: 'rgba(34,197,94,0.08)' };
      case 'SUSPICIOUS': return { color: '#f59e0b', bg: 'rgba(245,158,11,0.08)' };
      case 'PHISHING':   return { color: '#ef4444', bg: 'rgba(239,68,68,0.08)' };
      default:           return { color: '#94a3b8', bg: 'rgba(148,163,184,0.08)' };
    }
  }

  // ─── Overlay: Loading Banner ────────────────────────────────────────────────

  /**
   * Inject a pulsing loading banner above the email body.
   * @param {HTMLElement} targetEl — container element to prepend into
   */
  TL.injectLoadingBanner = function (targetEl) {
    if (!targetEl) return;

    // Remove any existing banner
    document.getElementById(TL.BANNER_ID)?.remove();

    const banner = document.createElement('div');
    banner.id = TL.BANNER_ID;
    banner.setAttribute('data-threatlens', 'loading');
    Object.assign(banner.style, {
      position: 'relative',
      zIndex: '9999',
      margin: '0 0 12px 0',
      padding: '12px 16px',
      borderLeft: '4px solid #94a3b8',
      background: 'rgba(148,163,184,0.08)',
      borderRadius: '6px',
      fontFamily: 'Inter, sans-serif',
      fontSize: '13px',
      color: '#94a3b8',
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      boxSizing: 'border-box'
    });

    banner.innerHTML = `
      <span class="tl-pulse" style="
        display:inline-block;
        width:8px;height:8px;
        border-radius:50%;
        background:#94a3b8;
        flex-shrink:0;
      "></span>
      🔍 ThreatLens scanning...
    `;

    targetEl.prepend(banner);
  };

  // ─── Overlay: Result Card ───────────────────────────────────────────────────

  /**
   * Replace loading banner with a verdict result card.
   * @param {HTMLElement} targetEl — container element to prepend into
   * @param {object} result — { verdict, score, flags, recommended_action }
   */
  TL.injectResultOverlay = function (targetEl, result) {
    if (!targetEl) return;

    // Remove existing banner
    document.getElementById(TL.BANNER_ID)?.remove();

    const verdict = result?.verdict ?? 'OFFLINE';
    const score   = result?.score ?? result?.combined_score;
    const flags   = Array.isArray(result?.flags) ? result.flags : [];
    const action  = result?.llm_human_explanation ?? result?.recommended_action ?? '';

    const { color, bg } = _getVerdictColors(verdict);

    // Build flag pills HTML
    const pillsHtml = flags.slice(0, 3).map(f => `
      <span style="
        background:${bg};
        border:1px solid ${color}33;
        color:${color};
        border-radius:999px;
        padding:2px 10px;
        font-size:11px;
        white-space:nowrap;
      ">${_escapeHtml(f)}</span>
    `).join('');

    // Build verdict emoji
    const verdictEmoji = { SAFE: '✅', SUSPICIOUS: '⚠️', PHISHING: '🚨', OFFLINE: '⚡' }[verdict] ?? '🛡';

    const overlay = document.createElement('div');
    overlay.id = TL.BANNER_ID;
    overlay.setAttribute('data-threatlens', 'result');
    Object.assign(overlay.style, {
      position: 'relative',
      zIndex: '9999',
      margin: '0 0 12px 0',
      padding: '12px 16px',
      borderLeft: `4px solid ${color}`,
      background: bg,
      borderRadius: '6px',
      fontFamily: 'Inter, sans-serif',
      fontSize: '13px',
      color: '#1e293b',
      boxSizing: 'border-box'
    });

    overlay.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:${pillsHtml || action ? '8px' : '0'};">
        <span style="font-weight:700;color:${color};font-size:14px;display:flex;align-items:center;gap:6px;">
          ${verdictEmoji} ThreatLens: ${_escapeHtml(verdict)}
          ${score !== null && score !== undefined
            ? `<span style="font-weight:400;color:#64748b;font-size:12px;">${score}/100</span>`
            : ''}
        </span>
        <button id="tl-dismiss" style="
          background:none;border:none;cursor:pointer;
          color:#94a3b8;font-size:18px;line-height:1;
          padding:0 4px;margin-left:12px;
        " title="Dismiss ThreatLens result">×</button>
      </div>
      ${pillsHtml
        ? `<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:${action ? '8px' : '0'};">${pillsHtml}</div>`
        : ''}
      ${action
        ? `<div style="font-size:12px;color:#64748b;">${_escapeHtml(action)}</div>`
        : ''}
    `;

    targetEl.prepend(overlay);

    // Wire dismiss button
    document.getElementById('tl-dismiss')?.addEventListener('click', () => {
      document.getElementById(TL.BANNER_ID)?.remove();
    });

    // Auto-dismiss removed per user request: overlay stays until 'X' is explicitly clicked.
  };

  // ─── Internal Helpers ───────────────────────────────────────────────────────

  function _escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }


  // ─── SSE Progress Handler ───────────────────────────────────────────────────

  /**
   * Progress stage labels mapped from backend event types.
   * Shown in the loading banner while scan is in progress.
   */
  const SSE_LABELS = {
    url_analysis_start:    '🔗 Analyzing URLs...',
    url_analysis_complete: '🔗 URLs analyzed',
    email_analysis_start:  '📧 Analyzing email body...',
    email_analysis_done:   '📧 Email body analyzed',
    combining_scores:      '🔀 Combining scores...',
    complete:              '✅ Analysis complete',
  };

  /**
   * Update the text content of an active loading banner.
   * Called when SSE_PROGRESS messages arrive from background.js.
   * @param {string} text - Status text to display
   */
  TL.updateBannerText = function (text) {
    const banner = document.getElementById(TL.BANNER_ID);
    if (!banner || banner.getAttribute('data-threatlens') !== 'loading') return;

    // Find the text node after the pulse dot and update it
    const pulse = banner.querySelector('.tl-pulse');
    if (pulse && pulse.nextSibling) {
      pulse.nextSibling.textContent = ` ${text}`;
    } else {
      banner.childNodes.forEach(node => {
        if (node.nodeType === Node.TEXT_NODE && node.textContent.includes('ThreatLens')) {
          node.textContent = ` ${text}`;
        }
      });
    }
  };

  /**
   * Listen for SSE progress events forwarded from the background service worker.
   * Updates the loading banner's status text in real time.
   */
  if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
    chrome.runtime.onMessage.addListener((message) => {
      if (message.type === 'SSE_PROGRESS' && message.event) {
        const label = SSE_LABELS[message.event.stage] || message.event.message || '';
        if (label) TL.updateBannerText(label);
      }
    });
  }

})();
