// ThreatLens Scanner — Popup Script (popup.js)
// Reads last scan result from chrome.storage.local and renders dashboard.

(function () {
  'use strict';

  // ─── Constants ───────────────────────────────────────────────────────────────

  const VERDICT_CONFIG = {
    SAFE:       { color: '#22c55e', emoji: '✅', label: 'SAFE'       },
    SUSPICIOUS: { color: '#f59e0b', emoji: '⚠️',  label: 'SUSPICIOUS' },
    PHISHING:   { color: '#ef4444', emoji: '🚨', label: 'PHISHING'   },
    OFFLINE:    { color: '#94a3b8', emoji: '⚡', label: 'OFFLINE'    },
  };

  const CLIENT_LABELS = {
    gmail:   '📧 Gmail',
    outlook: '📨 Outlook Web',
    unknown: '📬 Unknown Client',
  };

  // ─── DOM References ─────────────────────────────────────────────────────────

  const elLoading      = document.getElementById('state-loading');
  const elEmpty        = document.getElementById('state-empty');
  const elResult       = document.getElementById('state-result');
  const elGaugeArc     = document.getElementById('gauge-arc');
  const elGaugeScore   = document.getElementById('gauge-score');
  const elVerdictBadge = document.getElementById('verdict-badge');
  const elClientLabel  = document.getElementById('client-label');
  const elTimestamp    = document.getElementById('timestamp-label');
  const elFlagsSection = document.getElementById('flags-section');
  const elFlagsContainer = document.getElementById('flags-container');
  const elActionSection  = document.getElementById('action-section');
  const elActionText     = document.getElementById('action-text');
  const elRescanBtn      = document.getElementById('rescan-btn');

  // ─── Gauge Rendering ─────────────────────────────────────────────────────────

  /**
   * Animate the SVG arc gauge to reflect the score (0–100).
   * Arc circumference for r=32 is 2π×32 ≈ 201.1
   */
  function renderGauge(score, color) {
    const CIRCUMFERENCE = 201.1;
    const pct = Math.min(Math.max(score ?? 0, 0), 100) / 100;
    const offset = CIRCUMFERENCE * (1 - pct);

    elGaugeArc.style.strokeDashoffset = offset;
    elGaugeArc.style.stroke = color;
    elGaugeScore.textContent = score !== null && score !== undefined ? score : '—';
    elGaugeScore.style.color = color;
  }

  // ─── Main Render ─────────────────────────────────────────────────────────────

  function renderResult(data) {
    const cfg     = VERDICT_CONFIG[data.verdict] ?? VERDICT_CONFIG.OFFLINE;
    const flags   = Array.isArray(data.flags) ? data.flags : [];
    const action  = data.recommended_action ?? '';
    const client  = CLIENT_LABELS[data.client] ?? CLIENT_LABELS.unknown;
    const score   = data.score ?? data.combined_score;

    // Switch to result view
    elLoading.classList.add('hidden');
    elEmpty.classList.add('hidden');
    elResult.classList.remove('hidden');

    // Gauge
    renderGauge(score, cfg.color);

    // Verdict badge
    elVerdictBadge.innerHTML = `${cfg.emoji} ${cfg.label}`;
    elVerdictBadge.style.background = `${cfg.color}20`;
    elVerdictBadge.style.color = cfg.color;
    elVerdictBadge.style.border = `1px solid ${cfg.color}55`;

    // Meta
    elClientLabel.textContent = client;
    elTimestamp.textContent = data.timestamp
      ? `Last scan: ${new Date(data.timestamp).toLocaleTimeString()}`
      : '';

    // Flags
    if (flags.length > 0) {
      elFlagsSection.classList.remove('hidden');
      elFlagsContainer.innerHTML = flags.map(f => `
        <span style="
          background: ${cfg.color}18;
          border: 1px solid ${cfg.color}44;
          color: ${cfg.color};
          border-radius: 999px;
          padding: 2px 10px;
          font-size: 11px;
          white-space: nowrap;
        ">${escapeHtml(f)}</span>
      `).join('');
    }

    // Recommended action
    if (action) {
      elActionSection.classList.remove('hidden');
      elActionText.textContent = action;
    }
  }

  function showEmpty() {
    elLoading.classList.add('hidden');
    elEmpty.classList.remove('hidden');
    elResult.classList.add('hidden');
  }

  // ─── Rescan Button ──────────────────────────────────────────────────────────

  elRescanBtn.addEventListener('click', () => {
    elRescanBtn.textContent = '...';
    elRescanBtn.disabled = true;

    chrome.runtime.sendMessage({ type: 'RESCAN' }, () => {
      // Close popup after triggering rescan — content script will update the overlay
      window.close();
    });
  });

  // ─── Init ───────────────────────────────────────────────────────────────────

  chrome.storage.local.get('lastScanResult', (data) => {
    const result = data?.lastScanResult;
    if (!result) {
      showEmpty();
      return;
    }
    renderResult(result);
  });

  // ─── Helpers ────────────────────────────────────────────────────────────────

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

})();
