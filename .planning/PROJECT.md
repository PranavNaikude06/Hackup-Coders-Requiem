# ThreatLens

## What This Is

ThreatLens is an AI-powered phishing detection platform that analyzes URLs, email bodies, and file attachments across multiple vectors. It uses a 3-layer detection engine — RandomForest URL analysis, DistilBERT email NLP, and hard deterministic rules — combined into a single risk score (0-100) with human-readable explainability. Built by Coder's Requiem for HackUp 2026.

## Current Milestone: v3.0 Chrome Extension Scanner

**Goal:** Build a Manifest V3 Chrome Extension that performs real-time phishing detection in Gmail and Outlook Web by integrating with the existing ThreatLens backend.

**Target features:**
- MV3 Background Service Worker connecting to backend API (`localhost:8000`) and handling SSE streams
- Client-specific content scripts (`content_gmail.js`, `content_outlook.js`) monitoring email reading panes via MutationObserver
- Shared common logic (`common.js`) for debouncing, URL filtering, and caching
- Non-intrusive colored UI overlay injected into reading pane (auto-dismiss for SAFE results)
- Popup UI displaying detailed scan breakdown (gauge, client icon, risk flags) and rescanning controls
- Incremental UI updates using backend SSE stream progress events

## Core Value

Achieving 90%+ classification accuracy without relying on blacklists, through highly explainable structural analysis that detects zero-day phishing threats in milliseconds.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

- ✓ URL feature extraction engine (30 structural parameters) — v1.0 Phase 1
- ✓ RandomForestClassifier trained and serialized (rf_model.pkl) — v1.0 Phase 2
- ✓ DistilBERT email NLP analysis with evidence flags — v1.0 Phase 3
- ✓ `/analyze/url` and `/analyze/email` endpoints — v1.0 Phase 4
- ✓ Human-readable risk flags with recommended actions — v1.0 Phase 5
- ✓ Typosquatting / homograph detection engine — v1.0
- ✓ Hard rules: IP floor, DNS safety floor, confidence capping — v1.0
- ✓ VirusTotal Dynamic Attachment Analysis / Polling & Embed Scanning — v2.0 Phase 10
- ✓ Server-Sent Events (SSE) FastAPI Streaming Integration — v2.0 Phase 11

### Active

<!-- Current scope. Building toward these. -->

- [ ] Chrome Extension background service worker (manifest v3)
- [ ] Gmail content script & mutation observer
- [ ] Outlook Web content script & mutation observer
- [ ] Shared common script (overlay injection, caching, filtering)
- [ ] Popup UI implementation (Tailwind CDN)
- [ ] SSE streaming integration onto UI overlays

### Out of Scope

<!-- Explicit boundaries. Includes reasoning to prevent re-adding. -->

- [Hardcoded Blacklists] — Goes against the core strategy of robust structural detection and zero-day protection.
- [Frontend User Interface] — This phase is strictly focused on building the backend infrastructure and API structure.

## Context

- **Workflow/Ecosystem**: Built primarily in Python, employing tools such as FastAPI, Scikit-Learn, and pre-trained models from HuggingFace.
- **Problem Statement**: Traditional threat analysis relies heavily on pre-determined URL lists. Phishers use randomization to generate short-lived domains, bypassing traditional rulesets.
- **Approach**: Moving to a model that extracts complexity parameters, keyword patterns, and structural counts removes the threat of "first seen" domains.

## Constraints

- **Execution Speed**: Inference must stay fast (milliseconds) — vital for real-time traffic analysis. 
- **Dataset Needs**: Data must be balanced (roughly 50/50 phishing to legitimate target ratios) to prevent structural biases.

## Key Decisions

<!-- Decisions that constrain future work. Add throughout project lifecycle. -->

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Multi-layer Weighting (40% URL, 40% email, 20% hard rules) | Better handles complex attempts while enforcing zero-tolerance behavior | — Pending |
| Adopt RandomForest for URL params | Handles both binary and numeric attributes well and provides feature importance | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "workflow" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-04-04 Milestone v3.0 started*
