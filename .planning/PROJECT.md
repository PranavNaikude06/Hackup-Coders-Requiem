# ThreatLens

## What This Is

ThreatLens is an AI-powered phishing detection platform that analyzes URLs, email bodies, and file attachments across multiple vectors. It uses a 3-layer detection engine — RandomForest URL analysis, DistilBERT email NLP, and hard deterministic rules — combined into a single risk score (0-100) with human-readable explainability. Built by Coder's Requiem for HackUp 2026.

## Current Milestone: v4.0 B2B SaaS API Platform

**Goal:** Transform ThreatLens into a self-serve B2B API platform where businesses generate API keys and consume phishing detection as a service, with usage tracking and rate limiting.

**Target features:**
- Self-serve Developer Dashboard for API key generation (Frontend)
- Secure `tl_live_xxxx` API key storage in Firestore per user
- FastAPI middleware validating `X-API-Key` header on all scan endpoints
- URL scanning, email scanning, file attachment scanning exposed as authenticated REST API
- Per-key usage tracking logged to Firestore (`key_id`, `endpoint`, `timestamp`)
- Rate limiting with 100 req/month free tier, returning `429` when exceeded
- Developer Dashboard UI showing usage stats and key management

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

- [ ] API key generation endpoint and Firestore storage
- [ ] FastAPI API key authentication middleware
- [ ] Authenticated `/api/v1/scan/url` endpoint
- [ ] Authenticated `/api/v1/scan/email` endpoint
- [ ] Authenticated `/api/v1/scan/file` endpoint
- [ ] Per-key usage tracking in Firestore
- [ ] Rate limiting enforcement (100 req/month free tier)
- [ ] Developer Dashboard frontend page (key display, usage stats, regenerate)

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
*Last updated: 2026-04-04 Milestone v4.0 started*
