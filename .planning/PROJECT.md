# ThreatLens Backend

## What This Is

ThreatLens Backend is an advanced parameter-based system designed to detect phishing URLs using structural characteristics rather than relying on hardcoded threat blacklists. It extracts 50+ specific features from any URL or email body and scores them using a three-layer architecture (RandomForest logic, DistilBERT text analysis, and hard deterministic rules) to provide explainable risk flags and accurately classify zero-day phishing attempts.

## Core Value

Achieving 90%+ classification accuracy without relying on blacklists, through highly explainable structural analysis that detects zero-day phishing threats in milliseconds.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

(None yet — ship to validate)

### Active

<!-- Current scope. Building toward these. -->

- [ ] Build Feature Extraction Engine capable of parsing 50+ binary and numerical URL parameters.
- [ ] Gather, clean, and balance a dataset of 10,000+ real-world URLs for training purposes.
- [ ] Train, optimize, and serialize a RandomForestClassifier on extracted URL parameters.
- [ ] Implement a pre-trained DistilBERT integration to perform email-body textual analysis.
- [ ] Build a FastAPI server exposing `/analyze/url`, `/analyze/email`, and `/analyze/combined` endpoints.
- [ ] Combine model inferences and hard rules using a distinct 40/40/20 weighted architecture.
- [ ] Develop dynamic human-readable risk flags tracing decisions down to specific URL parameters.

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
*Last updated: 2026-04-02 after initialization*
