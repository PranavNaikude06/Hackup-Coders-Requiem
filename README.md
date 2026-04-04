# ThreatLens

> Real-time, zero-day phishing detection — no blacklists, no blind spots.

![ThreatLens Dashboard Overview](assets/dashboard_overview.png)

**[▶ Watch Demo](#)** &nbsp;|&nbsp; **Built by Coder's Requiem · HackUp 2026**

---

## The Problem

Every 11 seconds, someone falls victim to a phishing attack. Phishers don't reuse domains — they spin up thousands of short-lived, randomized URLs that traditional security tools have **never seen before**. Blacklist-based tools like VirusTotal are reactive by design. By the time a phishing URL enters a threat database, credentials are already stolen.

**The first 60 minutes of a phishing domain's life are its most dangerous. ThreatLens was built for exactly that window.**

---

## What It Does

ThreatLens is a **3-layer AI detection engine** that analyzes URLs, email bodies, and file attachments simultaneously — producing a single unified risk score (0–100) with human-readable explanations, in milliseconds.

| Layer | Method | Weight |
|---|---|---|
| 🔗 URL Analysis | RandomForestClassifier on 30 structural parameters | 40% |
| 📧 Email NLP | DistilBERT fine-tuned for phishing language patterns | 40% |
| 🛡️ Hard Rules | IP floor, DNS safety floor, confidence capping | 20% |

**Trained on 160,000 samples from the PhishTank dataset.**
**90%+ classification accuracy. Zero blacklists. Zero-day capable.**

---

## Why Not Just Use VirusTotal?

VirusTotal is a **lookup tool** — it only flags URLs it has already seen and catalogued. If a phishing domain was registered this morning, VirusTotal scores it clean.

ThreatLens *understands* a URL structurally regardless of whether it has ever been seen before:

- How deep are the subdomains?
- What is the character entropy of the domain?
- Are there homograph characters mimicking legitimate brands?
- Does the TLD carry inherent risk?
- Is this typosquatting a known brand?

A brand-new phishing domain, zero hours old, will still get caught.

> VirusTotal is integrated into ThreatLens — but only as a **secondary signal** for file attachment scanning, never as the primary detection method.

---

## Key Features

- **30-parameter URL feature extraction** — subdomain depth, entropy, special character ratios, TLD risk scoring, homograph & typosquatting detection
- **DistilBERT email NLP** — detects urgency manipulation, credential harvesting language, and suspicious anchor text patterns
- **VirusTotal attachment scanning** — dynamic sandbox analysis with async polling for file attachments
- **Real-time SSE streaming** — results stream to the UI incrementally as each detection layer completes
- **Chrome Extension (Manifest V3)** — live scanning embedded directly inside Gmail and Outlook Web via MutationObserver
- **Non-intrusive overlay UI** — color-coded threat indicators injected into the email reading pane, auto-dismissed for SAFE results
- **Explainable output** — every risk score ships with human-readable flags and recommended actions

---

## Architecture

```
Browser (Gmail / Outlook Web)
        │
        ▼
Chrome Extension (Manifest V3)
  ├── content_gmail.js       ← MutationObserver on Gmail reading pane
  ├── content_outlook.js     ← MutationObserver on Outlook Web reading pane
  ├── common.js              ← Debouncing, URL filtering, response caching
  └── Popup UI (Tailwind)    ← Risk gauge, client icon, risk flags, rescan
        │
        ▼  REST + SSE Stream
FastAPI Backend (localhost:8000)
  ├── /analyze/url           ← RandomForest on 30 structural URL features
  ├── /analyze/email         ← DistilBERT NLP pipeline
  └── /analyze/attachment    ← VirusTotal dynamic sandbox + async polling
```

---

## Real-World Example

During testing against PhishTank samples, ThreatLens flagged a fake Microsoft login page hosted on a domain registered **4 hours prior** — scoring it **87/100 (HIGH RISK)**. At the time of scanning, VirusTotal returned a **clean result** with 0/90 vendor detections.

Detection was driven entirely by structural signals: abnormal subdomain depth, high character entropy, a spoofed brand keyword embedded mid-path, and a mismatched TLD.

---

## Getting Started

### Prerequisites
- Python 3.11+
- Node.js & npm
- Chromium-based browser (Chrome, Edge, Brave)

### 1. Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```env
GROQ_API_KEY=your_key_here
OPENROUTER_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
# Backend live at http://127.0.0.1:8000
```

### 2. Frontend Dashboard

```bash
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

### 3. Chrome Extension

1. Navigate to `chrome://extensions/`
2. Enable **Developer Mode** (top-right toggle)
3. Click **Load unpacked** → select the `/extension` folder
4. The ThreatLens icon will appear in your browser toolbar
5. Open Gmail or Outlook Web — ThreatLens activates automatically

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI, Python 3.11 |
| ML Classification | Scikit-Learn (RandomForestClassifier) |
| Email NLP | HuggingFace DistilBERT |
| Streaming | Server-Sent Events (SSE) |
| Browser Extension | Chrome Manifest V3, Vanilla JS |
| Frontend Dashboard | React, Vite, Tailwind CSS |
| Threat Intelligence | VirusTotal API |
| Training Data | PhishTank (160,000 samples) |

---

## What's Shipped

| Feature | Status |
|---|---|
| 30-parameter URL feature extraction engine | ✅ Shipped |
| RandomForest trained & serialized (`rf_model.pkl`) | ✅ Shipped |
| DistilBERT email NLP with evidence flags | ✅ Shipped |
| `/analyze/url` and `/analyze/email` API endpoints | ✅ Shipped |
| Typosquatting & homograph detection | ✅ Shipped |
| VirusTotal attachment scanning with async polling | ✅ Shipped |
| SSE streaming integration | ✅ Shipped |
| Chrome Extension — Gmail content script | ✅ Shipped |
| Chrome Extension — Outlook Web content script | ✅ Shipped |
| Chrome Extension — Popup UI with risk gauge | ✅ Shipped |

---

## Team — Coder's Requiem

| Name | GitHub |
|---|---|
| Mayank Bhujbal | [@Mayank-Bhujabal](https://github.com/Mayank-Bhujabal) |
| Sumeet Chauhan | [@SumeetChauhan27](https://github.com/SumeetChauhan27) |
| Pranav Naikude | [@PranavNaikude06](https://github.com/PranavNaikude06) |
| Shrushti Shinde | [@srushtis2504](https://github.com/srushtis2504) |

---

*HackUp 2026 · ThreatLens v3.0*
