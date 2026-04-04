# ThreatLens Platform

ThreatLens is an advanced AI-powered security platform and phishing detection engine designed to identify and analyze potential threats in real-time. It analyzes URLs, emails, and file attachments dynamically using a combination of structural extraction, machine learning classification, and large language models.

## Project Structure

This is a monorepo containing three core components:

* **`/backend`**: The core FastAPI server that handles ML inference, VirusTotal integration, and LLM orchestration.
* **`/frontend`**: A React/Vite-powered web dashboard with real-time Server-Sent Events (SSE) streaming for analysis results.
* **`/extension`**: A Chrome Web Extension providing on-page, real-time threat detection capabilities.

> **Note:** The platform is currently configured for local execution and is not yet hosted in production. Follow the instructions below to run the full environment locally.

---

## Getting Started Locally

### Prerequisites

* Python 3.11+
* Node.js & npm (for the frontend)
* Chromium-based browser (for the extension)

### 1. Starting the Backend (FastAPI)

1. Open a terminal and navigate to the `backend` directory:
   ```bash
   cd backend
   ```
2. Create and activate a Python virtual environment (recommended):
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Mac/Linux:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Configure Environment Variables:
   Create a `.env` file in the **root directory** of the project with your API keys:
   ```env
   GROQ_API_KEY=your_key_here
   OPENROUTER_API_KEY=your_key_here
   VIRUSTOTAL_API_KEY=your_key_here
   ```
5. Run the server:
   ```bash
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
   The backend API will be available at `http://127.0.0.1:8000`.

### 2. Starting the Frontend (Web Dashboard)

The frontend is configured to automatically proxy `/api` requests to your local backend server (`localhost:8000`) during development.

1. Open a **new** terminal and navigate to the `frontend` directory:
   ```bash
   cd frontend
   ```
2. Install npm dependencies:
   ```bash
   npm install
   ```
3. Start the Vite development server:
   ```bash
   npm run dev
   ```
   The web interface will typically be available at `http://localhost:5173`.

### 3. Loading the Chrome Extension

1. Open your Chromium-based browser (Chrome, Edge, Brave).
2. Navigate to `chrome://extensions/`.
3. Enable **Developer mode** using the toggle in the top right corner.
4. Click **Load unpacked**.
5. Select the `extension` folder located inside this repository.
6. The extension icon should now be visible in your browser toolbar!

---

## Deployment Configuration (Upcoming)

While you are currently running the platform locally, the repository contains configuration files to easily deploy to production once you are ready:

* **Backend**: Contains a root `Dockerfile` and `railway.json` for one-click deployment to [Railway.app](https://railway.app/).
* **Frontend**: Optimized for deployment on [Vercel](https://vercel.com/) with native support for the `VITE_API_URL` environment variable to link securely to the hosted backend.
