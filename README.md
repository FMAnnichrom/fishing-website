# AI-Powered Phishing URL Detection System

An evidence-based phishing URL detection platform combining machine learning (URL structural features + character n-gram TF-IDF), multi-provider threat-intelligence adapters, categorized suspicious keyword detection, persistent threat-feed ingestion, and optional SSRF-hardened website inspection.

> **Security Note**: No automated system can guarantee that a website is completely safe. A newly launched phishing domain may not yet appear in any threat-intelligence feed. Always verify domains independently before entering sensitive credentials.

---

## Architecture Overview

- **Frontend (`src/`)**: React + Vite + Tailwind CSS + Lucide icons. Single-input URL analyzer, transparent security assessment report with 5-tier verdicts (`Confirmed Malicious`, `High Risk`, `Suspicious`, `No Known Threat`, `Unable to Verify`), prioritized `Evidence Findings`, expandable `Advanced URL Analysis` (PSL registrable domain, subdomains, decoded paths, query parameters, brand similarity), recent scan history, threat statistics, threat-feed & keyword explorer, ML evaluation dashboard, and suspicious URL reporting workflow.
- **Advanced URL Analysis & Brand Detection (`backend/services/advancedUrlAnalyzer.ts`, `backend/services/brandDetector.ts`)**: Public Suffix List (`tldts`) domain extraction, mixed-case hostname normalization, bounded percent-decoding for hex obfuscation, nested & external redirect analysis, duplicate/lure query parameter inspection, contextual non-standard port classification, Unicode homoglyph normalization, and Damerau-Levenshtein/leetspeak brand lookalike detection.
- **Backend (`server.ts`, `backend/`)**: Node.js + Express + SQLite (`node:sqlite`, persistent at `./data/phishing_detector.db`) with Helmet CSP headers, CORS restrictions, rate limiting, input validation, SSRF/DNS-rebinding guards, and Bearer-protected admin routes.
- **ML Inference & Training (`backend/ml/` & `ml-service/`)**:
  - Embedded Node.js/TypeScript L2-regularized Logistic Regression model (34 Structural/Brand/Redirect/Encoding Features + Character 3–4 Gram TF-IDF) trained via `npx tsx backend/ml/train.ts` and persisted at `ml-service/models/url_classifier_model.json`.
  - Optional Python FastAPI + Scikit-learn RandomForest microservice (`ml-service/main.py`, `ml-service/training/train_model.py`) configurable via `ML_SERVICE_URL` and `docker-compose.yml`.

---

## Quick Start

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Train the ML model** (generates `ml-service/models/url_classifier_model.json` from `ml-service/datasets/urls_dataset.csv` with domain-grouped train/validation/test splits):
   ```bash
   npx tsx backend/ml/train.ts
   ```

3. **Run tests**:
   ```bash
   npx tsx --test tests/detectionEngine.test.ts
   ```

4. **Start the application** (runs Express API + Vite frontend on port `3000`):
   ```bash
   npm run dev
   ```

---

## Threat-Intelligence API Configuration

Copy `.env.example` to `.env` and configure any desired server-side API keys (never place keys in frontend code):

| Variable | Provider | Purpose |
| :--- | :--- | :--- |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing v4 | Checks URLs against Google's `SOCIAL_ENGINEERING` & `MALWARE` lists |
| `PHISHTANK_API_KEY` | PhishTank | Queries community-verified phishing submissions |
| `URLHAUS_AUTH_KEY` | abuse.ch URLhaus | Queries malware & payload distribution URLs |
| `ENABLE_PUBLIC_FEED_SYNC` | OpenPhish & URLhaus Feeds | Set `true` to periodically ingest public feeds into local SQLite storage |
| `ADMIN_API_KEY` | Admin Endpoints | Required Bearer token for `POST /api/admin/feeds/sync`, `POST /api/admin/keywords`, and `GET /api/admin/reports` |

When an external API key is not configured, the backend honestly reports `not_configured` instead of fabricating results.

---

## Optional Isolated Website Inspection

Website inspection is **disabled by default** (`ENABLE_WEBSITE_INSPECTION=false`). When enabled in an isolated deployment:
- Rejects non-HTTP(S) schemes and embedded credentials (`user:pass@`).
- Validates DNS resolution before connecting and on every manual redirect hop (max 3 hops) to block loopback, RFC1918 private networks, IPv6 local addresses, and cloud metadata IPs (`169.254.169.254`).
- Enforces strict 4s request timeout, 512KB download cap, no cookies/credentials, and non-executing static HTML text extraction.

---

## Running the Standalone Python ML Service & Feed Ingestion (Optional)

With Python 3.10+ and Docker/pip installed:
```bash
cd ml-service
pip install -r requirements.txt
python training/train_model.py
uvicorn main:app --host 0.0.0.0 --port 8000
```
Set `ML_SERVICE_URL=http://localhost:8000` in `.env` to route ML inference to FastAPI (automatically falls back to the embedded trained model if unreachable).

To ingest public OpenPhish and URLhaus feeds via Python:
```bash
python scripts/ingest_threat_feeds.py
```

---

## Key API Endpoints

- `POST /api/analyze` — Validate, normalize, and analyze a submitted URL.
- `GET /api/analyze/:id` — Retrieve a stored analysis report by ID.
- `GET /api/stats` — Retrieve detection statistics and recent scans.
- `POST /api/reports` — Submit a suspicious URL for review (stored as `unverified`).
- `GET /api/keywords` — List active categorized suspicious keywords.
- `GET /api/threat-feeds` — List active local threat indicators and pending user reports.
- `GET /api/model/evaluation` — Inspect held-out ML validation/test metrics and confusion matrix.
- `GET /api/health` — Check backend, ML engine, and provider configuration status.
- `POST /api/admin/feeds/sync` — Trigger public threat feed sync (`Authorization: Bearer <ADMIN_API_KEY>`).


---

## Standalone GitHub Pages Deployment

This repository also builds as a **100% standalone static web app** for **GitHub Pages** (`dist/`) with no Node.js or database server required.

In standalone mode (`npm run build:pages` or when `/api/*` is unavailable):
- The trained Logistic Regression + Character N-Gram TF-IDF ML model (`ml-service/models/url_classifier_model.json`), URL validator, structural analyzer, keyword detector, and combined risk scorer execute directly inside the browser.
- Recent scans, statistics, and community URL reports persist locally in browser `localStorage`.
- External threat-intelligence providers (`Google Safe Browsing`, `PhishTank`, `URLhaus`) honestly indicate that a backend proxy is required to protect private API keys.

### Deploy to GitHub Pages (Two Options)

> **Important**: Do **not** set GitHub Pages to `main` → `/ (root)`, because the repository root `index.html` points to uncompiled `/src/main.tsx` TypeScript sources and will show a white screen on static hosting.

**Option A — GitHub Actions (Recommended):**
1. Push this repository to GitHub (`main` branch).
2. In your GitHub repository, open **Settings → Pages** and set **Source** to **GitHub Actions**.
3. The included workflow (`.github/workflows/deploy-pages.yml`) automatically runs ML training, executes unit tests, builds `dist/` via `npm run build:pages`, and publishes to `https://<your-username>.github.io/<repo-name>/`.

**Option B — Deploy from `/docs` Branch Folder:**
1. Run `npm run build:pages` (which builds the compiled standalone bundle into both `dist/` and `docs/`) and commit `docs/`.
2. In **Settings → Pages**, set **Source** to **Deploy from a branch**, select branch **`main`**, and select folder **`/docs`**.

### Local Static Build Check

```bash
npm run build:pages
npx vite preview --port 4173
```
