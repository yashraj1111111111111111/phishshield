# PhishShield

**PhishShield** is a privacy-first phishing-link and scam-message checker for students, parents, and families. Paste a URL or message to receive an explainable risk score, concrete indicators, a supporting ML phishing-similarity signal, and a plain-language explanation in English or Hindi.

It **never opens, fetches, renders, or executes** submitted links.

## Features

- **Lexical URL & message checks:** Detects non-HTTPS links, raw IPv4/IPv6 hosts, look-alike brand domains, URL shorteners, `%`/`@` obfuscation, urgency, KYC/OTP/PIN/CVV pressure language, and malformed IPv6 brackets.
- **Explainable risk tiers:** **Low Risk** (`0–24`, displayed as *Low Risk (Unverified)*), **Suspicious** (`25–59`), and **Dangerous** (`60–100`). Unknown URLs are never promised to be "Safe" or authentic.
- **Progressive-disclosure `Technical details`:** Keeps plain-language reasons front and center while letting advanced users expand text-extracted facts (parsed host, host type, explicit port or `Not specified`, scheme, HTTPS, TLD, URL length, subdomain count, and every triggered rule ID + score contribution) without any network lookup.
- **Supporting neural network:** `StandardScaler` + `MLPClassifier` (`app/ml/models/phishing_mlp.joblib`) providing `ml_probability` as supporting evidence only (never lowers a rule-derived risk score).
- **Plain-language explanations (EN / HI):** Local Ollama (`qwen3.5:9b`) with prompt-injection delimiting, output-length capping, and built-in offline English and Hindi fallbacks.
- **Abuse & campaign protection:** In-memory per-IP rate limiting (HTTP `429`), salted SHA-256 IP hashes (`IP_HASH_SALT`), and repeated-domain / similar-message campaign detection logged to SQLite.
- **Three interfaces:** React/Vite web app (`frontend/`), Streamlit app (`streamlit_app.py`), and Chrome/Edge Manifest V3 link-guard extension (`extension/`).

## Quick Start

### 1. Backend (FastAPI on port `8001`)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8001
```

API root: `http://127.0.0.1:8001` (interactive docs at `http://127.0.0.1:8001/docs`).

### 2. Web Frontend (React + Vite)

```bash
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite (normally `http://localhost:5173`).

### 3. Streamlit App (Local or Streamlit Community Cloud)

```bash
source .venv/bin/activate
streamlit run streamlit_app.py
```

For Streamlit Community Cloud, point the app to `streamlit_app.py` on `main`. Theme defaults are configured in `.streamlit/config.toml` with a live Dark/Light toggle in the UI.

### 4. Deploy Exact React + FastAPI UI Online (Vercel + Render)

To host the exact React interface (`frontend/`) publicly instead of Streamlit:

1. **Deploy the FastAPI backend (`render.yaml`):**
   - Create a new **Blueprint** or **Web Service** on [Render](https://render.com) connected to this GitHub repository (Render automatically reads `render.yaml`).
   - Wait for the service to go live and copy its URL (for example `https://phishshield-api.onrender.com`).
2. **Deploy the React frontend (`frontend/vercel.json`):**
   - Import this GitHub repository on [Vercel](https://vercel.com) and set **Root Directory** to `frontend`.
   - Add environment variable `VITE_API_URL` = your Render backend URL (e.g. `https://phishshield-api.onrender.com`).
   - Deploy. `*.vercel.app` and `*.netlify.app` origins are already allowed by `CORS_ALLOW_ORIGIN_REGEX` (custom domains can be added via `CORS_ALLOW_ORIGINS`).

### 5. Browser Extension (Chrome / Edge MV3)

1. Open `chrome://extensions` (or `edge://extensions`) and enable **Developer mode**.
2. Click **Load unpacked** and select `extension/`.
3. The extension intercepts risky clicks and navigations (`risk_score >= 25`) before opening them and queries `http://127.0.0.1:8001/api/scan` (falling back to local rules in `extension/scanner.js` if the backend is stopped).

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_PATH` | `database/phishshield.db` | SQLite database file path |
| `OLLAMA_MODEL` | `qwen3.5:9b` | Local Ollama model tag |
| `OLLAMA_URL` | `http://localhost:11434/api/generate` | Ollama generate endpoint |
| `ENABLE_LLM_EXPLANATIONS` | `false` | Enable Ollama explanations (`true` / `false`) |
| `RATE_LIMIT_PER_MINUTE` | `10` | Max scans per 60-second sliding window |
| `IP_HASH_SALT` | `phishshield-local-dev-salt` | Secret salt for SHA-256 hashing (`security_events` & `scan_fingerprints`) |
| `TRUST_PROXY_HEADERS` | `false` | Trust left-most `X-Forwarded-For` IP only behind a trusted proxy |
| `STORE_SCAN_CONTENT` | `false` | Persist raw submitted text in `scans` (`false` stores `"[redacted]"`) |
| `SCAN_RETENTION_DAYS` | `30` | Days before `scans`, `scan_fingerprints`, and `security_events` auto-purge (`0` disables) |
| `CORS_ALLOW_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated allowed CORS origins for FastAPI |
| `CORS_ALLOW_ORIGIN_REGEX` | `^(chrome-extension://.*\|https://.*\.vercel\.app\|https://.*\.netlify\.app)$` | Regex for extension and preview/hosted frontend origins |
| `VITE_API_URL` | `http://127.0.0.1:8001` | Frontend API base URL override |

## API Reference

- **`GET /health`** → `200 OK`: `{"status": "ok"}`
- **`POST /api/scan`**
  - Request JSON: `{"content": "<3..5000 chars>", "language": "en" | "hi"}`
  - Response `200 OK`:
    ```json
    {
      "scan_reference": "261127000001",
      "risk_score": 60,
      "risk_level": "Dangerous",
      "content_type": "url",
      "reasons": ["..."],
      "explanation": "...",
      "ml_probability": 1.0,
      "campaign_detected": false,
      "technical_details": {
        "parsed_host": "198.51.100.42",
        "host_type": "ip_address",
        "port": "Not specified",
        "scheme": "http",
        "https": "no",
        "top_level_domain": "Not applicable (IP address)",
        "url_length": 27,
        "subdomain_count": 0,
        "detected_url_indicators": ["..."],
        "detected_message_indicators": [],
        "triggered_rules": [{"rule_id": "url_raw_ip", "category": "url", "score": 30, "reason": "..."}]
      }
    }
    ```
  - Errors: `422 Unprocessable Entity` (validation failure), `429 Too Many Requests` (rate limit exceeded).

## Dataset, Training & Model Metrics

Prepare a deduplicated dataset (`data/processed/phishing_urls.csv`) and train/evaluate with a domain-grouped 80/20 split (`GroupShuffleSplit` by base domain):

```bash
source .venv/bin/activate
python -m app.ml.prepare_data --raw data/raw/PhiUSIIL_Phishing_URL_Dataset.csv --invert-labels
python -m app.ml.train
```

*(Omit `--raw ...` to generate the offline RFC 2606/5737 synthetic baseline.)*

Current held-out domain-grouped evaluation (`355,370` records across `219,094` base domains: `284,457` train / `70,913` test; see `analytics/evaluation_report.md` and archived stratified baseline in `analytics/evaluation_metrics_stratified.json`):

| Subset / Threshold | Accuracy | Precision | Recall | F1 Score | FPR | FNR |
| --- | --- | --- | --- | --- | --- | --- |
| Overall domain-grouped (`0.5`) | `0.9490` | `0.9465` | `0.8665` | `0.9048` | `0.0190` | `0.1335` |
| Original UCI rows (`46,878`) | `0.9429` | `0.9983` | `0.8665` | `0.9278` | `0.0011` | `0.1335` |
| Augmented benign rows (`24,035`) | `0.9608` | — | — | — | `0.0392` | — |

## Running Tests & Verification

```bash
source .venv/bin/activate
python -m pytest -v
(cd frontend && npm test && npm run build)
node --test extension/tests/*.test.mjs
```

With the backend running on port `8001`, you can also run the live end-to-end suite:

```bash
.venv/bin/python verify_phishshield_e2e.py
```

## Privacy

- **Zero-click safety:** Submitted URLs and messages are parsed strictly as strings and never fetched, rendered, or executed.
- **Hashed security logs:** `security_events` records a truncated SHA-256 hash of `IP_HASH_SALT + client_ip` rather than raw IP addresses.
- **Local LLM option:** When `ENABLE_LLM_EXPLANATIONS=true`, prompts are sent only to your local `OLLAMA_URL`, delimited inside `<evidence_data>` tags, length-capped, and checked for prompt-injection phrases before display.
- **Redacted persistence & retention:** `STORE_SCAN_CONTENT` defaults to `false`, so `scans.submitted_content` records `"[redacted]"` instead of raw user input. 15-minute campaign matching uses salted non-reversible digests in `scan_fingerprints`, and records older than `SCAN_RETENTION_DAYS` (default `30`) are purged automatically on write. Never commit `.env`, `database/*.db`, or `data/raw/`.

## Limitations

- **Lexical analysis only (cannot prove authenticity):** PhishShield cannot prove a website is authentic from URL or message text alone. A `Low Risk (Unverified)` or `0/100` result only means no common phishing indicators were detected by this text-only scan—new or convincing scams may not show visible warning signs, because PhishShield intentionally never fetches pages, checks WHOIS/domain age, or queries external threat-intel feeds. Always verify important requests through the organisation's official app, bookmarked website, or a known contact method.
- **Dataset augmentation:** Raw UCI PhiUSIIL benign samples were homepage-only (`www.` + `0` paths), so `app/ml/prepare_data.py` augments benign path and non-`www.` diversity; real-world prevalence differs.
- **Per-process rate limiting & ephemeral cloud DB:** FastAPI rate limiting is in-memory per process (`TRUST_PROXY_HEADERS=false` by default). On Streamlit Community Cloud, rate limiting is per-session and `database/phishshield.db` is ephemeral across container restarts.
- **Indicator language:** When `language=hi` is selected, `explanation` is localized to Hindi while `reasons` strings remain in English.

## Project Layout

- `app/` — FastAPI API, configuration, SQLite repository, rule scanner, ML pipeline, abuse/campaign/explainer services
- `frontend/` — React + Vite web app
- `streamlit_app.py` — Standalone / Streamlit Cloud UI
- `extension/` — Chrome/Edge Manifest V3 link-guard extension
- `analytics/` — Evaluation metrics and Markdown reports
- `docs/` — `architecture.md` and `demo-script.md`
- `tests/` — Pytest suite (`test_api.py`, `test_explainer.py`, `test_ml.py`, `test_scanner.py`, `test_streamlit_app.py`)
