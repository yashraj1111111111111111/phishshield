# PhishShield

**PhishShield** is a privacy-first phishing-link and scam-message checker for students and families. Paste a URL or message to receive a risk score, clear evidence, and an optional plain-language explanation generated locally through Ollama.

It never opens, visits, or executes submitted links.

## Features

- URL and message risk checks: HTTPS, raw IP links, look-alike domains, URL shorteners, encoded URLs, urgency, KYC, OTP, prize and payment language.
- Explainable score: **Safe**, **Suspicious**, or **Dangerous** with concrete reasons.
- Unique 12-digit scan reference for every scan.
- SQLite scan history and security-event log (`database/phishshield.db`).
- In-memory per-IP rate limiting (salted SHA-256 IP hashes via `IP_HASH_SALT`) and repeated-domain / similar-message campaign detection.
- Local Qwen/Ollama explanation in English or Hindi (with built-in offline English and Hindi fallbacks).
- Documented ML dataset preparation, stratified evaluation (`analytics/evaluation_report.md`), and supporting MLP probability signal (`ml_probability`).

## Safety rules

- **Never open, fetch, render, or execute submitted URLs.** All inspection is strictly lexical/textual.
- Never commit `.env`, local SQLite databases (`database/*.db`), or raw datasets (`data/raw/`).

## Quick start

### Backend

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8001
```

The API will be available at `http://127.0.0.1:8001` and its interactive documentation at `/docs`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the local address Vite prints (normally `http://localhost:5173`). Override the backend URL with `VITE_API_URL` if needed.

## Local Qwen explanation (optional)

PhishShield works without an AI model. To enable explanations through Ollama (`qwen3.5:9b`), make sure Ollama is running and set these variables in `.env` (or export them) before starting the backend:

```bash
OLLAMA_MODEL=qwen3.5:9b
ENABLE_LLM_EXPLANATIONS=true
```

If your installed model has a different tag, replace the value with `ollama list` output.

## Prepare dataset, train, and evaluate the neural network

1. Either place an external dataset CSV (`url,label` where `0` = benign and `1` = phishing) at `data/raw/phishing_urls.csv` and run `python -m app.ml.prepare_data` (for UCI PhiUSIIL, pass `--raw data/raw/PhiUSIIL_Phishing_URL_Dataset.csv --invert-labels`), or omit `--raw` to generate the safe RFC 2606/5737 reserved-domain baseline:

```bash
python -m app.ml.prepare_data --raw data/raw/PhiUSIIL_Phishing_URL_Dataset.csv --invert-labels
```

2. Train the `StandardScaler` + `MLPClassifier` pipeline and write held-out test metrics (`precision`, `recall`, `F1`, `FPR`, `FNR`) to `analytics/evaluation_report.md` and `analytics/evaluation_metrics.json`:

```bash
python -m app.ml.train
```

The model is an additional confidence signal (`ml_probability`), not the sole decision-maker. The explainable rules remain the primary source of evidence.

## Running tests

```bash
python -m pytest -v
cd frontend && npm test && npm run build
```

## Safe demo inputs

- `https://account-security.example/verify?urgent=true`
- `Your KYC will expire today. Verify now at http://198.51.100.42/login and share your OTP.`

These are reserved example addresses, not live malicious sites.

## GitHub checklist

```bash
git init
git add .
git commit -m "Initial PhishShield prototype"
git branch -M main
git remote add origin YOUR_GITHUB_REPOSITORY_URL
git push -u origin main
```

Never commit `.env`, local SQLite databases, raw datasets, or API credentials.

## Project layout

See `docs/architecture.md` for the system design and `docs/demo-script.md` for a concise judging demo.
