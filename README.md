# PhishShield

**PhishShield** is a privacy-first phishing-link and scam-message checker for students and families. Paste a URL or message to receive a risk score, clear evidence, and an optional plain-language explanation generated locally through Ollama.

It never opens, visits, or executes submitted links.

## Features

- URL and message risk checks: HTTPS, raw IP links, look-alike domains, URL shorteners, encoded URLs, urgency, KYC, OTP, prize and payment language.
- Explainable score: **Safe**, **Suspicious**, or **Dangerous** with concrete reasons.
- Unique 12-digit scan reference for every scan.
- SQLite scan history and security-event log.
- In-memory per-IP rate limiting and a burst detector for abusive traffic.
- Optional local Qwen/Ollama explanation in English or Hindi.
- ML-ready feature pipeline and a small neural-network training script.

## Quick start

### Backend

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The API will be available at `http://127.0.0.1:8000` and its interactive documentation at `/docs`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the local address Vite prints (normally `http://localhost:5173`).

## Local Qwen explanation (optional)

PhishShield works without an AI model. To enable explanations through Ollama, make sure Ollama is running and set these optional variables before starting the backend:

```bash
export OLLAMA_MODEL="qwen3.5:9b"
export ENABLE_LLM_EXPLANATIONS="true"
```

If your installed model has a slightly different tag, replace the value with `ollama list` output.

## Train the neural-network classifier

Put a CSV in `data/processed/phishing_urls.csv` with columns `url,label`, where `label` is `0` for benign and `1` for phishing. Then run:

```bash
python -m app.ml.train
```

The model is an additional confidence signal, not the sole decision-maker. The explainable rules remain the primary source of evidence.

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
