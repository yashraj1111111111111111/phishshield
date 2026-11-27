# Architecture

```text
Browser → FastAPI API → rate limiter → explainable detectors → SQLite
                                        └→ optional ML classifier
                                        └→ local Ollama/Qwen explainer
```

The scanner treats URLs strictly as text. It does not fetch, render, execute, or follow submitted links.

## Continuous-abuse protection & deployment limits

The FastAPI API maintains an in-memory, per-process per-IP request window. Exceeding `RATE_LIMIT_PER_MINUTE` returns HTTP 429 and records a salted SHA-256 IP hash in `security_events`. By default, `X-Forwarded-For` is ignored to prevent header spoofing; set `TRUST_PROXY_HEADERS=true` only when running behind a trusted reverse proxy that overwrites or sets `X-Forwarded-For`.

On **Streamlit Community Cloud** (`streamlit_app.py`), browser requests arrive over Streamlit's shared proxy/WebSocket layer, so per-IP limiting is ineffective; `streamlit_app.py` therefore uses a per-session identifier (`st.session_state.client_id`) for rate limiting. Additionally, SQLite (`database/phishshield.db`) on Streamlit Community Cloud is ephemeral and resets across app restarts or sleep cycles. By default (`STORE_SCAN_CONTENT=false`), submitted text is redacted (`"[redacted]"`) in `scans`, campaign detection matches against salted non-reversible digests in `scan_fingerprints`, and rows older than `SCAN_RETENTION_DAYS` are automatically purged. A production deployment should put a managed rate limiter/WAF in front of the API, use Redis for shared counters, use a managed database, and add authentication.

## Neural network

`app/ml/train.py` trains a small MLP classifier over URL features. It is deliberately separated from rule scoring until it is evaluated on a suitable dataset. Its probability should be displayed as supporting evidence, not presented as certainty.
