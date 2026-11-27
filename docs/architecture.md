# Architecture

```text
Browser → FastAPI API → rate limiter → explainable detectors → SQLite
                                        └→ optional ML classifier
                                        └→ local Ollama/Qwen explainer
```

The scanner treats URLs strictly as text. It does not fetch, render, execute, or follow submitted links.

## Continuous-abuse protection

The API maintains a short per-IP request window. Exceeding the configured request threshold returns HTTP 429 and records a privacy-preserving IP hash in `security_events`. This is appropriate hackathon-level protection. A production deployment should put a managed rate limiter/WAF in front of the API, use Redis for shared counters, and add authentication.

## Neural network

`app/ml/train.py` trains a small MLP classifier over URL features. It is deliberately separated from rule scoring until it is evaluated on a suitable dataset. Its probability should be displayed as supporting evidence, not presented as certainty.
