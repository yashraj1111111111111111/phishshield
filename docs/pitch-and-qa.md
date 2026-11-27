# PhishShield Pitch & Judge Q&A

## 60-Second Pitch

Every day, students and parents receive urgent KYC expiry texts, fake parcel links, job offers, and prize alerts. Most security tools either require installing heavy software or just flash a cryptic warning without explaining *why* a link or message is risky—and checking a link by opening it can already expose the user.

**PhishShield** is a privacy-first phishing and scam checker built for everyday families:

1. **Zero-click safety:** PhishShield inspects URLs and messages strictly as text. It **never opens, fetches, renders, or executes** submitted links.
2. **Explainable scoring (0–100):** Transparent rules score risk into **Safe**, **Suspicious**, or **Dangerous** with concrete evidence (raw IP links, brand look-alikes, URL shorteners, `%`/`@` obfuscation, urgency, and OTP/PIN/CVV/KYC requests), backed by a unique 12-digit scan reference.
3. **Supporting neural network:** A scikit-learn `MLPClassifier` trained and evaluated on **235,370 URLs** from the UCI PhiUSIIL dataset (`0.9940` F1, `0.9986` precision, `0.9894` recall, `0.0010` FPR) provides a secondary `ml_probability` confidence signal alongside the rules.
4. **Inclusive local AI explanations:** Local `qwen3.5:9b` via Ollama translates technical indicators into plain **English or Hindi** (with built-in offline fallbacks if Ollama is unavailable).
5. **Built-in abuse & campaign protection:** Per-IP rate limiting (`429` after 10 scans/min) and repeated-domain / similar-message campaign detection log events to SQLite using salted SHA-256 IP hashes—never storing raw IP addresses.

---

## Likely Judge Questions & Answers

### 1. Does PhishShield visit or sandbox the submitted URL?
No. By design, `app/detectors/scanner.py` and `app/ml/features.py` perform only lexical parsing (`urlparse`, regexes, and `ipaddress`) on the submitted string. Eliminating outbound requests prevents tracking pixel leaks, redirect chains, and drive-by payload execution.

### 2. Why combine deterministic rules with a neural network instead of using only ML?
Explainability and trust. Families need concrete reasons (*"uses a raw IP address"*, *"asks for an OTP"*) rather than a black-box score. Rules remain the primary decision-maker, while the MLP adds a calibrated lexical similarity signal (`ml_probability`) exposed as supporting evidence.

### 3. How was the neural network evaluated?
Using `app/ml/prepare_data.py` and `app/ml/train.py` on **235,370** deduplicated URLs from the UCI PhiUSIIL dataset with an 80/20 stratified split (`188,296` train / `47,074` held-out test):
- Accuracy: **0.9949**
- Precision: **0.9986**
- Recall: **0.9894**
- F1 Score: **0.9940**
- False-Positive Rate: **0.0010** | False-Negative Rate: **0.0106**

Full metrics are saved in `analytics/evaluation_report.md` and `analytics/evaluation_metrics.json`.

### 4. Why run `qwen3.5:9b` locally via Ollama instead of a cloud LLM API?
Scam messages often contain personal context, partial account details, or family phone numbers. Running `qwen3.5:9b` locally keeps submitted text on the user's own machine, works offline, and avoids API costs—with deterministic English/Hindi fallbacks if Ollama is turned off.

### 5. How do you protect user privacy while preventing abuse?
Rate-limit and campaign events in `security_events` store a truncated SHA-256 hash salted with `IP_HASH_SALT` from `.env` rather than raw IP addresses. Repeated-domain and similar-message bursts (`>= 3` suspicious scans within 15 minutes) trigger campaign alerts automatically.

### 6. What would you add next after the hackathon?
- Redis-backed rate limiting and multi-worker deployment behind a reverse proxy/WAF.
- Unicode/IDN homograph detection and a browser extension / WhatsApp-forwarding workflow.
- Periodically retraining the classifier on fresh, diverse multilingual scam message corpora.
