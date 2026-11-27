# 90-second demo script

1. “Students and parents receive KYC, parcel, prize, and job scams, but the warnings are usually technical.”
2. Paste `Your KYC will expire today. Verify now at http://198.51.100.42/login and share your OTP.` into PhishShield and press **Check safely**.
3. Point out the risk score, raw-IP finding, urgency/OTP warning, supporting ML confidence signal, plain-language explanation, and 12-digit scan reference.
4. Switch to **Hindi** and re-scan to show inclusive explanations (via local `qwen3.5:9b` in Ollama or built-in Hindi fallback).
5. Explain that links are never opened, fetched, or executed, so checking them does not expose the user to the destination.
6. Submit 3 similar scans or rapid bursts to highlight repeated-domain/message **campaign detection** and the friendly HTTP `429` rate-limit protection logged with salted IP hashes in `security_events`.
