# PhishShield MLP Evaluation Report

- **Evaluated at (UTC):** 2026-11-27T12:04:01.625605+00:00
- **Dataset:** `data/processed/phishing_urls.csv` (355370 total: 284296 train / 71074 test; benign URLs with paths: 47.1%)
- **Model:** `StandardScaler` + `MLPClassifier(hidden_layer_sizes=(16, 8), max_iter=200, early_stopping=True)` over 14 lexical URL features
- **Behavioral Sanity Probes Passed:** True

## Held-Out Test Metrics

| Metric | Value |
| --- | --- |
| Accuracy | 0.9462 |
| Precision | 0.9376 |
| Recall | 0.8676 |
| F1 Score | 0.9012 |
| False-Positive Rate (FPR) | 0.0228 |
| False-Negative Rate (FNR) | 0.1324 |

## Confusion Matrix

- True Negatives (Benign -> Benign): 49809
- False Positives (Benign -> Phishing): 1161
- False Negatives (Phishing -> Benign): 2662
- True Positives (Phishing -> Phishing): 17442

> Note: The classifier uses strictly lexical URL features without fetching pages. Its probability (`ml_probability`) is exposed strictly as a supporting confidence signal alongside explainable rule findings.
