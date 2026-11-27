# PhishShield MLP Evaluation Report

- **Evaluated at (UTC):** 2026-11-27T08:29:13.173181+00:00
- **Dataset:** `data/processed/phishing_urls.csv` (235370 total: 188296 train / 47074 test)
- **Model:** `StandardScaler` + `MLPClassifier(hidden_layer_sizes=(16, 8), max_iter=200, early_stopping=True)` over 14 lexical URL features

## Held-Out Test Metrics

| Metric | Value |
| --- | --- |
| Accuracy | 0.9949 |
| Precision | 0.9986 |
| Recall | 0.9894 |
| F1 Score | 0.9940 |
| False-Positive Rate (FPR) | 0.0010 |
| False-Negative Rate (FNR) | 0.0106 |

## Confusion Matrix

- True Negatives (Benign -> Benign): 26943
- False Positives (Benign -> Phishing): 27
- False Negatives (Phishing -> Benign): 213
- True Positives (Phishing -> Phishing): 19891

> Note: The classifier uses strictly lexical URL features without fetching pages. Its probability (`ml_probability`) is exposed strictly as a supporting confidence signal alongside explainable rule findings.
