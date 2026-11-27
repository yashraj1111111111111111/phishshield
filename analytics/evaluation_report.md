# PhishShield MLP Evaluation Report

- **Evaluated at (UTC):** 2026-11-27T16:19:47.742923+00:00
- **Dataset:** `data/processed/phishing_urls.csv` (355370 total across 219094 base domains: 284457 train / 70913 test; benign URLs with paths: 38.9%)
- **Split Strategy:** GroupShuffleSplit by base domain (80/20, random_state=42)
- **Model:** `StandardScaler` + `MLPClassifier(hidden_layer_sizes=(16, 8), max_iter=200, early_stopping=True)` over 14 lexical URL features
- **Behavioral Sanity Probes Passed:** True

## Held-Out Domain-Grouped Metrics (Threshold = 0.5)

| Metric | Value |
| --- | --- |
| Accuracy | 0.9490 |
| Precision | 0.9465 |
| Recall | 0.8665 |
| F1 Score | 0.9048 |
| False-Positive Rate (FPR) | 0.0190 |
| False-Negative Rate (FNR) | 0.1335 |

## Confusion Matrix

- True Negatives (Benign -> Benign): 50116
- False Positives (Benign -> Phishing): 971
- False Negatives (Phishing -> Benign): 2646
- True Positives (Phishing -> Phishing): 17180

## Original vs. Augmented Breakdown (Held-Out Domain Split)

| Subset | Accuracy | Precision | Recall | F1 | FPR | FNR |
| --- | --- | --- | --- | --- | --- | --- |
| Original UCI rows (`46878`) | 0.9429 | 0.9983 | 0.8665 | 0.9278 | 0.0011 | 0.1335 |
| Augmented benign rows (`24035`) | 0.9608 | — | — | — | 0.0392 | — |

## Precision / Recall Across Decision Thresholds

| Threshold | Precision | Recall | F1 Score | FPR | FNR |
| --- | --- | --- | --- | --- | --- |
| 0.1 | 0.7775 | 0.9590 | 0.8588 | 0.1065 | 0.0410 |
| 0.2 | 0.8482 | 0.9422 | 0.8927 | 0.0655 | 0.0578 |
| 0.3 | 0.8675 | 0.9335 | 0.8993 | 0.0553 | 0.0665 |
| 0.4 | 0.8828 | 0.9229 | 0.9024 | 0.0475 | 0.0771 |
| 0.5 | 0.9465 | 0.8665 | 0.9048 | 0.0190 | 0.1335 |
| 0.6 | 0.9756 | 0.8240 | 0.8934 | 0.0080 | 0.1760 |
| 0.7 | 0.9811 | 0.8154 | 0.8906 | 0.0061 | 0.1846 |
| 0.8 | 0.9857 | 0.8032 | 0.8851 | 0.0045 | 0.1968 |
| 0.9 | 0.9908 | 0.7805 | 0.8732 | 0.0028 | 0.2195 |

## Previous Stratified Split Baseline (Archived)

Preserved in `analytics/evaluation_metrics_stratified.json`: accuracy=0.9475, precision=0.9327, recall=0.8779, f1=0.9045, fpr=0.0250, fnr=0.1221.

> Note: The classifier uses strictly lexical URL features without fetching pages. Its probability (`ml_probability`) is exposed strictly as a supporting confidence signal alongside explainable rule findings and never lowers a rule-derived risk score.
