"""Train and evaluate a small neural network from data/processed/phishing_urls.csv (url,label)."""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from app.ml.features import url_features

DATASET_PATH = Path("data/processed/phishing_urls.csv")
MODEL_PATH = Path("app/ml/models/phishing_mlp.joblib")
METRICS_JSON_PATH = Path("analytics/evaluation_metrics.json")
REPORT_MD_PATH = Path("analytics/evaluation_report.md")


def load_dataset(csv_path: Path = DATASET_PATH) -> tuple[list[str], list[int]]:
    if not csv_path.exists():
        raise SystemExit(
            "Dataset missing: run `python -m app.ml.prepare_data` or add data/processed/phishing_urls.csv with url,label columns."
        )
    urls: list[str] = []
    labels: list[int] = []
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            url = (row.get("url") or "").strip()
            raw_label = (row.get("label") or "").strip()
            if not url or raw_label not in {"0", "1"}:
                continue
            urls.append(url)
            labels.append(int(raw_label))
    if len(urls) < 20 or len(set(labels)) < 2:
        raise SystemExit("Dataset must contain at least 20 records with both benign (0) and phishing (1) labels.")
    return urls, labels


def evaluate_behavioral_sanity(model) -> tuple[bool, list[dict]]:
    """Verify the trained model does not trigger shortcut false positives on benign deep-path URLs."""
    probes = [
        ("https://www.example.com", 0, 0.25),
        ("https://example.com", 0, 0.35),
        ("https://example.edu", 0, 0.35),
        ("https://example.org/tools/random-url-generator/", 0, 0.35),
        ("https://docs.example.edu/3/library/pathlib.html", 0, 0.35),
        ("http://198.51.100.42/verify", 1, 0.70),
        ("http://paypal-login-secure.example/account/update", 1, 0.70),
    ]
    results = []
    all_ok = True
    for url, expected, threshold in probes:
        prob = round(float(model.predict_proba([url_features(url)])[0][1]), 4)
        ok = prob < threshold if expected == 0 else prob > threshold
        all_ok = all_ok and ok
        results.append({"url": url, "expected": expected, "prob": prob, "passed": ok})
    return all_ok, results


def train_and_evaluate(csv_path: Path = DATASET_PATH, model_path: Path = MODEL_PATH) -> dict:
    urls, labels = load_dataset(csv_path)
    features = [url_features(url) for url in urls]
    x_train, x_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.2, stratify=labels, random_state=42
    )

    model = make_pipeline(
        StandardScaler(),
        MLPClassifier(hidden_layer_sizes=(16, 8), max_iter=200, early_stopping=True, random_state=42),
    )
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)

    tn, fp, fn, tp = confusion_matrix(y_test, predictions, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) else 0.0
    sanity_passed, sanity_probes = evaluate_behavioral_sanity(model)
    benign_urls = [u for u, lbl in zip(urls, labels) if lbl == 0]
    benign_path_share = round(sum(1 for u in benign_urls if u.count("/") >= 3) / len(benign_urls), 4)

    metrics = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_path": str(csv_path),
        "total_records": len(urls),
        "train_records": len(x_train),
        "test_records": len(x_test),
        "benign_with_paths_ratio": benign_path_share,
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, predictions, zero_division=0)), 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "behavioral_sanity_passed": sanity_passed,
        "behavioral_sanity_probes": sanity_probes,
    }

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    return metrics


def write_analytics_report(metrics: dict, json_path: Path = METRICS_JSON_PATH, md_path: Path = REPORT_MD_PATH) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")

    cm = metrics["confusion_matrix"]
    report = f"""# PhishShield MLP Evaluation Report

- **Evaluated at (UTC):** {metrics["evaluated_at"]}
- **Dataset:** `{metrics["dataset_path"]}` ({metrics["total_records"]} total: {metrics["train_records"]} train / {metrics["test_records"]} test; benign URLs with paths: {metrics["benign_with_paths_ratio"]:.1%})
- **Model:** `StandardScaler` + `MLPClassifier(hidden_layer_sizes=(16, 8), max_iter=200, early_stopping=True)` over 14 lexical URL features
- **Behavioral Sanity Probes Passed:** {metrics["behavioral_sanity_passed"]}

## Held-Out Test Metrics

| Metric | Value |
| --- | --- |
| Accuracy | {metrics["accuracy"]:.4f} |
| Precision | {metrics["precision"]:.4f} |
| Recall | {metrics["recall"]:.4f} |
| F1 Score | {metrics["f1_score"]:.4f} |
| False-Positive Rate (FPR) | {metrics["false_positive_rate"]:.4f} |
| False-Negative Rate (FNR) | {metrics["false_negative_rate"]:.4f} |

## Confusion Matrix

- True Negatives (Benign -> Benign): {cm["tn"]}
- False Positives (Benign -> Phishing): {cm["fp"]}
- False Negatives (Phishing -> Benign): {cm["fn"]}
- True Positives (Phishing -> Phishing): {cm["tp"]}

> Note: The classifier uses strictly lexical URL features without fetching pages. Its probability (`ml_probability`) is exposed strictly as a supporting confidence signal alongside explainable rule findings.
"""
    md_path.write_text(report, encoding="utf-8")


def main() -> None:
    metrics = train_and_evaluate()
    write_analytics_report(metrics)
    print(
        f"Trained & evaluated on {metrics['total_records']} records "
        f"(precision={metrics['precision']:.4f}, recall={metrics['recall']:.4f}, "
        f"f1={metrics['f1_score']:.4f}, fpr={metrics['false_positive_rate']:.4f}, "
        f"fnr={metrics['false_negative_rate']:.4f})."
    )


if __name__ == "__main__":
    main()
