"""Train and evaluate a small neural network from data/processed/phishing_urls.csv (url,label[,source])."""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import joblib
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from app.ml.features import url_features

DATASET_PATH = Path("data/processed/phishing_urls.csv")
MODEL_PATH = Path("app/ml/models/phishing_mlp.joblib")
METRICS_JSON_PATH = Path("analytics/evaluation_metrics.json")
STRATIFIED_METRICS_PATH = Path("analytics/evaluation_metrics_stratified.json")
REPORT_MD_PATH = Path("analytics/evaluation_report.md")


def load_dataset(csv_path: Path = DATASET_PATH) -> tuple[list[str], list[int], list[str]]:
    if not csv_path.exists():
        raise SystemExit(
            "Dataset missing: run `python -m app.ml.prepare_data` or add data/processed/phishing_urls.csv with url,label columns."
        )
    urls: list[str] = []
    labels: list[int] = []
    sources: list[str] = []
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            url = (row.get("url") or "").strip()
            raw_label = (row.get("label") or "").strip()
            source = (row.get("source") or "original").strip() or "original"
            if not url or raw_label not in {"0", "1"}:
                continue
            urls.append(url)
            labels.append(int(raw_label))
            sources.append(source)
    if len(urls) < 20 or len(set(labels)) < 2:
        raise SystemExit("Dataset must contain at least 20 records with both benign (0) and phishing (1) labels.")
    return urls, labels, sources


def _base_domain(url: str) -> str:
    candidate = url if "://" in url else f"https://{url}"
    try:
        host = (urlparse(candidate).hostname or "").lower()
    except ValueError:
        host = ""
    if host.startswith("www."):
        host = host[4:]
    return host or url.lower()


def _classification_metrics(y_true: list[int], y_pred: list[int]) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) else 0.0
    return {
        "count": len(y_true),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def _threshold_sweep(y_true: list[int], probs: list[float]) -> list[dict]:
    table: list[dict] = []
    for thresh in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
        preds = [1 if p >= thresh else 0 for p in probs]
        row = _classification_metrics(y_true, preds)
        row["threshold"] = thresh
        table.append(row)
    return table


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
    urls, labels, sources = load_dataset(csv_path)
    features = [url_features(url) for url in urls]
    groups = [_base_domain(url) for url in urls]

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(splitter.split(features, labels, groups=groups))

    x_train = [features[i] for i in train_idx]
    y_train = [labels[i] for i in train_idx]
    x_test = [features[i] for i in test_idx]
    y_test = [labels[i] for i in test_idx]
    test_sources = [sources[i] for i in test_idx]

    model = make_pipeline(
        StandardScaler(),
        MLPClassifier(hidden_layer_sizes=(16, 8), max_iter=200, early_stopping=True, random_state=42),
    )
    model.fit(x_train, y_train)
    probs = [float(p) for p in model.predict_proba(x_test)[:, 1]]
    predictions = [1 if p >= 0.5 else 0 for p in probs]

    overall = _classification_metrics(y_test, predictions)
    orig_pairs = [(y, pred) for y, pred, src in zip(y_test, predictions, test_sources) if src == "original"]
    aug_pairs = [(y, pred) for y, pred, src in zip(y_test, predictions, test_sources) if src == "augmented"]
    original_metrics = (
        _classification_metrics([y for y, _ in orig_pairs], [p for _, p in orig_pairs]) if orig_pairs else None
    )
    augmented_metrics = (
        _classification_metrics([y for y, _ in aug_pairs], [p for _, p in aug_pairs]) if aug_pairs else None
    )

    sanity_passed, sanity_probes = evaluate_behavioral_sanity(model)
    benign_urls = [u for u, lbl in zip(urls, labels) if lbl == 0]
    benign_path_share = round(sum(1 for u in benign_urls if u.count("/") >= 3) / len(benign_urls), 4)

    metrics = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_path": str(csv_path),
        "split_strategy": "GroupShuffleSplit by base domain (80/20, random_state=42)",
        "total_records": len(urls),
        "train_records": len(x_train),
        "test_records": len(x_test),
        "unique_domains": len(set(groups)),
        "benign_with_paths_ratio": benign_path_share,
        **{k: overall[k] for k in ("accuracy", "precision", "recall", "f1_score", "false_positive_rate", "false_negative_rate", "confusion_matrix")},
        "subset_metrics": {
            "original": original_metrics,
            "augmented": augmented_metrics,
        },
        "threshold_sweep": _threshold_sweep(y_test, probs),
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
    orig = metrics.get("subset_metrics", {}).get("original")
    aug = metrics.get("subset_metrics", {}).get("augmented")

    subset_lines = []
    if orig:
        subset_lines.append(
            f"| Original UCI rows (`{orig['count']}`) | {orig['accuracy']:.4f} | {orig['precision']:.4f} | "
            f"{orig['recall']:.4f} | {orig['f1_score']:.4f} | {orig['false_positive_rate']:.4f} | {orig['false_negative_rate']:.4f} |"
        )
    if aug:
        subset_lines.append(
            f"| Augmented benign rows (`{aug['count']}`) | {aug['accuracy']:.4f} | — | — | — | "
            f"{aug['false_positive_rate']:.4f} | — |"
        )
    subset_block = ""
    if subset_lines:
        subset_block = (
            "\n## Original vs. Augmented Breakdown (Held-Out Domain Split)\n\n"
            "| Subset | Accuracy | Precision | Recall | F1 | FPR | FNR |\n"
            "| --- | --- | --- | --- | --- | --- | --- |\n"
            + "\n".join(subset_lines)
            + "\n"
        )

    thresh_rows = "\n".join(
        f"| {row['threshold']:.1f} | {row['precision']:.4f} | {row['recall']:.4f} | {row['f1_score']:.4f} | "
        f"{row['false_positive_rate']:.4f} | {row['false_negative_rate']:.4f} |"
        for row in metrics.get("threshold_sweep", [])
    )

    prev_block = ""
    if STRATIFIED_METRICS_PATH.exists():
        prev = json.loads(STRATIFIED_METRICS_PATH.read_text(encoding="utf-8"))
        prev_block = (
            "\n## Previous Stratified Split Baseline (Archived)\n\n"
            f"Preserved in `{STRATIFIED_METRICS_PATH}`: "
            f"accuracy={prev['accuracy']:.4f}, precision={prev['precision']:.4f}, "
            f"recall={prev['recall']:.4f}, f1={prev['f1_score']:.4f}, "
            f"fpr={prev['false_positive_rate']:.4f}, fnr={prev['false_negative_rate']:.4f}.\n"
        )

    report = f"""# PhishShield MLP Evaluation Report

- **Evaluated at (UTC):** {metrics["evaluated_at"]}
- **Dataset:** `{metrics["dataset_path"]}` ({metrics["total_records"]} total across {metrics["unique_domains"]} base domains: {metrics["train_records"]} train / {metrics["test_records"]} test; benign URLs with paths: {metrics["benign_with_paths_ratio"]:.1%})
- **Split Strategy:** {metrics["split_strategy"]}
- **Model:** `StandardScaler` + `MLPClassifier(hidden_layer_sizes=(16, 8), max_iter=200, early_stopping=True)` over 14 lexical URL features
- **Behavioral Sanity Probes Passed:** {metrics["behavioral_sanity_passed"]}

## Held-Out Domain-Grouped Metrics (Threshold = 0.5)

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
{subset_block}
## Precision / Recall Across Decision Thresholds

| Threshold | Precision | Recall | F1 Score | FPR | FNR |
| --- | --- | --- | --- | --- | --- |
{thresh_rows}
{prev_block}
> Note: The classifier uses strictly lexical URL features without fetching pages. Its probability (`ml_probability`) is exposed strictly as a supporting confidence signal alongside explainable rule findings and never lowers a rule-derived risk score.
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
