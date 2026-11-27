"""Train a small neural network from data/processed/phishing_urls.csv (url,label)."""
from pathlib import Path

import joblib
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from app.ml.features import url_features


def main() -> None:
    csv_path = Path("data/processed/phishing_urls.csv")
    if not csv_path.exists():
        raise SystemExit("Dataset missing: add data/processed/phishing_urls.csv with url,label columns.")
    rows = [line.strip().split(",", 1) for line in csv_path.read_text().splitlines()[1:] if "," in line]
    urls, labels = zip(*rows)
    model = make_pipeline(StandardScaler(), MLPClassifier(hidden_layer_sizes=(16, 8), max_iter=500, random_state=42))
    model.fit([url_features(url) for url in urls], [int(label) for label in labels])
    Path("app/ml/models").mkdir(parents=True, exist_ok=True)
    joblib.dump(model, "app/ml/models/phishing_mlp.joblib")
    print(f"Trained model on {len(urls)} records.")


if __name__ == "__main__":
    main()
