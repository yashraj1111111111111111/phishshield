"""Load the trained phishing MLP classifier and score URLs safely without network calls."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import joblib

from app.ml.features import url_features

MODEL_PATH = Path("app/ml/models/phishing_mlp.joblib")
URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s]+", flags=re.IGNORECASE)


@lru_cache(maxsize=2)
def _load_model(path_str: str, mtime_ns: int):
    return joblib.load(path_str)


def predict_url_probability(content: str, content_type: str, model_path: Path = MODEL_PATH) -> float | None:
    """Return phishing probability in [0, 1] for a URL or message URLs, or None if unavailable."""
    if not model_path.exists():
        return None
    urls = [content.strip()] if content_type == "url" else URL_PATTERN.findall(content)
    if not urls:
        return None
    try:
        stat = model_path.stat()
        model = _load_model(str(model_path), stat.st_mtime_ns)
        probabilities = model.predict_proba([url_features(url) for url in urls])
    except Exception:
        return None
    return round(float(max(row[1] for row in probabilities)), 4)
