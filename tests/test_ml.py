import pytest

from app import config
from app.database.connection import initialize_database
from app.detectors.scanner import scan
from app.ml.predictor import MODEL_PATH, predict_url_probability
from app.services.abuse_protection import reset_rate_limits
from app.services.scan_pipeline import run_scan_pipeline


@pytest.mark.skipif(not MODEL_PATH.exists(), reason="Trained MLP artifact not present")
def test_mlp_does_not_misclassify_benign_deep_path_urls():
    benign_urls = [
        "https://www.example.com",
        "https://example.com",
        "https://example.edu",
        "https://chrisleverseo.com/tools/random-url-generator/",
        "https://docs.python.org/3/library/pathlib.html",
        "https://example.org/search?q=random&page=2",
    ]
    for url in benign_urls:
        prob = predict_url_probability(url, "url")
        assert prob is not None
        assert prob < 0.35, f"Expected low phishing probability for benign URL {url}, got {prob}"


@pytest.mark.skipif(not MODEL_PATH.exists(), reason="Trained MLP artifact not present")
def test_mlp_flags_clear_phishing_patterns():
    phishing_urls = [
        "http://198.51.100.42/verify",
        "http://paypal-login-secure.example/account/update",
    ]
    for url in phishing_urls:
        prob = predict_url_probability(url, "url")
        assert prob is not None
        assert prob > 0.70, f"Expected high phishing probability for {url}, got {prob}"


def test_ml_never_lowers_rule_score(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "ml_mono.db"))
    monkeypatch.setattr(config, "ENABLE_LLM_EXPLANATIONS", False)
    reset_rate_limits()
    initialize_database()

    sample_url = "http://198.51.100.42/verify"
    rule_only = scan(sample_url)

    monkeypatch.setattr("app.services.scan_pipeline.predict_url_probability", lambda *_args, **_kwargs: 0.0)
    outcome_low_ml = run_scan_pipeline(sample_url, "en", "127.0.0.1")
    assert outcome_low_ml.risk_score >= rule_only.score
    assert outcome_low_ml.risk_level == rule_only.level

    monkeypatch.setattr("app.services.scan_pipeline.predict_url_probability", lambda *_args, **_kwargs: 1.0)
    outcome_high_ml = run_scan_pipeline(sample_url, "en", "127.0.0.1")
    assert outcome_high_ml.risk_score >= rule_only.score
    reset_rate_limits()
