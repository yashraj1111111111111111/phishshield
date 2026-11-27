import pytest

from app.ml.predictor import MODEL_PATH, predict_url_probability


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
