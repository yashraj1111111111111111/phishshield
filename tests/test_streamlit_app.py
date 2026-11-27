from pathlib import Path

from streamlit.testing.v1 import AppTest

from app import config
from app.services.abuse_protection import reset_rate_limits

APP_PATH = Path(__file__).resolve().parents[1] / "streamlit_app.py"


def test_streamlit_app_safe_and_dangerous_scans(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "st_test.db"))
    monkeypatch.setattr(config, "ENABLE_LLM_EXPLANATIONS", False)
    monkeypatch.setattr(config, "RATE_LIMIT_PER_MINUTE", 10)
    reset_rate_limits()

    at = AppTest.from_file(APP_PATH, default_timeout=10).run()
    assert not at.exception

    at.text_area[0].set_value("http://198.51.100.42/verify")
    at.button[2].click().run()
    assert not at.exception
    assert any("Dangerous" in item.value for item in at.error)

    at.text_area[0].set_value("Urgent: share your OTP today to verify your KYC")
    at.selectbox[0].set_value("Hindi")
    at.button[2].click().run()
    assert not at.exception
    assert any("खतरनाक" in item.value for item in at.info)

    at.button[0].click().run()
    at.selectbox[0].set_value("English")
    at.button[2].click().run()
    assert not at.exception
    assert any("Low Risk" in item.value for item in at.success)

    reset_rate_limits()
