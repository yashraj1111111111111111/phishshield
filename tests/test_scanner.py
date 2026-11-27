from app.detectors.scanner import scan


def test_raw_ip_http_link_is_dangerous():
    result = scan("http://198.51.100.42/verify")
    assert result.level == "Dangerous"
    assert result.score >= 60


def test_benign_reserved_domain_has_low_risk():
    result = scan("https://www.example.com")
    assert result.level == "Safe"


def test_otp_message_is_flagged():
    result = scan("Urgent: share your OTP today to verify your KYC")
    assert result.level == "Dangerous"
