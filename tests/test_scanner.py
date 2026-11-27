from app.detectors.scanner import scan


def test_raw_ip_http_link_is_dangerous():
    result = scan("http://198.51.100.42/verify")
    assert result.level == "Dangerous"
    assert result.score >= 60


def test_benign_reserved_domain_has_low_risk():
    result = scan("https://www.example.com")
    assert result.level == "Low Risk"


def test_otp_message_is_flagged():
    result = scan("Urgent: share your OTP today to verify your KYC")
    assert result.level == "Dangerous"


def test_malformed_ipv6_url_does_not_crash():
    result = scan("http://[invalid-ipv6/login")
    assert result.content_type == "url"
    assert result.score >= 25


def test_digital_arrest_scam_is_dangerous():
    msg = (
        "Urgent notice from CBI Cyber Crime: Your parcel has been seized by customs. "
        "Join video call immediately or face arrest warrant."
    )
    result = scan(msg)
    assert result.level == "Dangerous"
    assert result.score >= 60


def test_upi_qr_trick_is_dangerous():
    msg = "Congratulations! Your cashback of Rs 4999 is approved. Scan QR code and enter UPI PIN to receive money."
    result = scan(msg)
    assert result.level == "Dangerous"
    assert result.score >= 60


def test_apk_challan_scam_is_dangerous():
    msg = "Pending traffic e-challan of Rs 2000. Download RTO challan.apk to pay now: rto-challan-pay.xyz"
    result = scan(msg)
    assert result.level == "Dangerous"
    assert result.score >= 60


def test_remote_access_scam_is_flagged():
    msg = "Install AnyDesk and share support code immediately so your blocked bank account can be verified."
    result = scan(msg)
    assert result.level == "Dangerous"
    assert result.score >= 60


def test_url_abused_tld_direct_apk_and_hyphen_stacking():
    apk_url = scan("https://rto-challan-pay.xyz/downloads/challan.apk")
    assert apk_url.content_type == "url"
    assert apk_url.level == "Dangerous"
    assert apk_url.score >= 60

    lookalike = scan("https://sbi-kyc-update.com/login")
    assert lookalike.level in {"Suspicious", "Dangerous"}
    assert lookalike.score >= 45


def test_official_indian_domains_not_flagged_as_lookalikes():
    for official in [
        "https://www.sbi.co.in",
        "https://retail.onlinesbi.sbi",
        "https://www.hdfcbank.com",
        "https://www.icicibank.com",
        "https://www.irctc.co.in",
        "https://uidai.gov.in",
        "https://www.epfindia.gov.in",
    ]:
        result = scan(official)
        assert result.level == "Low Risk", f"Unexpectedly flagged official domain {official}: {result.reasons}"


def test_word_boundaries_prevent_acronym_false_positives():
    benign = scan("Our portrait photography training workshop starts at 10am.")
    assert benign.level == "Low Risk"
    assert benign.score == 0
