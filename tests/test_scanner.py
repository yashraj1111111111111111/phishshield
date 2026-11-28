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


def test_low_risk_wording_makes_no_safe_or_authentic_claim():
    result = scan("https://www.example.com")
    assert result.score == 0
    assert result.level == "Low Risk"
    joined = " ".join(result.reasons).lower()
    assert "unverified" in joined
    assert "not guaranteed to be safe" in joined
    assert "authentic" not in joined


def test_url_with_explicit_port_technical_details():
    result = scan("http://198.51.100.42:8080/login")
    td = result.technical_details
    assert td["parsed_host"] == "198.51.100.42"
    assert td["host_type"] == "ip_address"
    assert td["port"] == 8080
    assert td["scheme"] == "http"
    assert td["https"] == "no"
    rule_ids = {r["rule_id"] for r in td["triggered_rules"]}
    assert {"url_raw_ip", "url_no_https", "url_explicit_port"}.issubset(rule_ids)


def test_url_without_explicit_port_reports_not_specified():
    result = scan("https://www.example.com/path")
    td = result.technical_details
    assert td["port"] == "Not specified"
    assert td["scheme"] == "https"
    assert td["https"] == "yes"


def test_domain_url_technical_details():
    result = scan("https://login.verify.paypal-secure.example/auth")
    td = result.technical_details
    assert td["parsed_host"] == "login.verify.paypal-secure.example"
    assert td["host_type"] == "domain"
    assert td["top_level_domain"] == ".example"
    assert td["subdomain_count"] == 2
    assert td["url_length"] == len("https://login.verify.paypal-secure.example/auth")
    assert len(td["detected_url_indicators"]) > 0


def test_message_with_multiple_scam_categories_technical_details():
    msg = (
        "CBI Cyber Crime digital arrest notice: download challan.apk and install AnyDesk "
        "or enter UPI PIN immediately at http://198.51.100.42:8080/pay"
    )
    result = scan(msg)
    td = result.technical_details
    assert result.content_type == "message"
    assert result.level == "Dangerous"
    assert td["parsed_host"] == "198.51.100.42"
    assert td["port"] == 8080
    assert len(td["detected_message_indicators"]) >= 4
    assert len(td["detected_url_indicators"]) >= 3
    rule_ids = {r["rule_id"] for r in td["triggered_rules"]}
    assert {"msg_digital_arrest", "msg_apk_challan", "msg_remote_access", "msg_upi_qr", "combo_threat_plus_action"}.issubset(rule_ids)


def test_homograph_and_punycode_spoof_detection():
    # Cyrillic 'р' (\u0440) + Latin 'aypal.com'
    cyrillic_paypal = scan("https://\u0440aypal.com/login")
    assert cyrillic_paypal.score >= 35
    assert cyrillic_paypal.level in {"Suspicious", "Dangerous"}
    rule_ids = {r["rule_id"] for r in cyrillic_paypal.technical_details["triggered_rules"]}
    assert "url_homograph_spoof" in rule_ids

    puny = scan("https://xn--pypal-4ve.com/login")
    puny_rules = {r["rule_id"] for r in puny.technical_details["triggered_rules"]}
    assert "url_punycode" in puny_rules


def test_zero_width_obfuscation_and_defanged_url_and_matched_terms():
    zws = scan("Enter U\u200bPI PIN to receive money at http://198.51.100.42:8080/login")
    rule_ids = {r["rule_id"] for r in zws.technical_details["triggered_rules"]}
    assert "msg_zero_width_obfuscation" in rule_ids
    assert zws.technical_details["defanged_url"] == "hxxp://198[.]51[.]100[.]42:8080/login"
    assert "198.51.100.42" in zws.matched_terms


def test_upi_intent_deep_inspector():
    upi = scan("upi://pay?pa=cashback-desk@okaxis&pn=ElectricityRefund&am=2500&tn=Claim%20Cashback%20Refund")
    td = upi.technical_details
    assert td["upi_details"]["pa"] == "cashback-desk@okaxis"
    assert td["upi_details"]["am"] == "2500"
    rule_ids = {r["rule_id"] for r in td["triggered_rules"]}
    assert {"upi_collect_trap", "upi_vpa_mismatch"}.issubset(rule_ids)
    assert upi.score >= 60
    assert upi.level == "Dangerous"


def test_email_header_spoof_analyzer():
    eml = (
        "From: security@hdfcbank.com\n"
        "Reply-To: helpdesk@hdfc-verify.xyz\n"
        "Return-Path: bounce@mail-alert.top\n"
        "Authentication-Results: spf=fail dmarc=fail\n"
        "Urgent: Update your KYC immediately."
    )
    res = scan(eml)
    eh = res.technical_details["email_headers"]
    assert eh["from_domain"] == "hdfcbank.com"
    assert eh["reply_to_domain"] == "hdfc-verify.xyz"
    assert eh["return_path_domain"] == "mail-alert.top"
    assert "SPF=fail" in eh["auth_failures"]
    rule_ids = {r["rule_id"] for r in res.technical_details["triggered_rules"]}
    assert {"email_reply_to_mismatch", "email_return_path_mismatch", "email_auth_fail"}.issubset(rule_ids)
    assert res.level == "Dangerous"
