#!/usr/bin/env python3
"""End-to-end verification script for PhishShield FastAPI backend."""

import json
import sys
import time
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8001"


def send_request(path, payload=None, method="POST", client_ip="127.0.0.1"):
    url = f"{BASE_URL}{path}"
    headers = {
        "Content-Type": "application/json",
        "X-Forwarded-For": client_ip,
    }
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, {"detail": body}
    except urllib.error.URLError as e:
        print(f"[FATAL] Could not connect to {BASE_URL}: {e.reason}")
        print("Make sure FastAPI is running on port 8001.")
        sys.exit(1)


def run_suite():
    passed = 0
    failed = 0

    def check(condition, label, details=""):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  [PASS] {label}")
        else:
            failed += 1
            print(f"  [FAIL] {label} -> {details}")

    # 1. Health Check
    print("\n=== 1. Health Check ===")
    status, data = send_request("/health", method="GET")
    check(status == 200 and data.get("status") == "ok", "GET /health returns ok", data)

    # 2. Tier & Content Probes (using distinct X-Forwarded-For IPs to avoid 429)
    print("\n=== 2. Risk Tier, SMS Scam & Localization Probes ===")
    probes = [
        # (Label, content, lang, expected_levels, expected_type, test_ip)
        (
            "Low Risk: Deep path without www",
            "https://example.com/tools/random-url-generator/",
            "en",
            {"Low Risk"},
            "url",
            "10.0.1.1",
        ),
        (
            "Low Risk: Clean university subdomain",
            "https://library.example.edu/courses/2026",
            "en",
            {"Low Risk"},
            "url",
            "10.0.1.2",
        ),
        (
            "Suspicious: Plain HTTP + verify/payment",
            "http://portal.example.com/verify/payment",
            "en",
            {"Suspicious", "Dangerous"},
            "url",
            "10.0.1.3",
        ),
        (
            "Suspicious: URL shortener + HTTP + verify",
            "http://bit.ly/verify",
            "en",
            {"Suspicious", "Dangerous"},
            "url",
            "10.0.1.4",
        ),
        (
            "Dangerous: Raw IPv4 + HTTP + SBI + verify/login",
            "http://192.0.2.42/sbi/verify/login",
            "en",
            {"Dangerous"},
            "url",
            "10.0.1.5",
        ),
        (
            "Dangerous: @ credential mask + brand + %20",
            "http://user@paypal-login.example/verify%20account",
            "en",
            {"Dangerous"},
            "url",
            "10.0.1.6",
        ),
        (
            "SMS Scam (English): SBI YONO KYC + OTP",
            "URGENT: Your SBI YONO account will be blocked today! Update your PAN and verify OTP immediately at http://198.51.100.42/login to avoid suspension.",
            "en",
            {"Suspicious", "Dangerous"},
            "message",
            "10.0.1.7",
        ),
        (
            "SMS Scam (Hindi): UPI PIN + Bonus",
            "Congratulations! You won a Rs 15,000 cashback bonus. Share your UPI PIN or claim free reward now: http://198.51.100.42/claim",
            "hi",
            {"Suspicious", "Dangerous"},
            "message",
            "10.0.1.8",
        ),
    ]

    for label, content, lang, expected_levels, expected_type, ip in probes:
        status, data = send_request(
            "/api/scan", {"content": content, "language": lang}, client_ip=ip
        )
        ok = (
            status == 200
            and data.get("risk_level") in expected_levels
            and data.get("content_type") == expected_type
            and bool(data.get("explanation"))
            and data.get("ml_probability") is not None
        )
        summary = (
            f"status={status}, score={data.get('risk_score')}, "
            f"level={data.get('risk_level')}, ml={data.get('ml_probability')}"
        )
        check(ok, f"{label} ({summary})", data)

    # 3. Edge Cases (Punycode & Malformed IPv6 ValueError guard)
    print("\n=== 3. Edge Cases (Punycode & Malformed IPv6) ===")
    status, data = send_request(
        "/api/scan",
        {"content": "http://xn--paypal-x.example/verify", "language": "en"},
        client_ip="10.0.2.1",
    )
    check(
        status == 200 and data.get("risk_score", 0) >= 25,
        f"Punycode IDN handled cleanly (score={data.get('risk_score')})",
        data,
    )

    status, data = send_request(
        "/api/scan",
        {"content": "http://[invalid-ipv6/login", "language": "en"},
        client_ip="10.0.2.2",
    )
    check(
        status == 200,
        f"Malformed IPv6 ValueError guard prevents 500 error (score={data.get('risk_score')})",
        data,
    )

    # 4. Campaign Detector (>= 3 scans of same domain with score >= 25 in 15 mins)
    print("\n=== 4. Campaign Detector (3 Repeated Domain Scans) ===")
    unique_campaign_domain = f"kyc-alert-{int(time.time())}.example.org"
    campaign_flags = []
    for i in range(1, 4):
        status, data = send_request(
            "/api/scan",
            {
                "content": f"http://{unique_campaign_domain}/verify?id={i}",
                "language": "en",
            },
            client_ip="10.0.3.1",
        )
        campaign_flags.append((status, data.get("campaign_detected")))
    check(
        campaign_flags[-1] == (200, True),
        f"3rd scan triggers campaign_detected=True ({campaign_flags})",
        campaign_flags,
    )

    # 5. Rate Limiter (11 rapid requests from same IP -> 429)
    print("\n=== 5. Rate Limiter (HTTP 429 on 11th Request) ===")
    statuses = []
    for _ in range(11):
        status, _ = send_request(
            "/api/scan",
            {"content": "https://example.com", "language": "en"},
            client_ip="10.0.9.99",
        )
        statuses.append(status)
    check(
        statuses[:10] == [200] * 10 and statuses[10] == 429,
        f"First 10 succeed (200), 11th returns 429 ({statuses})",
        statuses,
    )

    print(f"\nSummary: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    run_suite()
