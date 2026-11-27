import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

SUSPICIOUS_WORDS = {"verify", "urgent", "kyc", "otp", "reward", "claim", "prize", "blocked", "password", "payment", "parcel", "click here", "limited time"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "shorturl.at"}
BRANDS = {"amazon", "google", "microsoft", "paypal", "netflix", "apple", "instagram", "facebook", "whatsapp", "sbi", "hdfc", "icici"}


@dataclass
class ScanResult:
    score: int
    level: str
    reasons: list[str]
    content_type: str


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _url_reasons(url: str) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    candidate = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else f"https://{url}"
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    full_url = candidate.lower()

    if parsed.scheme != "https":
        findings.append((15, "The link does not use HTTPS, so its connection may not be protected."))
    if host and _is_ip(host):
        findings.append((30, "The link uses a raw IP address instead of a normal website name."))
    if host in SHORTENERS:
        findings.append((20, "This is a shortened link, which can hide its real destination."))
    if len(candidate) > 100:
        findings.append((10, "The link is unusually long, which can be used to hide a misleading destination."))
    if "%" in candidate or "@" in candidate:
        findings.append((15, "The link contains encoded characters or an @ symbol that can obscure the true destination."))
    if host.count(".") >= 3:
        findings.append((10, "The link has many subdomains, a pattern often used to imitate trusted sites."))
    if host.count("-") >= 2:
        findings.append((8, "The domain has multiple hyphens, which is common in imitation domains."))
    for brand in BRANDS:
        # A brand in a non-official-looking host is only a hint, never proof.
        if brand in host and not (host == f"{brand}.com" or host.endswith(f".{brand}.com")):
            findings.append((25, f"The domain mentions '{brand}' but does not look like its official domain."))
            break
    word_hits = sorted(word for word in SUSPICIOUS_WORDS if word in full_url)
    if word_hits:
        findings.append((min(20, 5 * len(word_hits)), f"The link contains pressure-related terms: {', '.join(word_hits[:4])}."))
    return findings


def _message_reasons(message: str) -> list[tuple[int, str]]:
    lowered = message.lower()
    findings: list[tuple[int, str]] = []
    hits = sorted(word for word in SUSPICIOUS_WORDS if word in lowered)
    if hits:
        findings.append((min(35, 6 * len(hits)), f"The message uses scam-associated language: {', '.join(hits[:5])}."))
    if re.search(r"\b(otp|cvv|pin|password)\b", lowered):
        findings.append((30, "The message asks for sensitive authentication or payment information."))
    if re.search(r"\b(today|immediately|within \d+ hours?|last chance)\b", lowered):
        findings.append((15, "The message creates urgency, a common social-engineering tactic."))
    for url in re.findall(r"(?:https?://|www\.)[^\s]+", message, flags=re.IGNORECASE):
        findings.extend(_url_reasons(url))
    return findings


def scan(content: str) -> ScanResult:
    content = content.strip()
    looks_like_url = bool(re.fullmatch(r"(?:https?://)?[^\s/]+(?:/[^\s]*)?", content)) and " " not in content
    findings = _url_reasons(content) if looks_like_url else _message_reasons(content)
    score = min(100, sum(weight for weight, _ in findings))
    if score >= 60:
        level = "Dangerous"
    elif score >= 25:
        level = "Suspicious"
    else:
        level = "Low Risk"
    reasons = [reason for _, reason in findings] or [
        "No common phishing indicators were found in the text, though the destination itself is unverified and not guaranteed to be safe."
    ]
    return ScanResult(score=score, level=level, reasons=reasons, content_type="url" if looks_like_url else "message")
