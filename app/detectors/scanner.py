import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

SUSPICIOUS_WORDS = {
    "verify",
    "urgent",
    "kyc",
    "otp",
    "reward",
    "claim",
    "prize",
    "blocked",
    "password",
    "payment",
    "parcel",
    "click here",
    "limited time",
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "shorturl.at"}
ABUSED_TLDS = (".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".loan", ".vip", ".icu", ".buzz")
DANGEROUS_DOWNLOAD_EXTS = (".apk", ".exe", ".zip", ".scr", ".bat")

BRAND_OFFICIAL_DOMAINS: dict[str, tuple[str, ...]] = {
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk"),
    "google": ("google.com", "google.co.in", "accounts.google.com", "pay.google.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com"),
    "paypal": ("paypal.com",),
    "netflix": ("netflix.com",),
    "apple": ("apple.com", "icloud.com"),
    "instagram": ("instagram.com",),
    "facebook": ("facebook.com", "fb.com"),
    "whatsapp": ("whatsapp.com",),
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"),
    "hdfc": ("hdfcbank.com", "hdfc.com"),
    "icici": ("icicibank.com", "icici.com"),
    "axis": ("axisbank.com", "axisbank.co.in"),
    "paytm": ("paytm.com",),
    "phonepe": ("phonepe.com",),
    "gpay": ("pay.google.com",),
    "flipkart": ("flipkart.com",),
    "irctc": ("irctc.co.in", "irctc.com"),
    "epfo": ("epfindia.gov.in",),
    "uidai": ("uidai.gov.in",),
    "aadhaar": ("uidai.gov.in",),
}

MESSAGE_SCAM_RULES: list[tuple[str, int, re.Pattern[str], str]] = [
    (
        "digital_arrest",
        35,
        re.compile(
            r"\b(?:cbi|cyber\s*crime|cyber\s*police|arrest\s*warrant|digital\s*arrest|"
            r"parcel\s*seized|customs\s*department|narcotics|money\s*laundering|"
            r"legal\s*action|court\s*notice|trai|sim\s*disconnected)\b",
            flags=re.IGNORECASE,
        ),
        "Impersonates police, customs, or government authorities to create fear and pressure you into paying.",
    ),
    (
        "upi_qr",
        35,
        re.compile(
            r"\b(?:upi\s*pin|enter\s*pin|scan\s*qr|receive\s*money|claim\s*cashback|"
            r"collect\s*request|refund\s*approved|payment\s*request|paytm\s*cashback|"
            r"gpay\s*reward|phonepe\s*reward)\b",
            flags=re.IGNORECASE,
        ),
        "Tries to trick you into entering your UPI PIN or scanning a QR code. You never need a PIN or QR scan to receive money.",
    ),
    (
        "apk_challan",
        40,
        re.compile(
            r"(?:\.apk\b|\b(?:install\s*app|download\s*app|e-?challan|traffic\s*challan|"
            r"rto|pm\s*kisan|apk\s*file|update\s*app\s*via\s*link)\b)",
            flags=re.IGNORECASE,
        ),
        "Mentions downloading an app or .APK file outside official app stores, which can install spyware and steal your OTPs.",
    ),
    (
        "remote_access",
        35,
        re.compile(
            r"\b(?:anydesk|teamviewer|quicksupport|rustdesk|screen\s*share|share\s*screen|"
            r"remote\s*access|support\s*code)\b",
            flags=re.IGNORECASE,
        ),
        "Asks you to share your screen or install a remote-access app, which allows scammers to watch your screen and steal bank details.",
    ),
]

_URGENCY_RE = re.compile(r"\b(today|immediately|within \d+ hours?|last chance)\b", flags=re.IGNORECASE)
_SENSITIVE_INFO_RE = re.compile(r"\b(otp|cvv|pin|password)\b", flags=re.IGNORECASE)
_BARE_DOMAIN_TLDS = "|".join(tld.lstrip(".") for tld in ABUSED_TLDS) + "|com|in|org|net|co\\.in"
_MESSAGE_URL_RE = re.compile(
    rf"(?:(?:https?://|www\.)[^\s]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:{_BARE_DOMAIN_TLDS})(?:/[^\s]*)?)",
    flags=re.IGNORECASE,
)


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


def _is_official_host(host: str, official_domains: tuple[str, ...]) -> bool:
    """Return True if host matches an official domain or one of its subdomains."""
    return any(host == domain or host.endswith(f".{domain}") for domain in official_domains)


def _extract_message_urls(message: str) -> list[str]:
    """Extract explicit URLs and bare suspicious-TLD domains from message text."""
    return [match.group(0).rstrip(".,;:!?)") for match in _MESSAGE_URL_RE.finditer(message)]


def _url_reasons(url: str) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    candidate = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else f"https://{url}"
    try:
        parsed = urlparse(candidate)
        scheme = parsed.scheme
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
    except ValueError:
        scheme = "http" if candidate.lower().startswith("http://") else "https"
        host = ""
        path = candidate.split("?", 1)[0].split("#", 1)[0].lower()
        findings.append((15, "The link has malformed brackets or host formatting."))
    full_url = candidate.lower()

    if scheme != "https":
        findings.append((15, "The link does not use HTTPS, so its connection may not be protected."))
    if host and _is_ip(host):
        findings.append((30, "The link uses a raw IP address instead of a normal website name."))
    if host in SHORTENERS:
        findings.append((20, "This is a shortened link, which can hide its real destination."))
    if host and any(host.endswith(tld) for tld in ABUSED_TLDS):
        findings.append((20, "Uses a domain extension (like .xyz or .top) frequently abused by temporary scam websites."))
    if path.endswith(DANGEROUS_DOWNLOAD_EXTS):
        findings.append((45, "Links directly to a downloadable app or executable file (.apk/.exe) instead of a standard webpage."))
    if len(candidate) > 100:
        findings.append((10, "The link is unusually long, which can be used to hide a misleading destination."))
    if "%" in candidate or "@" in candidate:
        findings.append((15, "The link contains encoded characters or an @ symbol that can obscure the true destination."))
    if host.count(".") >= 3:
        findings.append((10, "The link has many subdomains, a pattern often used to imitate trusted sites."))
    if host.count("-") >= 2:
        findings.append((15, "The website domain contains multiple hyphens, a common trick used to make fake links look official."))
    for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        # A brand in a non-official-looking host is only a hint, never proof.
        if brand in host and not _is_official_host(host, official_domains):
            findings.append(
                (
                    30,
                    f"Contains a well-known brand or service name ('{brand}') inside an unofficial web address to impersonate a trusted organization.",
                )
            )
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

    has_sensitive = bool(_SENSITIVE_INFO_RE.search(lowered))
    if has_sensitive:
        findings.append((30, "The message asks for sensitive authentication or payment information."))

    has_urgency = bool(_URGENCY_RE.search(lowered)) or any(w in hits for w in ("blocked", "urgent", "kyc", "limited time"))
    if _URGENCY_RE.search(lowered):
        findings.append((15, "The message creates urgency, a common social-engineering tactic."))

    matched_categories: set[str] = set()
    for category, weight, pattern, reason in MESSAGE_SCAM_RULES:
        if pattern.search(lowered):
            matched_categories.add(category)
            findings.append((weight, reason))

    urls = _extract_message_urls(message)
    for url in urls:
        findings.extend(_url_reasons(url))

    has_threat = has_urgency or ("digital_arrest" in matched_categories)
    has_action = has_sensitive or bool(urls) or bool(matched_categories & {"upi_qr", "apk_challan", "remote_access"})
    if has_threat and has_action:
        findings.append(
            (15, "Combines urgent pressure or legal threats with a request for sensitive action (OTP, PIN, app install, or link).")
        )
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
