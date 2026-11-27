import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
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
    technical_details: dict[str, Any] = field(default_factory=dict)


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


def _extract_url_facts(url: str) -> dict[str, Any]:
    """Extract lexical URL facts from submitted text without any network or DNS lookup."""
    has_explicit_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url))
    candidate = url if has_explicit_scheme else f"https://{url}"

    scheme = "not specified"
    https_status = "not specified"
    if has_explicit_scheme:
        explicit_scheme = url.split("://", 1)[0].lower()
        scheme = explicit_scheme if explicit_scheme in {"http", "https"} else explicit_scheme
        https_status = "yes" if explicit_scheme == "https" else "no"

    host = ""
    path = candidate.split("?", 1)[0].split("#", 1)[0].lower()
    port: int | str = "Not specified"
    malformed = False

    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        if parsed.port is not None:
            port = parsed.port
    except ValueError:
        malformed = True
        # Best-effort lexical fallback for malformed hosts/ports without raising
        netloc = candidate.split("://", 1)[-1].split("/", 1)[0]
        port_match = re.search(r":(\d+)$", netloc)
        if port_match:
            port = int(port_match.group(1))

    is_ip = bool(host and _is_ip(host))
    if is_ip:
        host_type = "ip_address"
        tld = "Not applicable (IP address)"
        subdomain_count: int | str = 0
    elif host:
        host_type = "domain"
        parts = [p for p in host.split(".") if p]
        tld = f".{parts[-1]}" if len(parts) >= 2 else "Not specified"
        subdomain_count = max(0, len(parts) - 2)
    else:
        host_type = "not_specified"
        tld = "Not specified"
        subdomain_count = "Not specified"

    return {
        "parsed_host": host or "Not specified",
        "host_type": host_type,
        "port": port,
        "scheme": scheme,
        "https": https_status,
        "top_level_domain": tld,
        "url_length": len(url),
        "subdomain_count": subdomain_count,
        "_candidate": candidate,
        "_path": path,
        "_malformed": malformed,
        "_effective_scheme": "http" if scheme == "http" else "https",
    }


def _url_findings(url: str) -> tuple[list[tuple[str, str, int, str]], dict[str, Any]]:
    facts = _extract_url_facts(url)
    findings: list[tuple[str, str, int, str]] = []
    candidate = facts["_candidate"]
    host = "" if facts["parsed_host"] == "Not specified" else facts["parsed_host"]
    path = facts["_path"]
    full_url = candidate.lower()

    if facts["_malformed"]:
        findings.append(("url_malformed_host", "url", 15, "The link has malformed brackets or host formatting."))
    if facts["scheme"] == "http" or facts["_effective_scheme"] != "https":
        findings.append(("url_no_https", "url", 15, "The link does not use HTTPS, so its connection may not be protected."))
    if host and _is_ip(host):
        findings.append(("url_raw_ip", "url", 30, "The link uses a raw IP address instead of a normal website name."))
    if facts["port"] != "Not specified":
        findings.append(("url_explicit_port", "url", 10, f"The link specifies an explicit port (:{facts['port']}), which is uncommon for standard websites."))
    if host in SHORTENERS:
        findings.append(("url_shortener", "url", 20, "This is a shortened link, which can hide its real destination."))
    if host and any(host.endswith(tld) for tld in ABUSED_TLDS):
        findings.append(("url_abused_tld", "url", 20, "Uses a domain extension (like .xyz or .top) frequently abused by temporary scam websites."))
    if path.endswith(DANGEROUS_DOWNLOAD_EXTS):
        findings.append(("url_executable_download", "url", 45, "Links directly to a downloadable app or executable file (.apk/.exe) instead of a standard webpage."))
    if len(candidate) > 100:
        findings.append(("url_excessive_length", "url", 10, "The link is unusually long, which can be used to hide a misleading destination."))
    if "%" in candidate or "@" in candidate:
        findings.append(("url_obfuscation_chars", "url", 15, "The link contains encoded characters or an @ symbol that can obscure the true destination."))
    if host.count(".") >= 3:
        findings.append(("url_many_subdomains", "url", 10, "The link has many subdomains, a pattern often used to imitate trusted sites."))
    if host.count("-") >= 2:
        findings.append(("url_hyphen_stacking", "url", 15, "The website domain contains multiple hyphens, a common trick used to make fake links look official."))
    for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        # A brand in a non-official-looking host is only a hint, never proof.
        if brand in host and not _is_official_host(host, official_domains):
            findings.append(
                (
                    "url_brand_impersonation",
                    "url",
                    30,
                    f"Contains a well-known brand or service name ('{brand}') inside an unofficial web address to impersonate a trusted organization.",
                )
            )
            break
    word_hits = sorted(word for word in SUSPICIOUS_WORDS if word in full_url)
    if word_hits:
        findings.append(
            (
                "url_pressure_keywords",
                "url",
                min(20, 5 * len(word_hits)),
                f"The link contains pressure-related terms: {', '.join(word_hits[:4])}.",
            )
        )
    return findings, facts


def _message_findings(message: str) -> tuple[list[tuple[str, str, int, str]], dict[str, Any] | None]:
    lowered = message.lower()
    findings: list[tuple[str, str, int, str]] = []
    hits = sorted(word for word in SUSPICIOUS_WORDS if word in lowered)
    if hits:
        findings.append(
            (
                "msg_scam_keywords",
                "message",
                min(35, 6 * len(hits)),
                f"The message uses scam-associated language: {', '.join(hits[:5])}.",
            )
        )

    has_sensitive = bool(_SENSITIVE_INFO_RE.search(lowered))
    if has_sensitive:
        findings.append(("msg_sensitive_info", "message", 30, "The message asks for sensitive authentication or payment information."))

    has_urgency = bool(_URGENCY_RE.search(lowered)) or any(w in hits for w in ("blocked", "urgent", "kyc", "limited time"))
    if _URGENCY_RE.search(lowered):
        findings.append(("msg_urgency_pressure", "message", 15, "The message creates urgency, a common social-engineering tactic."))

    matched_categories: set[str] = set()
    for category, weight, pattern, reason in MESSAGE_SCAM_RULES:
        if pattern.search(lowered):
            matched_categories.add(category)
            findings.append((f"msg_{category}", "message", weight, reason))

    urls = _extract_message_urls(message)
    primary_url_facts: dict[str, Any] | None = None
    for idx, url in enumerate(urls):
        url_findings, facts = _url_findings(url)
        if idx == 0:
            primary_url_facts = facts
        findings.extend(url_findings)

    has_threat = has_urgency or ("digital_arrest" in matched_categories)
    has_action = has_sensitive or bool(urls) or bool(matched_categories & {"upi_qr", "apk_challan", "remote_access"})
    if has_threat and has_action:
        findings.append(
            (
                "combo_threat_plus_action",
                "combo",
                15,
                "Combines urgent pressure or legal threats with a request for sensitive action (OTP, PIN, app install, or link).",
            )
        )
    return findings, primary_url_facts


def _build_technical_details(
    findings: list[tuple[str, str, int, str]],
    url_facts: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build structured text-only technical details from parsed URL facts and triggered rules."""
    url_indicators = [reason for _, cat, _, reason in findings if cat == "url"]
    message_indicators = [reason for _, cat, _, reason in findings if cat in {"message", "combo"}]
    triggered_rules = [
        {"rule_id": rule_id, "category": category, "score": weight, "reason": reason}
        for rule_id, category, weight, reason in findings
    ]
    base: dict[str, Any] = {
        "parsed_host": url_facts["parsed_host"] if url_facts else "Not applicable (message without URL)",
        "host_type": url_facts["host_type"] if url_facts else "not_applicable",
        "port": url_facts["port"] if url_facts else "Not specified",
        "scheme": url_facts["scheme"] if url_facts else "not specified",
        "https": url_facts["https"] if url_facts else "not specified",
        "top_level_domain": url_facts["top_level_domain"] if url_facts else "Not applicable",
        "url_length": url_facts["url_length"] if url_facts else None,
        "subdomain_count": url_facts["subdomain_count"] if url_facts else None,
        "detected_url_indicators": url_indicators,
        "detected_message_indicators": message_indicators,
        "triggered_rules": triggered_rules,
    }
    return base


def scan(content: str) -> ScanResult:
    content = content.strip()
    looks_like_url = bool(re.fullmatch(r"(?:https?://)?[^\s/]+(?:/[^\s]*)?", content)) and " " not in content
    if looks_like_url:
        findings, url_facts = _url_findings(content)
    else:
        findings, url_facts = _message_findings(content)

    score = min(100, sum(weight for _, _, weight, _ in findings))
    if score >= 60:
        level = "Dangerous"
    elif score >= 25:
        level = "Suspicious"
    else:
        level = "Low Risk"
    reasons = [reason for _, _, _, reason in findings] or [
        "No common phishing indicators were found in the text, though the destination itself is unverified and not guaranteed to be safe."
    ]
    technical_details = _build_technical_details(findings, url_facts)
    return ScanResult(
        score=score,
        level=level,
        reasons=reasons,
        content_type="url" if looks_like_url else "message",
        technical_details=technical_details,
    )
