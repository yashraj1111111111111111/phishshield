import re
from urllib.parse import urlparse


def url_features(url: str) -> list[float]:
    candidate = url if "://" in url else f"https://{url}"
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname or ""
        scheme = parsed.scheme
    except ValueError:
        host = ""
        scheme = "http" if candidate.lower().startswith("http://") else "https"
    lowered = url.lower()
    terms = ["verify", "login", "secure", "account", "update", "free", "bonus"]
    return [
        len(url), host.count("."), host.count("-"), url.count("/"), url.count("%"),
        float(scheme != "https"), float(bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))),
        *[float(term in lowered) for term in terms],
    ]
