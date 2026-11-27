"""Privacy-preserving salted fingerprints for campaign detection without raw text storage."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from app import config

URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s]+", flags=re.IGNORECASE)
SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
MIN_MESSAGE_LENGTH = 12
SHINGLE_SIZE = 4
MAX_SHINGLES = 64
SIMILARITY_THRESHOLD = 0.70


@dataclass(frozen=True)
class ScanFingerprints:
    domain_hashes: list[str]
    message_hash: str | None
    shingle_hashes: list[str]


def salted_hash(namespace: str, value: str, length: int = 16) -> str:
    """Return a truncated salted SHA-256 digest scoped to a namespace."""
    payload = f"{config.IP_HASH_SALT}:{namespace}:{value}".encode()
    return hashlib.sha256(payload).hexdigest()[:length]


def extract_hosts(content: str, content_type: str) -> set[str]:
    """Extract normalized lowercase hostnames from a URL or embedded links in text."""
    candidates = [content.strip()] if content_type == "url" else URL_PATTERN.findall(content)
    hosts: set[str] = set()
    for raw in candidates:
        candidate = raw if SCHEME_PATTERN.match(raw) else f"https://{raw}"
        try:
            host = (urlparse(candidate).hostname or "").lower()
        except ValueError:
            continue
        if host:
            hosts.add(host)
    return hosts


def normalize_message(message: str) -> str:
    """Mask URLs and numbers so template variants cluster together."""
    without_urls = URL_PATTERN.sub("<url>", message.lower())
    without_numbers = re.sub(r"\b\d+\b", "<num>", without_urls)
    return " ".join(without_numbers.split())


def _shingle_hashes(normalized: str) -> list[str]:
    if len(normalized) < MIN_MESSAGE_LENGTH:
        return []
    if len(normalized) <= SHINGLE_SIZE:
        return [salted_hash("shingle", normalized, length=12)]
    digests = {
        salted_hash("shingle", normalized[idx : idx + SHINGLE_SIZE], length=12)
        for idx in range(len(normalized) - SHINGLE_SIZE + 1)
    }
    return sorted(digests)[:MAX_SHINGLES]


def build_scan_fingerprints(content: str, content_type: str) -> ScanFingerprints:
    """Compute non-reversible salted hashes for hosts and message templates."""
    domain_hashes = sorted(salted_hash("domain", host) for host in extract_hosts(content, content_type))
    if content_type != "message":
        return ScanFingerprints(domain_hashes=domain_hashes, message_hash=None, shingle_hashes=[])

    normalized = normalize_message(content)
    if len(normalized) < MIN_MESSAGE_LENGTH:
        return ScanFingerprints(domain_hashes=domain_hashes, message_hash=None, shingle_hashes=[])

    return ScanFingerprints(
        domain_hashes=domain_hashes,
        message_hash=salted_hash("message", normalized),
        shingle_hashes=_shingle_hashes(normalized),
    )


def fingerprints_similar(
    current_message_hash: str | None,
    current_shingles: list[str],
    stored_message_hash: str | None,
    stored_shingles: list[str],
) -> bool:
    """Return True when two salted message fingerprints represent the same or similar template."""
    if current_message_hash and stored_message_hash and current_message_hash == stored_message_hash:
        return True
    if not current_shingles or not stored_shingles:
        return False
    cur_set = set(current_shingles)
    stored_set = set(stored_shingles)
    dice = (2 * len(cur_set & stored_set)) / (len(cur_set) + len(stored_set))
    return dice >= SIMILARITY_THRESHOLD
