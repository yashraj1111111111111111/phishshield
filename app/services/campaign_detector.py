"""Detect repeated-domain and similar-message campaign bursts from recent scans."""
from __future__ import annotations

import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

from app.database.repository import fetch_recent_scans, save_security_event
from app.services.abuse_protection import hash_client_ip

URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s]+", flags=re.IGNORECASE)
SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _extract_hosts(content: str, content_type: str) -> set[str]:
    candidates = [content.strip()] if content_type == "url" else URL_PATTERN.findall(content)
    hosts: set[str] = set()
    for raw in candidates:
        candidate = raw if SCHEME_PATTERN.match(raw) else f"https://{raw}"
        host = (urlparse(candidate).hostname or "").lower()
        if host:
            hosts.add(host)
    return hosts


def _normalize_message(message: str) -> str:
    without_urls = URL_PATTERN.sub("<url>", message.lower())
    without_numbers = re.sub(r"\b\d+\b", "<num>", without_urls)
    return " ".join(without_numbers.split())


def detect_campaign(
    content: str,
    content_type: str,
    risk_score: int,
    client_ip: str,
    window_minutes: int = 15,
    threshold: int = 3,
) -> list[str]:
    """Flag repeated domains or similar suspicious messages seen recently."""
    if risk_score < 25:
        return []

    recent = fetch_recent_scans(window_minutes=window_minutes)
    findings: list[str] = []
    client_hash = hash_client_ip(client_ip)

    current_hosts = _extract_hosts(content, content_type)
    if current_hosts:
        max_domain_count = 1
        matched_host = ""
        for host in sorted(current_hosts):
            count = 1 + sum(1 for r_type, r_content in recent if host in _extract_hosts(r_content, r_type))
            if count > max_domain_count:
                max_domain_count = count
                matched_host = host
        if max_domain_count >= threshold:
            save_security_event(client_hash, "campaign_domain", max_domain_count, "flagged_campaign_pattern")
            findings.append(
                f"Campaign pattern detected: '{matched_host}' appeared in {max_domain_count} recent scans."
            )

    if content_type == "message":
        norm_current = _normalize_message(content)
        if len(norm_current) >= 12:
            similar_count = 1 + sum(
                1
                for r_type, r_content in recent
                if r_type == "message"
                and SequenceMatcher(None, norm_current, _normalize_message(r_content)).ratio() >= 0.8
            )
            if similar_count >= threshold:
                save_security_event(client_hash, "campaign_message", similar_count, "flagged_campaign_pattern")
                findings.append(
                    f"Campaign pattern detected: a similar suspicious message appeared {similar_count} times recently."
                )

    return findings
