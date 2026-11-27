"""Detect repeated-domain and similar-message campaign bursts from recent salted fingerprints."""
from __future__ import annotations

from app.database.repository import fetch_recent_fingerprints, save_security_event
from app.services.abuse_protection import hash_client_ip
from app.services.fingerprints import (
    build_scan_fingerprints,
    extract_hosts,
    fingerprints_similar,
    salted_hash,
)


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

    recent = fetch_recent_fingerprints(window_minutes=window_minutes)
    findings: list[str] = []
    client_hash = hash_client_ip(client_ip)
    current_fp = build_scan_fingerprints(content, content_type)

    current_hosts = extract_hosts(content, content_type)
    if current_hosts:
        max_domain_count = 1
        matched_host = ""
        for host in sorted(current_hosts):
            host_hash = salted_hash("domain", host)
            count = 1 + sum(1 for item in recent if host_hash in item["domain_hashes"])
            if count > max_domain_count:
                max_domain_count = count
                matched_host = host
        if max_domain_count >= threshold:
            save_security_event(client_hash, "campaign_domain", max_domain_count, "flagged_campaign_pattern")
            findings.append(
                f"Campaign pattern detected: '{matched_host}' appeared in {max_domain_count} recent scans."
            )

    if content_type == "message" and (current_fp.message_hash or current_fp.shingle_hashes):
        similar_count = 1 + sum(
            1
            for item in recent
            if item["content_type"] == "message"
            and fingerprints_similar(
                current_fp.message_hash,
                current_fp.shingle_hashes,
                item["message_hash"],
                item["shingle_hashes"],
            )
        )
        if similar_count >= threshold:
            save_security_event(client_hash, "campaign_message", similar_count, "flagged_campaign_pattern")
            findings.append(
                f"Campaign pattern detected: a similar suspicious message appeared {similar_count} times recently."
            )

    return findings
