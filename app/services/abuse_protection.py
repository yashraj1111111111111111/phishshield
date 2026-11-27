import hashlib
import time
from collections import defaultdict, deque

from fastapi import HTTPException

from app import config
from app.database.repository import save_security_event

REQUESTS: dict[str, deque[float]] = defaultdict(deque)


def hash_client_ip(client_ip: str) -> str:
    """Return a short salted SHA-256 hash of the client IP for privacy-preserving logs."""
    salted = f"{config.IP_HASH_SALT}:{client_ip}".encode()
    return hashlib.sha256(salted).hexdigest()[:16]


def reset_rate_limits() -> None:
    """Clear in-memory rate-limit windows (intended for tests)."""
    REQUESTS.clear()


def enforce_rate_limit(client_ip: str) -> None:
    now = time.monotonic()
    window = REQUESTS[client_ip]
    while window and now - window[0] > 60:
        window.popleft()
    window.append(now)
    if len(window) > config.RATE_LIMIT_PER_MINUTE:
        client_hash = hash_client_ip(client_ip)
        save_security_event(client_hash, "rate_limit", len(window), "blocked_for_60_seconds")
        raise HTTPException(status_code=429, detail="Too many scan requests. Please wait one minute and try again.")
