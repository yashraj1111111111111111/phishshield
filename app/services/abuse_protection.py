import hashlib
import time
from collections import defaultdict, deque

from fastapi import HTTPException

from app.config import RATE_LIMIT_PER_MINUTE
from app.database.repository import save_security_event

REQUESTS: dict[str, deque[float]] = defaultdict(deque)


def enforce_rate_limit(client_ip: str) -> None:
    now = time.monotonic()
    window = REQUESTS[client_ip]
    while window and now - window[0] > 60:
        window.popleft()
    window.append(now)
    if len(window) > RATE_LIMIT_PER_MINUTE:
        client_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:16]
        save_security_event(client_hash, "rate_limit", len(window), "blocked_for_60_seconds")
        raise HTTPException(status_code=429, detail="Too many scan requests. Please wait one minute and try again.")
