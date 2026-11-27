import json
from datetime import datetime, timezone

from app.database.connection import get_connection


def save_scan(content: str, content_type: str, score: int, level: str, reasons: list[str], language: str, ml_probability: float | None = None) -> str:
    with get_connection() as connection:
        cursor = connection.execute(
            """INSERT INTO scans (submitted_content, content_type, risk_score, risk_level, reasons_json, language, ml_probability)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (content, content_type, score, level, json.dumps(reasons), language, ml_probability),
        )
        # YYMMDD + six-digit SQLite sequence = a compact, human-readable 12-digit reference.
        reference = f"{datetime.now(timezone.utc):%y%m%d}{cursor.lastrowid:06d}"
        connection.execute("UPDATE scans SET scan_reference = ? WHERE id = ?", (reference, cursor.lastrowid))
    return reference


def save_security_event(client_hash: str, event_type: str, request_count: int, action_taken: str) -> None:
    with get_connection() as connection:
        connection.execute(
            """INSERT INTO security_events (client_hash, event_type, request_count, window_start, action_taken)
               VALUES (?, ?, ?, ?, ?)""",
            (client_hash, event_type, request_count, datetime.now(timezone.utc).isoformat(), action_taken),
        )
