import json
import sqlite3
from datetime import datetime, timezone

from app import config
from app.database.connection import get_connection
from app.services.fingerprints import build_scan_fingerprints

REDACTED_CONTENT = "[redacted]"


def purge_expired_records(connection: sqlite3.Connection, retention_days: int) -> None:
    """Delete scans, fingerprints, and security events older than retention_days."""
    if retention_days <= 0:
        return
    modifier = f"-{int(retention_days)} days"
    for table in ("scan_fingerprints", "scans", "security_events"):
        connection.execute(f"DELETE FROM {table} WHERE created_at < datetime('now', ?)", (modifier,))


def save_scan(content: str, content_type: str, score: int, level: str, reasons: list[str], language: str, ml_probability: float | None = None) -> str:
    persisted_content = content if config.STORE_SCAN_CONTENT else REDACTED_CONTENT
    fingerprints = build_scan_fingerprints(content, content_type)
    with get_connection() as connection:
        purge_expired_records(connection, config.SCAN_RETENTION_DAYS)
        cursor = connection.execute(
            """INSERT INTO scans (submitted_content, content_type, risk_score, risk_level, reasons_json, language, ml_probability)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (persisted_content, content_type, score, level, json.dumps(reasons), language, ml_probability),
        )
        # YYMMDD + six-digit SQLite sequence = a compact, human-readable 12-digit reference.
        reference = f"{datetime.now(timezone.utc):%y%m%d}{cursor.lastrowid:06d}"
        connection.execute("UPDATE scans SET scan_reference = ? WHERE id = ?", (reference, cursor.lastrowid))
        connection.execute(
            """INSERT INTO scan_fingerprints (scan_id, content_type, domain_hashes_json, message_hash, shingle_hashes_json)
               VALUES (?, ?, ?, ?, ?)""",
            (
                cursor.lastrowid,
                content_type,
                json.dumps(fingerprints.domain_hashes),
                fingerprints.message_hash,
                json.dumps(fingerprints.shingle_hashes),
            ),
        )
    return reference


def save_security_event(client_hash: str, event_type: str, request_count: int, action_taken: str) -> None:
    with get_connection() as connection:
        connection.execute(
            """INSERT INTO security_events (client_hash, event_type, request_count, window_start, action_taken)
               VALUES (?, ?, ?, ?, ?)""",
            (client_hash, event_type, request_count, datetime.now(timezone.utc).isoformat(), action_taken),
        )


def fetch_recent_fingerprints(window_minutes: int = 15, limit: int = 200) -> list[dict[str, object]]:
    """Return recent salted scan fingerprints within the trailing campaign window."""
    modifier = f"-{max(1, int(window_minutes))} minutes"
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT content_type, domain_hashes_json, message_hash, shingle_hashes_json
               FROM scan_fingerprints
               WHERE created_at >= datetime('now', ?)
               ORDER BY id DESC
               LIMIT ?""",
            (modifier, limit),
        ).fetchall()
    return [
        {
            "content_type": row["content_type"],
            "domain_hashes": set(json.loads(row["domain_hashes_json"])),
            "message_hash": row["message_hash"],
            "shingle_hashes": json.loads(row["shingle_hashes_json"]),
        }
        for row in rows
    ]
