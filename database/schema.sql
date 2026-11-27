CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_reference TEXT UNIQUE,
    submitted_content TEXT NOT NULL,
    content_type TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    ml_probability REAL,
    language TEXT NOT NULL DEFAULT 'en',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_hash TEXT NOT NULL,
    event_type TEXT NOT NULL,
    request_count INTEGER NOT NULL,
    window_start TEXT NOT NULL,
    action_taken TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_client_hash ON security_events(client_hash);
