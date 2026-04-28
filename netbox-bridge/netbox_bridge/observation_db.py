from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    started_at      TEXT NOT NULL,
    source          TEXT NOT NULL,
    input_path      TEXT NOT NULL,
    input_sha256    TEXT NOT NULL,
    host_count      INTEGER,
    finding_count   INTEGER
);

CREATE TABLE IF NOT EXISTS observations (
    scan_id             TEXT NOT NULL REFERENCES scans(id),
    device_key          TEXT NOT NULL,
    netbox_device_id    INTEGER,
    port                INTEGER,
    protocol            TEXT,
    service_name        TEXT,
    observed_at         TEXT NOT NULL,
    PRIMARY KEY (scan_id, device_key, port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_observations_device      ON observations(device_key);
CREATE INDEX IF NOT EXISTS idx_observations_observed_at ON observations(observed_at);
"""


def open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    return conn
