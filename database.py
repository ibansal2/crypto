# Functions to manage the database initialization and connections

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Optional

import config

# Initialize the database schema
def init_db() -> None:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not config.SCHEMA_PATH.exists():
        raise RuntimeError("schema.sql is missing; cannot initialize database schema")
    with sqlite3.connect(config.DB_PATH) as conn, open(config.SCHEMA_PATH, "r", encoding="utf-8") as schema_file:
        conn.executescript(schema_file.read())

# Establish a database connection
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# Logs 'who did what and when' into the access_logs table
def log_access(user_id: Optional[int], document_id: int, action: str) -> None:
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO access_logs (user_id, document_id, action, timestamp) VALUES (?, ?, ?, ?)",
            (user_id, document_id, action, datetime.utcnow().isoformat()),
        )
        conn.commit()
