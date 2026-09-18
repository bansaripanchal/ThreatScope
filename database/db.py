"""
ThreatScope V2 - Database Connection and Schema Management
Handles SQLite database initialization, table creation, and connection pooling.
"""

import sqlite3
import os
from contextlib import contextmanager
from pathlib import Path
from config import Config

def get_db_path():
    path = Path(Config.DATABASE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)

@contextmanager
def get_db_connection():
    """Provides a transactional database connection context."""
    conn = sqlite3.connect(get_db_path(), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    """Initializes the database schema if tables do not exist."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            target_type TEXT NOT NULL,
            normalized_target TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            duration_seconds REAL,
            findings_count INTEGER DEFAULT 0,
            data_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS timeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            operation TEXT NOT NULL,
            status TEXT NOT NULL,
            duration_ms INTEGER,
            message TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            affected_asset TEXT NOT NULL,
            evidence TEXT NOT NULL,
            source TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_investigations_created ON investigations(created_at DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timeline_investigation ON timeline_events(investigation_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_investigation ON findings(investigation_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
