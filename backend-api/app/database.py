"""OctoPlamTree Database Layer — async SQLite via aiosqlite"""

import aiosqlite
import os
from contextlib import asynccontextmanager
from .config import DATABASE_PATH

# Resolve DB path relative to backend-api/ directory
_DB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(_DB_DIR, DATABASE_PATH)


async def init_db():
    """Create tables if they don't exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                threat_type TEXT,
                details TEXT,
                severity TEXT,
                url TEXT,
                risk_score INTEGER DEFAULT 0,
                source TEXT DEFAULT 'extension',
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                type TEXT,
                url TEXT,
                method TEXT,
                page_url TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS url_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                score INTEGER,
                is_suspicious INTEGER,
                reason TEXT,
                scanned_at TEXT DEFAULT (datetime('now'))
            )
        """)
        # Indexes for common queries
        await db.execute("CREATE INDEX IF NOT EXISTS idx_threat_severity ON threat_logs(severity)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_threat_timestamp ON threat_logs(timestamp)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_threat_type ON threat_logs(threat_type)")
        await db.commit()
    print(f"[OctoPlamTree] Database initialized at {DB_PATH}")


@asynccontextmanager
async def get_db():
    """Async context manager for database connections."""
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    try:
        yield db
    finally:
        await db.close()
