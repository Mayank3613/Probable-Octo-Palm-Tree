
"""
SQLite Database Layer (Async)
Probable-Octo-Palm-Tree
Uses aiosqlite for async context manager support.
"""

import aiosqlite
import sqlite3
import os

# =========================================================
# DATABASE LOCATION
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DB_PATH = os.path.join(
    BASE_DIR,
    "probable_octo_threats.db"
)

# =========================================================
# ASYNC DATABASE CONNECTION
# =========================================================

def get_db():
    """Returns an aiosqlite connection context manager.
    Usage: async with get_db() as db:
    """
    return aiosqlite.connect(DB_PATH)

# =========================================================
# SYNCHRONOUS CONNECTION (for init only)
# =========================================================

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def init_db():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # =====================================================
    # THREAT LOGS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            threat_type TEXT,
            details TEXT,
            severity TEXT,
            url TEXT,
            risk_score INTEGER DEFAULT 0,
            source TEXT DEFAULT 'extension',
            action TEXT DEFAULT 'detected',
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # =====================================================
    # URL SCANS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            score INTEGER,
            is_suspicious INTEGER,
            reason TEXT,
            scanned_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # =====================================================
    # CONNECTION LOGS
    # =====================================================

    cursor.execute("""
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

    conn.commit()
    conn.close()

    print("[DB] SQLite initialized")
