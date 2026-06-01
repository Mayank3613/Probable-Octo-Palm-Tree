
"""
SQLite Database Layer
Probable-Octo-Palm-Tree
"""

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
# DATABASE CONNECTION
# =========================================================

def get_db_connection():

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    return conn

# =========================================================
# BACKWARD COMPATIBILITY
# =========================================================

def get_db():
    return get_db_connection()

# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def init_db():

    conn = get_db_connection()

    cursor = conn.cursor()

    # =====================================================
    # THREAT LOGS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            threat_type TEXT,

            severity TEXT,

            url TEXT,

            details TEXT,

            source TEXT,

            risk_score REAL,

            action TEXT
        )
    """)

    # =====================================================
    # URL SCANS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            url TEXT,

            verdict TEXT,

            risk_score REAL,

            scan_time TEXT
        )
    """)

    # =====================================================
    # CONNECTION LOGS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS connections (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            source_ip TEXT,

            destination_ip TEXT,

            protocol TEXT,

            timestamp TEXT
        )
    """)

    conn.commit()

    conn.close()

    print("[DB] SQLite initialized")

