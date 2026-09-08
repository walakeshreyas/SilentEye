import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "silenteye_hashes.db")

def init_database():
    """
    Creates malicious hash database with proper schema and index.
    Run once to initialize. Safe to run multiple times.
    """
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS malicious_hashes (
            sha256       TEXT PRIMARY KEY,
            malware_name TEXT,
            severity     TEXT DEFAULT 'high',
            source       TEXT DEFAULT 'manual',
            added_date   TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Index for instant lookup
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_sha256
        ON malicious_hashes(sha256)
    """)

    conn.commit()
    conn.close()
    print(f"[DB] Database initialized at {DB_PATH}")

def add_hash(sha256: str, malware_name: str, severity: str = "high", source: str = "manual"):
    """Add a single malicious hash to database"""
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO malicious_hashes (sha256, malware_name, severity, source) VALUES (?,?,?,?)",
        (sha256, malware_name, severity, source)
    )
    conn.commit()
    conn.close()

def get_stats():
    """Return total hash count in database"""
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM malicious_hashes")
    count  = cursor.fetchone()[0]
    conn.close()
    return {"total_hashes": count}

if __name__ == "__main__":
    init_database()
    print(f"[DB] Stats: {get_stats()}")
