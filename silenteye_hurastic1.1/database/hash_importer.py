import sqlite3
import os
import sys

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "silenteye_hashes.db")

# ================================
# INIT DATABASE
# FIXED: Removed duplicate init_database() — imports from init_db.py
# Single source of truth for schema definition
# ================================

import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from init_db import init_database
except ImportError:
    # Fallback if init_db not in same directory
    def init_database():
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS malicious_hashes (
                sha256       TEXT PRIMARY KEY,
                malware_name TEXT,
                severity     TEXT DEFAULT 'high',
                source       TEXT DEFAULT 'malwarebazaar',
                added_date   TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON malicious_hashes(sha256)")
        conn.commit()
        conn.close()

# ================================
# IMPORT FROM MALWAREBAZAAR CSV
# ================================

def import_malwarebazaar(txt_path: str):
    """
    Imports hashes from MalwareBazaar full SHA256 txt export.
    Download from: https://bazaar.abuse.ch/export/
    File: full_sha256.txt

    Format:
    # comment lines starting with # are skipped
    09db02307346921bb4e49dcf6f4b89c49584b994c08dbbecadd7f087c1c41961
    6740023be829f84fa543ebfb2f745e33cba576ed8f51d4fdb4331dc36c16a3b7
    ...
    """

    if not os.path.exists(txt_path):
        print(f"ERROR: File not found at {txt_path}")
        return

    file_size_mb = os.path.getsize(txt_path) / (1024 * 1024)
    print(f"Opening : {txt_path}")
    print(f"Size    : {file_size_mb:.1f} MB")
    print(f"Importing... this may take 1-2 minutes for 1M+ hashes")
    print("-" * 50)

    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Performance optimization for bulk insert
    cursor.execute("PRAGMA journal_mode = WAL")
    cursor.execute("PRAGMA synchronous = NORMAL")

    imported = 0
    skipped  = 0
    errors   = 0
    batch    = []
    BATCH_SIZE = 5000  # larger batch = faster for 1M+ entries

    try:
        with open(txt_path, "r", encoding="utf-8", errors="ignore") as f:

            for line in f:

                line = line.strip()

                # Skip empty lines and comment lines
                if not line or line.startswith("#"):
                    skipped += 1
                    continue

                try:
                    sha256 = line.lower()

                    # Validate — must be exactly 64 hex characters
                    if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
                        skipped += 1
                        continue

                    batch.append((sha256, "malwarebazaar_sample", "high", "malwarebazaar"))

                    # Insert batch
                    if len(batch) >= BATCH_SIZE:
                        cursor.executemany(
                            "INSERT OR IGNORE INTO malicious_hashes (sha256, malware_name, severity, source) VALUES (?,?,?,?)",
                            batch
                        )
                        conn.commit()
                        imported += len(batch)
                        print(f"  Imported: {imported:,} hashes...", end="\r")
                        batch = []

                except Exception:
                    errors += 1
                    continue

        # Insert remaining batch
        if batch:
            cursor.executemany(
                "INSERT OR IGNORE INTO malicious_hashes (sha256, malware_name, severity, source) VALUES (?,?,?,?)",
                batch
            )
            conn.commit()
            imported += len(batch)

    except Exception as e:
        print(f"\nERROR during import: {e}")

    finally:
        conn.close()

    print(f"\n{'='*50}")
    print(f"  IMPORT COMPLETE")
    print(f"  Imported : {imported:,}")
    print(f"  Skipped  : {skipped:,}  (comments + invalid lines)")
    print(f"  Errors   : {errors:,}")
    print(f"  DB Path  : {DB_PATH}")
    print(f"{'='*50}")

# ================================
# ADD SINGLE HASH MANUALLY
# ================================

def add_hash(sha256: str, malware_name: str = "unknown", severity: str = "high"):
    """Add a single hash manually"""

    sha256 = sha256.strip().lower()

    if len(sha256) != 64:
        print(f"ERROR: Invalid SHA256 hash length: {len(sha256)}")
        return

    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO malicious_hashes (sha256, malware_name, severity, source) VALUES (?,?,?,?)",
        (sha256, malware_name, severity, "manual")
    )
    conn.commit()
    conn.close()
    print(f"Added: {sha256[:16]}... → {malware_name}")

# ================================
# LOOKUP SINGLE HASH
# ================================

def lookup_hash(sha256: str):
    """Test lookup for a single hash"""

    sha256 = sha256.strip().lower()
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT sha256, malware_name, severity, source, added_date FROM malicious_hashes WHERE sha256 = ?",
        (sha256,)
    )
    result = cursor.fetchone()
    conn.close()

    if result:
        print(f"MATCH FOUND:")
        print(f"  SHA256  : {result[0]}")
        print(f"  Malware : {result[1]}")
        print(f"  Severity: {result[2]}")
        print(f"  Source  : {result[3]}")
        print(f"  Added   : {result[4]}")
    else:
        print(f"No match found for: {sha256[:16]}...")

# ================================
# DATABASE STATS
# ================================

def get_stats():
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM malicious_hashes")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT source, COUNT(*) FROM malicious_hashes GROUP BY source")
    by_source = cursor.fetchall()

    cursor.execute("SELECT severity, COUNT(*) FROM malicious_hashes GROUP BY severity")
    by_severity = cursor.fetchall()

    conn.close()

    print(f"{'='*50}")
    print(f"  DATABASE STATS")
    print(f"  Total hashes : {total}")
    print(f"  By source    :")
    for src, count in by_source:
        print(f"    {src}: {count}")
    print(f"  By severity  :")
    for sev, count in by_severity:
        print(f"    {sev}: {count}")
    print(f"{'='*50}")

# ================================
# ENTRY POINT
# ================================

if __name__ == "__main__":

    init_database()

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python hash_importer.py import  <path/to/full_sha256.csv>")
        print("  python hash_importer.py add     <sha256> <malware_name>")
        print("  python hash_importer.py lookup  <sha256>")
        print("  python hash_importer.py stats")
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "import" and len(sys.argv) >= 3:
        import_malwarebazaar(sys.argv[2])

    elif command == "add" and len(sys.argv) >= 4:
        add_hash(sys.argv[2], sys.argv[3])

    elif command == "lookup" and len(sys.argv) >= 3:
        lookup_hash(sys.argv[2])

    elif command == "stats":
        get_stats()

    else:
        print("Invalid command. Run without arguments for usage.")
