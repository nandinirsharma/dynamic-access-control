#!/usr/bin/env python3
"""
setup_db_import_users.py

- Removes existing data.db (if present) and creates a fresh DB with 3 tables:
    * users (registered users only)
    * login_events (to be used when actual logins happen)
    * access_logs (for resource access decisions)
- Imports users from data/sample_rba_200.csv into users table ONLY (no login_events inserted).
- Uses bcrypt with SHA-256 prehash for password hashing (bcrypt must be installed).
- Provides helper function `record_login_event` to be used by your login route.
"""

import os
import sqlite3
import pandas as pd
import hashlib
import bcrypt
import secrets
import re
from datetime import datetime, timezone

DB_PATH = "data.db"
CSV_PATH = os.path.join("data", "sample_rba_200.csv")

# -------------------------
# Utilities
# -------------------------
ipv4_re = re.compile(r"(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})")

def normalize_ip(value) -> str:
    """Extract first IPv4-like substring from value; return empty string if none."""
    if pd.isna(value):
        return ""
    s = str(value)
    m = ipv4_re.search(s)
    return m.group(0) if m else s.strip()

def bcrypt_sha256_hash(plaintext: str) -> str:
    """
    Pre-hash password with SHA-256 then bcrypt the digest. Returns UTF-8 hashed string.
    """
    pre = hashlib.sha256(plaintext.encode("utf-8")).digest()
    hashed = bcrypt.hashpw(pre, bcrypt.gensalt())
    return hashed.decode("utf-8")

def verify_bcrypt_sha256(plaintext: str, stored_hash: str) -> bool:
    pre = hashlib.sha256(plaintext.encode("utf-8")).digest()
    try:
        return bcrypt.checkpw(pre, stored_hash.encode("utf-8"))
    except Exception:
        return False

# -------------------------
# DB schema creation
# -------------------------
def create_schema(conn: sqlite3.Connection):
    cur = conn.cursor()
 
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        registration_time TEXT NOT NULL,   -- ISO8601
        registration_ip TEXT,              -- IP at registration (may be blank)
        device_type TEXT                   -- device string at registration (may be blank)
    );
    """)

    # LOGIN EVENTS: filled only when actual login happens 
    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        timestamp TEXT NOT NULL,
        ip TEXT,
        device_type TEXT,
        user_agent TEXT,
        success INTEGER NOT NULL DEFAULT 0,    -- 1 success, 0 failure
        is_attack_ip INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """)

    # ACCESS LOGS: to record resource accesses & risk decisions
    cur.execute("""
    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        resource TEXT,
        timestamp TEXT NOT NULL,
        ip TEXT,
        device_type TEXT,
        user_agent TEXT,
        login_failure INTEGER DEFAULT 0,
        freq_last_5min INTEGER DEFAULT 0,
        risk_score INTEGER DEFAULT 0,
        risk_level TEXT,
        decision TEXT,
        details TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """)
    conn.commit()

# -------------------------
# DB helpers
# -------------------------
def open_conn(path=DB_PATH):
    conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn

def insert_user(conn: sqlite3.Connection, username: str, password_plain: str,
                registration_time: str, registration_ip: str = None, device_type: str = None) -> int:
    """Insert user if username doesn't exist. Return user id."""
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if row:
        return row["id"]
    ph = bcrypt_sha256_hash(password_plain)
    cur.execute("""
        INSERT INTO users (username, password_hash, registration_time, registration_ip, device_type)
        VALUES (?, ?, ?, ?, ?)
    """, (username, ph, registration_time, registration_ip or "", device_type or ""))
    conn.commit()
    return cur.lastrowid

def record_login_event(conn: sqlite3.Connection, username: str, timestamp_iso: str,
                       ip: str = None, device_type: str = None, user_agent: str = None,
                       success: int = 0, is_attack_ip: int = 0) -> int:
    """
    Record a real login attempt. This should be called by your login route.
    It links to users table if username exists.
    """
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    r = cur.fetchone()
    user_id = r["id"] if r else None
    cur.execute("""
        INSERT INTO login_events (user_id, username, timestamp, ip, device_type, user_agent, success, is_attack_ip)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, username, timestamp_iso, ip or "", device_type or "", user_agent or "", int(bool(success)), int(bool(is_attack_ip))))
    conn.commit()
    return cur.lastrowid

# -------------------------
# Import CSV -> users only
# -------------------------
def import_users_from_csv(conn: sqlite3.Connection, csv_path=CSV_PATH):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found at {csv_path}")

    df = pd.read_csv(csv_path, low_memory=False)
    # Normalize column names for robust mapping
    cols_lc = {c.lower(): c for c in df.columns}

    # Try to detect useful columns
    def match_any(options):
        for o in options:
            if o.lower() in cols_lc:
                return cols_lc[o.lower()]
        # substring fallback
        for col in df.columns:
            for o in options:
                if o.lower() in col.lower():
                    return col
        return None

    ip_col = match_any(["ip", "ip_address", "clientip", "source_ip"])
    ua_col = match_any(["user_agent", "useragent", "user_agent_string", "ua"])
    device_col = match_any(["device_type", "device", "devicetype"])
    username_col = match_any(["username", "user", "user_name"])
    password_col = match_any(["password", "password_plain", "password_hash"])

    print("Detected mapping for import:")
    print(" username_col:", username_col)
    print(" password_col:", password_col)
    print(" ip_col:", ip_col)
    print(" device_col:", device_col)
    print(" ua_col:", ua_col)

    inserted = 0
    for idx, row in df.iterrows():
        # build username and password
        uname = row.get(username_col) if username_col else None
        passwd = row.get(password_col) if password_col else None

        # If username missing in CSV, synthesize one deterministically
        if pd.isna(uname) or uname is None:
            # use user_id if exists or fallback to index
            uid_col = match_any(["user_id", "userid", "user"])
            if uid_col and not pd.isna(row.get(uid_col)):
                uname = f"user_{str(row.get(uid_col))}"
            else:
                uname = f"user_csv_{idx}_{secrets.token_hex(2)}"

        # If password missing, generate a secure random one
        if pd.isna(passwd) or passwd is None:
            passwd = secrets.token_urlsafe(10)

        # registration time: prefer login_timestamp/ts, otherwise now
        ts_col = match_any(["login_timestamp", "timestamp", "time", "event_time"])
        ts_raw = row.get(ts_col) if ts_col else None
        try:
            if pd.isna(ts_raw) or ts_raw is None:
                reg_ts = datetime.now(timezone.utc).isoformat()
            else:
                reg_ts = pd.to_datetime(ts_raw).isoformat()
        except Exception:
            reg_ts = datetime.now(timezone.utc).isoformat()

        ip_raw = row.get(ip_col) if ip_col else None
        ip_norm = normalize_ip(ip_raw) if ip_raw is not None else ""

        device_val = row.get(device_col) if device_col else None
        if pd.isna(device_val): device_val = ""

        # insert user (unique)
        insert_user(conn, username=str(uname), password_plain=str(passwd),
                    registration_time=reg_ts, registration_ip=ip_norm, device_type=str(device_val))
        inserted += 1

    print(f"Imported {inserted} users into users table (unique usernames preserved).")

# -------------------------
# Main: recreate DB and import
# -------------------------
def main():
    # remove DB if exists (user wants to delete and recreate)
    if os.path.exists(DB_PATH):
        print(f"Removing existing DB: {DB_PATH}")
        os.remove(DB_PATH)

    conn = open_conn(DB_PATH)
    create_schema(conn)
    # import only users from CSV
    import_users_from_csv(conn, CSV_PATH)
    conn.close()
    print("DB created and users imported successfully.")

if __name__ == "__main__":
    main()
