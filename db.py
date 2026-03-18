import sqlite3
from datetime import datetime, timedelta
import os
import logging

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create tables if missing (users.username COLLATE NOCASE for case-insensitive uniqueness)."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      registration_ip TEXT,
      device_type TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      device_fingerprint TEXT,
      compliance_score INTEGER DEFAULT 0,
      last_seen TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS access_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      resource TEXT,
      ip TEXT,
      device_type TEXT,
      user_agent TEXT,
      timestamp TEXT,
      risk_score REAL,
      risk_level TEXT,
      decision TEXT,
      details TEXT
    );
    """)
    # login_events includes optional access_token column
    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      timestamp TEXT NOT NULL,
      ip TEXT,
      device_type TEXT,
      user_agent TEXT,
      success INTEGER NOT NULL DEFAULT 0,
      access_token TEXT
    );
    """)
    # Sessions table for server-side session management (jti-based)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      jti TEXT UNIQUE,
      access_token TEXT,
      issued_at TEXT,
      expires_at TEXT,
      revoked INTEGER DEFAULT 0,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    conn.commit()
    conn.close()
    logging.info("init_db: ensured tables exist at %s", DB_PATH)

# ----------------------
# Normalization helpers
# ----------------------
def _normalize_username(username):
    if username is None:
        return None
    return str(username).strip().lower()

# ----------------------
# User helpers
# ----------------------
def create_user(username, password_hash):
    username = _normalize_username(username)
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash))
        conn.commit()
        uid = cur.lastrowid
        conn.close()
        logging.info("create_user: inserted username=%s id=%s", username, uid)
        return uid
    except sqlite3.IntegrityError:
        logging.warning("create_user: username already exists: %s", username)
        conn.close()
        return None
    except Exception:
        logging.exception("create_user failed")
        conn.close()
        return None

def get_user_by_username(username):
    username = _normalize_username(username)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

# ----------------------
# Device helpers
# ----------------------
def add_or_update_device(user_id, fingerprint, compliance_score=0):
    conn = get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    try:
        cur.execute("SELECT id FROM devices WHERE user_id=? AND device_fingerprint=?", (user_id, fingerprint))
        r = cur.fetchone()
        if r:
            cur.execute("UPDATE devices SET compliance_score=?, last_seen=? WHERE id=?", (compliance_score, now, r["id"]))
        else:
            cur.execute("INSERT INTO devices (user_id, device_fingerprint, compliance_score, last_seen) VALUES (?, ?, ?, ?)",
                        (user_id, fingerprint, compliance_score, now))
        conn.commit()
    finally:
        conn.close()

def get_devices_for_user(user_id):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM devices WHERE user_id=?", (user_id,))
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def get_device_compliance(device_fingerprint):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("SELECT compliance_score FROM devices WHERE device_fingerprint = ?", (device_fingerprint,))
        r = cur.fetchone()
        if r and r["compliance_score"] is not None:
            try:
                return float(r["compliance_score"])
            except Exception:
                return float(r["compliance_score"] or 0.0)
        return 20.0
    finally:
        conn.close()

# ----------------------
# Logging & counts
# ----------------------
def log_access(user_id, username, resource, ip, device_type, user_agent, risk_score, risk_level, decision, details=""):
    """
    Insert a row into access_logs. device_type is optional.
    Note: signature changed to include device_type before user_agent.
    """
    conn = get_conn()
    cur = conn.cursor()
    try:
        now = datetime.utcnow().isoformat()
        cur.execute("""
          INSERT INTO access_logs
            (user_id, username, resource, ip, device_type, user_agent, timestamp, risk_score, risk_level, decision, details)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, resource, ip, device_type, user_agent, now, risk_score, risk_level, decision, details))
        conn.commit()
        lastrowid = cur.lastrowid
        logging.info("log_access: inserted id=%s user=%s resource=%s decision=%s", lastrowid, username, resource, decision)
        return lastrowid
    finally:
        conn.close()

def record_login_event(user_id, username, ip, device_type, user_agent, success, access_token=None):
    """
    Record an entry in login_events.
    success: 1 for success, 0 for failure.
    access_token: optional JWT string (stored for successful logins).
    """
    try:
        conn = get_conn()
        cur = conn.cursor()
        now = datetime.utcnow().isoformat()
        cur.execute("""
            INSERT INTO login_events (user_id, username, timestamp, ip, device_type, user_agent, success, access_token)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, now, ip or "", device_type or "", user_agent or "", int(bool(success)), access_token))
        conn.commit()
        lastrowid = cur.lastrowid
        logging.info("record_login_event: id=%s user=%s success=%s ip=%s device=%s", lastrowid, username, success, ip, device_type)
        return lastrowid
    except Exception:
        logging.exception("record_login_event failed")
        try:
            conn.close()
        except Exception:
            pass
        return None

# ----------------------
# Session helpers (jti-based)
# ----------------------
def create_session(user_id, jti, access_token, issued_at_iso, expires_at_iso):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("""INSERT INTO sessions (user_id, jti, access_token, issued_at, expires_at, revoked)
                       VALUES (?, ?, ?, ?, ?, 0)""",
                    (user_id, jti, access_token, issued_at_iso, expires_at_iso))
        conn.commit()
        sid = cur.lastrowid
        return sid
    except sqlite3.IntegrityError:
        # duplicate jti
        conn.close()
        return None
    except Exception:
        logging.exception("create_session failed")
        conn.close()
        return None

def get_session_by_jti(jti):
    if not jti:
        return None
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM sessions WHERE jti = ?", (jti,))
        r = cur.fetchone()
        return dict(r) if r else None
    finally:
        conn.close()

def revoke_session_by_jti(jti):
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE sessions SET revoked = 1 WHERE jti = ?", (jti,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()

def get_recent_access_count(user_id, minutes=60, only_failed=False):
    if not user_id:
        return 0
    try:
        conn = get_conn()
        cur = conn.cursor()
        cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
        if only_failed:
            cur.execute("""
                SELECT COUNT(*) as cnt FROM access_logs
                WHERE user_id = ? AND timestamp >= ? AND LOWER(decision) = 'deny'
            """, (user_id, cutoff))
        else:
            cur.execute("""
                SELECT COUNT(*) as cnt FROM access_logs
                WHERE user_id = ? AND timestamp >= ?
            """, (user_id, cutoff))
        row = cur.fetchone()
        conn.close()
        if not row:
            return 0
        try:
            return int(row["cnt"])
        except Exception:
            return int(row[0])
    except Exception:
        try: conn.close()
        except: pass
        logging.exception("get_recent_access_count failed")
        return 0
