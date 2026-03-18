# check_db.py
import os, sqlite3, sys

DB = os.path.abspath("data.db")
print("DB absolute path:", DB)
print()

if not os.path.exists(DB):
    print("File does not exist:", DB)
    sys.exit(1)

conn = sqlite3.connect(DB)
cur = conn.cursor()

def q_fetchall(q, params=()):
    cur.execute(q, params)
    return cur.fetchall()

print("=== last 10 users (id, username) ===")
rows = q_fetchall("SELECT id, username FROM users ORDER BY id DESC LIMIT 10")
for r in rows:
    print(r)
print()

print("=== users count ===")
cur.execute("SELECT COUNT(*) FROM users")
print(cur.fetchone()[0])
print()

print("=== max user id ===")
cur.execute("SELECT MAX(id) FROM users")
print(cur.fetchone()[0])
print()

print("=== last 10 access_logs (id, user_id, username, resource, decision, timestamp) ===")
rows = q_fetchall("SELECT id, user_id, username, resource, decision, timestamp FROM access_logs ORDER BY id DESC LIMIT 10")
for r in rows:
    print(r)
print()

conn.close()
print("Done.")
