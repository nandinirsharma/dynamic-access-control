# import_csv_users.py
import sqlite3
import pandas as pd
import os
from auth import hash_password
from db import DB_PATH, get_conn

CSV_PATH = "data/sample_rba_200.csv"   # adjust path if needed
USERNAME_COL = "username"               # use the actual username column from CSV
PASSWORD_COL = None   # set if CSV includes a password; otherwise generated

def gen_password_for(row_index):
    return f"pwd_{row_index:04d}"

def safe_username(u):
    if u is None:
        return None
    return str(u).strip().lower()

def main():
    if not os.path.exists(CSV_PATH):
        print("CSV not found:", CSV_PATH); return
    df = pd.read_csv(CSV_PATH, low_memory=False)
    conn = get_conn()
    cur = conn.cursor()
    inserted = 0
    for idx, row in df.iterrows():
        raw_u = row.get(USERNAME_COL, None)
        if raw_u is None or str(raw_u).strip() == "":
            continue
        username = safe_username(raw_u)
        if PASSWORD_COL:
            password = str(row.get(PASSWORD_COL, "")).strip()
            if not password:
                password = gen_password_for(idx)
        else:
            password = gen_password_for(idx)
        ph = hash_password(password)
        try:
            cur.execute("INSERT INTO users (username, password_hash, registration_ip, device_type) VALUES (?, ?, ?, ?)",
                        (username, ph, row.get("ip",""), row.get("device_type","")))
            inserted += 1
        except sqlite3.IntegrityError:
            # user exists -> skip
            pass
    conn.commit()
    conn.close()
    print("Inserted users:", inserted)

if __name__ == "__main__":
    main()
