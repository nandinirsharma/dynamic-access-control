#!/usr/bin/env python3
"""
extract_sample_rba_safe.py

Safer extractor for very large RBA CSVs.
 - Reads the CSV in chunks
 - Attempts to auto-detect required columns
 - If user_id (or other fields) are missing, synthesizes reasonable placeholders
 - Adds unique username and password
 - Writes exactly TARGET_ROWS to output CSV

Edit INPUT_PATH before running if needed.
"""
import os
import hashlib
import pandas as pd
import secrets
import string
from typing import Dict, List, Optional

# === CONFIG ===
INPUT_PATH = r"C:\Users\Nandini Sharma\Downloads\rba-dataset.csv"  # <-- change to your file if needed
OUTPUT_PATH = "data/sample_rba_200.csv"
TARGET_ROWS = 200
CHUNK_SIZE = 50000  # tune as needed

# Candidate names for automatic detection (case-insensitive)
COLUMN_MAP_CANDIDATES = {
    "ip": ["ip", "ip_address", "client_ip", "clientip", "ipaddr"],
    "user_agent": ["user_agent", "useragent", "user_agent_string", "ua", "user-agent", "http_user_agent"],
    "device_type": ["device_type", "device", "device_name", "devicetype"],
    "user_id": ["user_id", "userid", "user", "username_id", "userId"],
    "login_timestamp": ["login_timestamp", "timestamp", "time", "login_time", "ts", "event_time"],
    "login_success": ["login_success", "success", "login_successful", "is_success", "result"],
    "is_attack_ip": ["is_attack_ip", "is_attack", "attack", "is_malicious", "malicious"]
}


def find_column(df_cols: List[str], candidates: List[str]) -> Optional[str]:
    lowered = {c.lower(): c for c in df_cols}
    for cand in candidates:
        if cand.lower() in lowered:
            return lowered[cand.lower()]
    # fallback: substring match
    for col in df_cols:
        for cand in candidates:
            if cand.lower() in col.lower():
                return col
    return None


def generate_password(length=10):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def synthesize_user_id(row: pd.Series, fallback_index: int) -> str:
    """
    Create a stable synthetic user id based on available fields (IP + UA),
    otherwise use an index-based id.
    """
    # prefer IP + UA if available
    ip = row.get("ip", None) or row.get("IP", None) or ""
    ua = row.get("user_agent", None) or row.get("User-Agent", None) or ""
    if ip or ua:
        h = hashlib.sha1(f"{ip}|{ua}".encode("utf-8")).hexdigest()[:10]
        return f"synthetic_{h}"
    return f"synthetic_idx_{fallback_index}"


def safe_rename_and_extract(chunk: pd.DataFrame, rename_map: Dict[str, str]) -> pd.DataFrame:
    """
    Return a DataFrame with canonical names for fields we want. Do not assume user_id exists.
    """
    # Keep only columns that exist
    exist_cols = [v for v in rename_map.values() if v in chunk.columns]
    df = chunk[exist_cols].copy()
    # Rename to canonical keys (invert the rename_map: canonical -> actual)
    inv_map = {v: k for k, v in rename_map.items()}
    df.rename(columns=inv_map, inplace=True)
    return df


def main():
    os.makedirs(os.path.dirname(OUTPUT_PATH) or ".", exist_ok=True)
    collected = []
    rename_map = None  # canonical_name -> actual_csv_col_name

    print("Starting chunked read from:", INPUT_PATH)
    total_rows_collected = 0
    for chunk_idx, chunk in enumerate(pd.read_csv(INPUT_PATH, chunksize=CHUNK_SIZE, low_memory=False)):
        # On first chunk detect mapping
        if rename_map is None:
            found = {}
            for canonical, candidates in COLUMN_MAP_CANDIDATES.items():
                found_col = find_column(list(chunk.columns), candidates)
                found[canonical] = found_col
            print("Column detection (first chunk):")
            for k, v in found.items():
                print(f"  {k:15s} -> {v}")
            # build rename_map mapping canonical -> actual_col (only if found)
            rename_map = {k: v for k, v in found.items() if v is not None}
            if "ip" not in rename_map:
                print("Warning: Could not detect IP column. Output will still be created but 'ip' will be empty.")
            # we continue even if user_id missing; we'll synthesize later

        # extract the desired columns we found
        sub = safe_rename_and_extract(chunk, rename_map)

        # ensure canonical columns exist (create missing ones as NaN)
        for col in ["ip", "user_agent", "device_type", "user_id", "login_timestamp", "login_success", "is_attack_ip"]:
            if col not in sub.columns:
                sub[col] = pd.NA

        # Fill user_id where missing by synthesizing it deterministically per row
        synth_ids = []
        for i, row in sub.iterrows():
            if pd.isna(row["user_id"]):
                synth = synthesize_user_id(row, fallback_index=(chunk_idx * CHUNK_SIZE + i))
                synth_ids.append(synth)
            else:
                # coerce to str
                synth_ids.append(str(row["user_id"]))
        sub["user_id"] = synth_ids

        # Generate unique usernames and passwords for this sub-chunk
        usernames = []
        passwords = []
        for idx_local, uid in enumerate(sub["user_id"].tolist()):
            uname = f"user_{uid}_{secrets.token_hex(2)}"
            usernames.append(uname)
            passwords.append(generate_password())

        sub["username"] = usernames
        sub["password"] = passwords

        # append
        collected.append(sub)
        total_rows_collected = sum(len(df) for df in collected)
        print(f"Chunk {chunk_idx+1}: collected {total_rows_collected} rows so far")

        if total_rows_collected >= TARGET_ROWS:
            break

    if not collected:
        print("No rows were collected. Possible reasons: wrong INPUT_PATH or file unreadable.")
        return

    # concat and trim
    df_out = pd.concat(collected, ignore_index=True).head(TARGET_ROWS)

    # final ordering of columns (only the ones that exist)
    desired_order = ["username", "password", "user_id", "ip", "user_agent",
                     "device_type", "login_timestamp", "login_success", "is_attack_ip"]
    final_cols = [c for c in desired_order if c in df_out.columns]
    df_out = df_out[final_cols]

    # write
    df_out.to_csv(OUTPUT_PATH, index=False)
    print(f"Done. Wrote {len(df_out)} rows to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
