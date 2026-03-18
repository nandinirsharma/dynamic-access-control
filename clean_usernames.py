#!/usr/bin/env python3
# scripts/clean_usernames.py
import pandas as pd
import os
import json

SRC = "data/sample_rba_200.csv"
OUT = "data/sample_rba_200_clean.csv"
MAP_OUT = "data/username_mapping.json"

if not os.path.exists(SRC):
    raise SystemExit(f"Source CSV not found: {SRC}")

# read CSV
df = pd.read_csv(SRC, low_memory=False)

# find username column case-insensitively
cols_lower = {c.lower(): c for c in df.columns}
if 'username' in cols_lower:
    uname_col = cols_lower['username']
else:
    # fallback: use first column
    uname_col = df.columns[0]
    print(f"Warning: 'username' column not found. Using first column '{uname_col}' as username column.")

orig_usernames = df[uname_col].astype(str).tolist()

# List of common first names (100). We'll create deterministic simple usernames.
first_names = [
"Alice","Bob","Charlie","Diana","Ethan","Fiona","George","Hannah","Ian","Julia",
"Kevin","Laura","Michael","Nina","Oliver","Paula","Quentin","Rachel","Simon","Tina",
"Uma","Victor","Wendy","Xavier","Yvonne","Zach","Aaron","Bella","Caleb","Denise",
"Ella","Felix","Gavin","Hazel","Isaac","Jade","Kyle","Leah","Mason","Maya",
"Noah","Olivia","Peter","Queenie","Riley","Sophie","Trent","Ursula","Violet","Wyatt",
"Xena","Yara","Zane","Adrian","Bianca","Cody","Delia","Eli","Gia","Howard",
"Ivy","Jonah","Kira","Liam","Molly","Nathan","Opal","Parker","Quinn","Rosa",
"Scott","Tara","Ulrich","Valerie","Will","Ximena","Yusuf","Zara","Amber","Blake",
"Clara","Damien","Erin","Frank","Greta","Holden","Iris","Jasper","Kelsey","Lucas",
"Megan","Nolan","Odette","Preston","Quincy","Rowan","Selina","Theo","Una","Vera"
]

# Build deterministic mapping original -> simple username
mapping = {}
used = {}
counter = 0
for orig in orig_usernames:
    if orig in mapping:
        continue
    idx = counter % len(first_names)
    base = first_names[idx].strip().lower()
    # if base unused -> use it; otherwise append numeric suffix
    if base not in used:
        newname = base
        used[base] = 1
    else:
        used[base] += 1
        newname = f"{base}{used[base]}"
    mapping[orig] = newname
    counter += 1

# Apply mapping
df_clean = df.copy()
df_clean[uname_col] = df_clean[uname_col].astype(str).map(mapping)

# Save results
df_clean.to_csv(OUT, index=False)
with open(MAP_OUT, "w", encoding="utf-8") as fh:
    json.dump(mapping, fh, indent=2, ensure_ascii=False)

# Print short summary
unique_count = len(set(orig_usernames))
print("Source CSV:", SRC)
print("Row count:", len(df))
print("Unique original usernames:", unique_count)
print("Output CSV:", OUT)
print("Mapping JSON:", MAP_OUT)
print("\nSample mappings (first 20):")
for i, (k,v) in enumerate(mapping.items()):
    print(f"{k}  ->  {v}")
    if i >= 19:
        break
print("\nDone.")
