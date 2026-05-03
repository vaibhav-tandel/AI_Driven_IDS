# data_processing.py
# CIC-IDS2017 Data Processing (Robust & Automatic)

import pandas as pd
import numpy as np
import glob
import os

from config import RAW_DATA_DIR, SAMPLE_DATASET_PATH, PROCESSED_DATA_DIR

# ---------------- CONFIG ----------------
INPUT_PATTERN = os.path.join(RAW_DATA_DIR, "*.csv")

# Ensure output directory exists
os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)

MAX_BENIGN_SAMPLES = 100000

print("🔄 Processing CIC-IDS2017 dataset...\n")

# 1️⃣ Load & Merge
all_files = glob.glob(INPUT_PATTERN)
if not all_files:
    print(f"❌ No CSV files found in '{INPUT_PATTERN}'")
    exit()

chunks = []
for filename in all_files:
    print(f"📂 Reading {filename}")
    try:
        df = pd.read_csv(filename, encoding='latin-1')
        df.columns = df.columns.str.strip()

        # Detect Label column
        label_cols = [c for c in df.columns if 'label' in c.lower()]
        if not label_cols:
            print(f"⚠️ No label column in {filename}, skipping")
            continue
        label_col = label_cols[0]
        df.rename(columns={label_col: 'label'}, inplace=True)

        # Standardize labels (handle both regular space and non-breaking space \xa0)
        df['label'] = df['label'].str.strip()
        df['label'] = df['label'].replace({
            'BENIGN': 'Benign',
            'Web Attack  Brute Force': 'Web Attack',
            'Web Attack  XSS': 'Web Attack',
            'Web Attack  Sql Injection': 'Web Attack',
            'Web Attack \xa0 Brute Force': 'Web Attack',
            'Web Attack \xa0 XSS': 'Web Attack',
            'Web Attack \xa0 Sql Injection': 'Web Attack',
            'Web Attack \u2013 Brute Force': 'Web Attack',
            'Web Attack \u2013 XSS': 'Web Attack',
            'Web Attack \u2013 Sql Injection': 'Web Attack',
        })

        # Downsample benign
        df_benign = df[df['label'] == 'Benign']
        df_attack = df[df['label'] != 'Benign']
        if len(df_benign) > 50000:
            df_benign = df_benign.sample(n=50000, random_state=42)

        chunks.append(pd.concat([df_benign, df_attack]))
    except Exception as e:
        print(f"❌ Error in {filename}: {e}")

# Combine all
full_df = pd.concat(chunks, ignore_index=True)
print(f"\n✅ Raw size: {len(full_df)} rows")

# 2️⃣ Clean data
full_df.drop_duplicates(inplace=True)
full_df.replace([np.inf, -np.inf], np.nan, inplace=True)
full_df.dropna(inplace=True)
print(f"✅ Cleaned size: {len(full_df)} rows")

# 3️⃣ Feature detection
bytes_cols = [c for c in full_df.columns if 'bytes' in c.lower() or 'totlen' in c.lower()]
packets_cols = [c for c in full_df.columns if 'pkt' in c.lower() or 'packet' in c.lower()]
duration_cols = [c for c in full_df.columns if 'duration' in c.lower()]

if not bytes_cols:
    raise ValueError("❌ Cannot detect a bytes column. Check CSV.")
if not packets_cols:
    raise ValueError("❌ Cannot detect a packets column. Check CSV.")
if not duration_cols:
    raise ValueError("❌ Cannot detect a flow duration column. Check CSV.")
duration_col = duration_cols[0]

# 4️⃣ Derived features
full_df['total_bytes'] = full_df[bytes_cols].sum(axis=1)
full_df['total_packets'] = full_df[packets_cols].sum(axis=1)
full_df['bytes_per_packet'] = full_df['total_bytes'] / (full_df['total_packets'] + 1e-6)
full_df['packets_per_duration'] = full_df['total_packets'] / (full_df[duration_col] + 1e-6)

# 5️⃣ Drop non-numeric columns
drop_cols = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Timestamp']
existing_drop = [c for c in drop_cols if c in full_df.columns]
full_df.drop(columns=existing_drop, inplace=True)

# 6️⃣ Save final CSV
full_df.to_csv(SAMPLE_DATASET_PATH, index=False)
print(f"\n💾 Dataset ready: {SAMPLE_DATASET_PATH}")
print(f"📊 Shape: {full_df.shape}")
print("📊 Class distribution:")
print(full_df['label'].value_counts())
