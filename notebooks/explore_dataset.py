"""
Quick exploration of CICIDS2017.
Run this to understand what we're working with
before writing the cleaning pipeline.
"""
import pandas as pd
import os
import numpy as np

RAW_DIR = "data/raw/"

# find all CSV files
csv_files = [f for f in os.listdir(RAW_DIR) if f.endswith(".csv")]
print(f"Found {len(csv_files)} CSV files:")
for f in csv_files:
    size = os.path.getsize(os.path.join(RAW_DIR, f)) / (1024*1024)
    print(f"  {f} ({size:.1f} MB)")

print("\n" + "="*60)

# load one file to explore structure
print("\nLoading first file to explore structure...")
first_file = os.path.join(RAW_DIR, csv_files[0])
print(f"File: {first_file}")
df = pd.read_csv(first_file, low_memory=False)

print(f"\nShape: {df.shape}")
print(f"Rows: {df.shape[0]:,}")
print(f"Columns: {df.shape[1]}")

print(f"\nALL column names:")
for i, col in enumerate(df.columns):
    print(f"  [{i}] '{col}'")

print(f"\nLabel column values:")
# find the label column whatever it's called
label_col = None
for col in df.columns:
    if col.strip().lower() == "label":
        label_col = col
        break

if label_col:
    print(f"Label column found: '{label_col}'")
    print(df[label_col].value_counts())
else:
    print("Could not find label column automatically")

print(f"\nNull values per column (only columns with nulls):")
nulls = df.isnull().sum()
print(nulls[nulls > 0])

print(f"\nInfinity values check:")
numeric_cols = df.select_dtypes(include=[np.number]).columns
inf_count = np.isinf(df[numeric_cols]).sum().sum()
print(f"  Total infinity values: {inf_count}")

print("\nDone.")
