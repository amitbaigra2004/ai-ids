
import pandas as pd
import numpy as np
import os
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

RAW_DIR       = "data/raw/"
PROCESSED_DIR = "data/processed/"


FEATURE_ORDER = [
    "duration",
    "packet_count",
    "byte_count",
    "packets_per_second",
    "bytes_per_second",
    "avg_packet_size",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "syn_ratio",
    "rst_ratio",
    "dst_port",
]


def load_all_csvs(raw_dir=RAW_DIR):

    csv_files = [f for f in os.listdir(raw_dir) if f.endswith(".csv")]
    print(f"Found {len(csv_files)} CSV files to merge:")

    dfs = []
    for filename in sorted(csv_files):
        path = os.path.join(raw_dir, filename)
        print(f"  Loading {filename}...")
        df = pd.read_csv(path, low_memory=False)
        dfs.append(df)

    merged = pd.concat(dfs, ignore_index=True)
    print(f"\nTotal merged rows: {len(merged):,}")
    return merged


def clean_column_names(df):
   
    df.columns = [c.strip() for c in df.columns]
    return df


def build_feature_dataframe(df):
  
    result = pd.DataFrame()

   
    result["duration"] = df["Flow Duration"] / 1_000_000  
   
    result["packet_count"] = (
        df["Total Fwd Packets"] + df["Total Backward Packets"]
    )

    # byte_count - sum forward + backward bytes
    result["byte_count"] = (
        df["Total Length of Fwd Packets"] +
        df["Total Length of Bwd Packets"]
    )

    # packets_per_second - direct mapping
    result["packets_per_second"] = df["Flow Packets/s"]

    # bytes_per_second - direct mapping
    result["bytes_per_second"] = df["Flow Bytes/s"]

    # avg_packet_size - direct mapping
    result["avg_packet_size"] = df["Average Packet Size"]

    # flag counts - direct mapping
    result["syn_count"] = df["SYN Flag Count"]
    result["ack_count"] = df["ACK Flag Count"]
    result["fin_count"] = df["FIN Flag Count"]
    result["rst_count"] = df["RST Flag Count"]

    # destination port - direct mapping
    result["dst_port"] = df["Destination Port"]

    # derived ratios - computed the same way flow_engine.py does
    pkt_count_safe = result["packet_count"].replace(0, 1)
    # avoid division by zero
    result["syn_ratio"] = result["syn_count"] / pkt_count_safe
    result["rst_ratio"] = result["rst_count"] / pkt_count_safe

    # label - binary encoding
    # BENIGN -> 0, everything else -> 1
    result["label"] = df["Label"].apply(
        lambda x: 0 if str(x).strip().upper() == "BENIGN" else 1
    )

    return result


def clean_data(df):
    """
    Remove bad rows: infinity, NaN, negative durations.
    """
    before = len(df)

    # replace infinity with NaN so dropna catches them
    df = df.replace([np.inf, -np.inf], np.nan)

    # drop rows with any NaN
    df = df.dropna()

    # drop rows with negative or zero duration
    # (a flow with zero duration is a data artifact, not real)
    df = df[df["duration"] > 0]

    after = len(df)
    print(f"\nDropped {before - after:,} bad rows ({(before-after)/before:.2%})")
    print(f"Remaining rows: {after:,}")

    return df


def show_class_distribution(df):
    print(f"\nClass distribution:")
    print(df["label"].value_counts())
    attack_rate = df["label"].mean()
    print(f"Attack rate: {attack_rate:.2%}")


def normalize_and_split(df):
    """
    Scale features and split into train/test sets.
    """
    X = df[FEATURE_ORDER].values
    y = df["label"].values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y,
        test_size=0.2,
        random_state=42,
        stratify=y   # preserve class ratio in both splits
    )

    print(f"\nTraining set: {X_train.shape}")
    print(f"Test set:     {X_test.shape}")
    print(f"Train attack rate: {y_train.mean():.2%}")
    print(f"Test attack rate:  {y_test.mean():.2%}")

    return X_train, X_test, y_train, y_test, scaler


def save_processed(X_train, X_test, y_train, y_test, scaler):
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    np.save(os.path.join(PROCESSED_DIR, "X_train.npy"), X_train)
    np.save(os.path.join(PROCESSED_DIR, "X_test.npy"), X_test)
    np.save(os.path.join(PROCESSED_DIR, "y_train.npy"), y_train)
    np.save(os.path.join(PROCESSED_DIR, "y_test.npy"), y_test)
    joblib.dump(scaler, os.path.join(PROCESSED_DIR, "scaler.pkl"))

    print(f"\nSaved processed data to {PROCESSED_DIR}")
    print("Files created:")
    print("  X_train.npy, X_test.npy")
    print("  y_train.npy, y_test.npy")
    print("  scaler.pkl")


if __name__ == "__main__":
    print("=" * 60)
    print("CICIDS2017 Dataset Processing — Day 4")
    print("=" * 60)

    raw_df = load_all_csvs()
    raw_df = clean_column_names(raw_df)

    print("\nBuilding feature dataframe...")
    feature_df = build_feature_dataframe(raw_df)

    print("\nCleaning data...")
    feature_df = clean_data(feature_df)

    show_class_distribution(feature_df)

    print("\nNormalizing and splitting...")
    X_train, X_test, y_train, y_test, scaler = normalize_and_split(feature_df)

    save_processed(X_train, X_test, y_train, y_test, scaler)

    print("\n" + "=" * 60)
    print("Day 4 complete. Dataset ready for training.")
    print("=" * 60)
