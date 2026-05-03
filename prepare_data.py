# prepare_data.py
# Split, Scale, and Balance CIC-IDS2017 dataset

import pandas as pd
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler, LabelEncoder
from imblearn.over_sampling import SMOTE

from config import SAMPLE_DATASET_PATH, PREPARED_DATA_PATH

print("🔧 Preparing data for training...")

df = pd.read_csv(SAMPLE_DATASET_PATH)

# Separate features and labels
X = df.drop("label", axis=1)
y = df["label"]

# === FIX: Ensure all feature columns are numeric ===
for col in X.columns:
    X[col] = pd.to_numeric(X[col], errors='coerce')

# Replace inf with NaN, then fill NaN with 0
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(0, inplace=True)

# Encode labels
le = LabelEncoder()
y_encoded = le.fit_transform(y)

# Split first (no leakage)
X_train_raw, X_test_raw, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

# Handle imbalance using SMOTE
print("⚖️ Applying SMOTE to balance classes...")
# === FIX: Limit k_neighbors so small classes (e.g. Heartbleed=11) don't crash ===
min_class_count = pd.Series(y_train).value_counts().min()
k_neighbors = min(5, max(1, min_class_count - 1))
print(f"   Smallest class in training set has {min_class_count} samples, using k_neighbors={k_neighbors}")
smote = SMOTE(random_state=42, k_neighbors=k_neighbors)
X_train_bal, y_train_bal = smote.fit_resample(X_train_raw, y_train)

# Scale features (RobustScaler is more stable for bursty outlier traffic)
scaler = RobustScaler()
X_train = scaler.fit_transform(X_train_bal)
X_test = scaler.transform(X_test_raw)

# Save prepared data
data = {
    "X_train": X_train,
    "X_test": X_test,
    "y_train": y_train_bal,
    "y_test": y_test,
    "label_encoder": le,
    "scaler": scaler,
    "feature_names": X.columns.tolist()
}

with open(PREPARED_DATA_PATH, "wb") as f:
    pickle.dump(data, f)

print(f"✅ Data prepared and saved to '{PREPARED_DATA_PATH}'")
print(f"   Training samples: {len(X_train)} | Test samples: {len(X_test)}")
print(f"   Features: {len(X.columns)} | Classes: {len(le.classes_)}")
