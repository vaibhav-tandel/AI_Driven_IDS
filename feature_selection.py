# feature_selection.py
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
import numpy as np

from config import PREPARED_DATA_PATH, PROCESSED_DATA_DIR

with open(PREPARED_DATA_PATH, "rb") as f:
    data = pickle.load(f)

X_train = data["X_train"]
y_train = data["y_train"]
feature_names = data["feature_names"]

# Train RF to get feature importance
rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)

importances = rf.feature_importances_
indices = np.argsort(importances)[::-1]

top_features = [feature_names[i] for i in indices[:20]]  # Top 20 features
print("✅ Top features selected:", top_features)

selector_path = os.path.join(PROCESSED_DATA_DIR, "feature_selector.pkl")
with open(selector_path, "wb") as f:
    pickle.dump(top_features, f)
print(f"💾 Feature selector saved to '{selector_path}'")
