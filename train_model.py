# train_model.py
# Train IDS model with RandomForest (and optionally XGBoost)

import pickle
import os
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

from config import PREPARED_DATA_PATH, MODEL_PATH, PROCESSED_DATA_DIR

# Optional: XGBoost
try:
    from xgboost import XGBClassifier
    xgboost_available = True
except ImportError:
    xgboost_available = False

print("🤖 Training IDS model...")

# Load data
with open(PREPARED_DATA_PATH, "rb") as f:
    data = pickle.load(f)

X_train = data["X_train"]
X_test = data["X_test"]
y_train = data["y_train"]
y_test = data["y_test"]
le = data["label_encoder"]
feature_names = data["feature_names"]
scaler = data["scaler"]
feature_columns = X_train.columns.tolist() if hasattr(X_train, "columns") else list(feature_names)

# -------- RandomForest --------
rf_model = RandomForestClassifier(
    n_estimators=85,
    max_depth=23,
    min_samples_split=5,
    min_samples_leaf=1,
    max_features=0.5866,
    bootstrap=False,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)
rf_model.fit(X_train, y_train)
print("✅ RandomForest trained")

# -------- Optional XGBoost --------
if xgboost_available:
    xgb_model = XGBClassifier(n_estimators=200, use_label_encoder=False, eval_metric="mlogloss", random_state=42)
    xgb_model.fit(X_train, y_train)
    print("✅ XGBoost trained")
else:
    xgb_model = None

# -------- Evaluation --------
def evaluate(model, X_test, y_test, name="Model"):
    y_pred = model.predict(X_test)
    print(f"\n📊 {name} Classification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(10,8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=le.classes_, yticklabels=le.classes_)
    plt.title(f"{name} Confusion Matrix")
    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    cm_path = os.path.join(PROCESSED_DATA_DIR, f"{name.lower().replace(' ','_')}_confusion_matrix.png")
    plt.savefig(cm_path)
    print(f"✅ {name} confusion matrix saved to {cm_path}")

evaluate(rf_model, X_test, y_test, "RandomForest")
if xgb_model:
    evaluate(xgb_model, X_test, y_test, "XGBoost")

# Save RandomForest as main model
model_data = {
    "model": rf_model,
    "scaler": scaler,
    "label_encoder": le,
    "feature_names": feature_names,
    "feature_columns": feature_columns,
}
with open(MODEL_PATH, "wb") as f:
    pickle.dump(model_data, f)
print(f"💾 RandomForest model saved as '{MODEL_PATH}'")
