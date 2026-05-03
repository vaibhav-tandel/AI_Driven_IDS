# realtime_ids.py
# Real-time IDS simulation with RandomForest + optional XGBoost

import pickle
import numpy as np
import time
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import MODEL_PATH, PREPARED_DATA_PATH

print("🛡️ Unified IDS Real-Time Monitoring\n")

# Load main model
try:
    with open(MODEL_PATH, "rb") as f:
        data = pickle.load(f)
    rf_model = data["model"]
    scaler = data["scaler"]
    le = data["label_encoder"]
    feature_names = data["feature_names"]
    print("✅ RandomForest model loaded")
except FileNotFoundError:
    print("❌ Model file not found! Run train_model.py first.")
    exit()

# Optional: Load XGBoost if exists
try:
    import xgboost as xgb
    xgb_model = xgb.XGBClassifier()
    xgb_model.load_model("xgb_model.json")
    use_xgb = True
    print("✅ XGBoost model loaded")
except Exception:
    xgb_model = None
    use_xgb = False
    print("ℹ️ XGBoost model not found. Only RandomForest will be used.")

# Load prepared data
try:
    with open(PREPARED_DATA_PATH, "rb") as f:
        pdata = pickle.load(f)
    X_test = pdata["X_test"]
    y_test = pdata["y_test"]
    print("✅ Test data loaded")
except FileNotFoundError:
    print("❌ Prepared data not found! Run prepare_data.py first.")
    exit()

print("="*60)

# --- User Inputs ---
num_packets = int(input("Enter number of packets to analyze: "))
delay = float(input("Enter delay between packets (seconds): "))
print(f"\n🚀 Starting analysis of {num_packets} flows...\n")

attacks_detected = 0
total_confidence = 0

for i in range(num_packets):
    idx = np.random.randint(0, len(X_test))
    features = X_test[idx].reshape(1, -1)
    true_label_idx = y_test[idx]
    true_label = le.inverse_transform([true_label_idx])[0]

    # RandomForest prediction
    rf_pred_idx = rf_model.predict(features)[0]
    rf_probs = rf_model.predict_proba(features)[0]
    rf_label = le.inverse_transform([rf_pred_idx])[0]
    rf_conf = rf_probs[rf_pred_idx] * 100

    # XGBoost prediction (if available)
    if use_xgb:
        xgb_pred_idx = xgb_model.predict(features)[0]
        xgb_probs = xgb_model.predict_proba(features)[0]
        xgb_label = le.inverse_transform([xgb_pred_idx])[0]
        xgb_conf = xgb_probs[xgb_pred_idx] * 100
    else:
        xgb_label, xgb_conf = None, None

    timestamp = time.strftime("%H:%M:%S")

    # Display RandomForest result
    if rf_label == "Benign":
        status = "✅ Normal Traffic"
    else:
        status = f"🚨 ALERT: {rf_label}"
        attacks_detected += 1
        total_confidence += rf_conf

    false_alarm = ""
    if rf_label != "Benign" and rf_label != true_label:
        false_alarm = " ⚠️ FALSE ALARM"

    print(f"[{timestamp}] {status} | Confidence: {rf_conf:.1f}%{false_alarm}")

    # Display XGBoost result (if available)
    if use_xgb:
        xgb_status = "✅ Normal Traffic" if xgb_label == "Benign" else f"🚨 ALERT: {xgb_label}"
        xgb_false_alarm = ""
        if xgb_label != "Benign" and xgb_label != true_label:
            xgb_false_alarm = " ⚠️ FALSE ALARM"
        print(f"[{timestamp}] [XGB] {xgb_status} | Confidence: {xgb_conf:.1f}%{xgb_false_alarm}")

    time.sleep(delay)

print("\n" + "="*60)
print("📊 SESSION SUMMARY")
print(f"Total Scanned: {num_packets}")
print(f"Attacks Detected (RF): {attacks_detected}")
if attacks_detected > 0:
    print(f"Avg Confidence (RF): {total_confidence/attacks_detected:.1f}%")
print("="*60)
