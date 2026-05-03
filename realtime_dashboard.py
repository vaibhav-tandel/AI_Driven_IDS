# realtime_dashboard.py
# Real-time IDS dashboard simulation

import pickle
import os
import sys
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import MODEL_PATH, PREPARED_DATA_PATH

# ---------------- Load Models ----------------
with open(MODEL_PATH, "rb") as f:
    data = pickle.load(f)

rf_model = data["model"]
scaler = data["scaler"]
le = data["label_encoder"]

# Load prepared test data
with open(PREPARED_DATA_PATH, "rb") as f:
    pdata = pickle.load(f)

X_test = pdata["X_test"]
y_test = pdata["y_test"]

# ---------------- Metrics ----------------
total_scanned = 0
attacks_detected = 0
false_alarms = 0
confidence_list = []

# ---------------- Styles ----------------
try:
    import seaborn as sns
    sns.set_style("darkgrid")
except ImportError:
    plt.style.use("ggplot")  # fallback style if seaborn not installed

# ---------------- Dashboard Setup ----------------
fig, ax = plt.subplots(figsize=(8,6))
bars = ax.bar(["Normal","Attack","False Alarm"], [0,0,0], color=["green","red","orange"])
ax.set_ylim(0, 10)
ax.set_ylabel("Count")
ax.set_title("Real-Time IDS Dashboard")
txt = ax.text(0.5, 0.9, "", transform=ax.transAxes, ha="center")

# ---------------- Simulation Function ----------------
def update(frame):
    global total_scanned, attacks_detected, false_alarms, confidence_list

    # Randomly pick a flow from test set
    idx = np.random.randint(0, len(X_test))
    features = X_test[idx].reshape(1,-1)
    true_label_idx = y_test[idx]
    true_label = le.inverse_transform([true_label_idx])[0]

    # RandomForest prediction
    pred_idx = rf_model.predict(features)[0]
    pred_label = le.inverse_transform([pred_idx])[0]
    confidence = rf_model.predict_proba(features)[0][pred_idx] * 100

    total_scanned += 1

    if pred_label != "Benign":
        attacks_detected += 1
        confidence_list.append(confidence)
        if pred_label != true_label:
            false_alarms += 1

    # Update bars
    bars[0].set_height(total_scanned - attacks_detected)
    bars[1].set_height(attacks_detected)
    bars[2].set_height(false_alarms)

    # Update text with average confidence
    avg_conf = np.mean(confidence_list) if confidence_list else 0
    txt.set_text(f"Total: {total_scanned} | Avg Confidence: {avg_conf:.1f}%")

# ---------------- Animation ----------------
anim = FuncAnimation(fig, update, interval=500)  # Update every 0.5 sec
plt.show()
