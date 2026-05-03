# feature_extractor.py — Converts flows to model-ready feature vectors
import pickle
import numpy as np
import pandas as pd
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import MODEL_PATH

# The exact feature order expected by the trained model (81 features, no label)
FEATURE_COLUMNS = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s",
    "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
    "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags",
    "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length",
    "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
    "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std",
    "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    "total_bytes", "total_packets", "bytes_per_packet", "packets_per_duration"
]


class FeatureExtractor:
    """
    Extracts features from completed Flow objects and transforms
    them using the same scaler the model was trained with.
    """

    def __init__(self, model_path=None):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_columns = list(FEATURE_COLUMNS)
        self._loaded = False
        self._model_path = model_path or MODEL_PATH

    def load_model(self):
        """Load the trained model, scaler, and label encoder."""
        if self._loaded:
            return True
        try:
            print(f"📦 Loading model from {self._model_path}...")
            with open(self._model_path, "rb") as f:
                data = pickle.load(f)
            self.model = data["model"]
            self.scaler = data["scaler"]
            self.label_encoder = data["label_encoder"]
            model_columns = data.get("feature_columns") or data.get("feature_names")
            if model_columns:
                self.feature_columns = list(model_columns)
            self._loaded = True
            print(f"✅ Model loaded — {len(self.label_encoder.classes_)} classes: "
                  f"{list(self.label_encoder.classes_)}")
            print(f"   Using {len(self.feature_columns)} feature columns for inference")
            return True
        except FileNotFoundError:
            print(f"❌ Model file not found: {self._model_path}")
            return False
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return False

    def extract_and_predict(self, flow):
        """
        Extract features from a Flow object, scale them, and predict.
        Returns: (predicted_label, confidence, all_probabilities)
        """
        if not self._loaded:
            if not self.load_model():
                return "Unknown", 0.0, {}

        # Get feature dict from flow
        feat_dict = flow.to_feature_dict()

        # Build feature vector in the correct order as a DataFrame
        # (using DataFrame with column names avoids sklearn warnings
        #  about feature names mismatch with the fitted scaler)
        feature_values = [feat_dict.get(col, 0.0) for col in self.feature_columns]
        feature_df = pd.DataFrame([feature_values], columns=self.feature_columns)

        # Replace inf/nan
        feature_df.replace([np.inf, -np.inf], 0.0, inplace=True)
        feature_df.fillna(0.0, inplace=True)

        # Scale
        feature_scaled = self.scaler.transform(feature_df)

        # Predict
        pred_idx = self.model.predict(feature_scaled)[0]
        proba = self.model.predict_proba(feature_scaled)[0]

        label = self.label_encoder.inverse_transform([pred_idx])[0]
        confidence = float(proba[pred_idx]) * 100

        # Build probability dict
        prob_dict = {
            self.label_encoder.inverse_transform([i])[0]: float(p) * 100
            for i, p in enumerate(proba)
        }

        return label, confidence, prob_dict

    def get_classes(self):
        """Return list of possible prediction classes."""
        if self._loaded:
            return list(self.label_encoder.classes_)
        return []
