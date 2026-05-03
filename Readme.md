# AI-Powered Real-Time Intrusion Detection System 

An end-to-end, real-time IDS that converts live network activity into alerts within seconds. It trains on CIC-IDS2017, extracts 81 flow features, and uses a hybrid ML + rules + temporal engine. Alerts are persisted to SQLite and visualized in a Streamlit dashboard.

## Highlights

- Hybrid detection: RandomForest predictions reinforced by rules and temporal heuristics
- Real-time flow analytics: 81 CIC-IDS2017 features with early flow emission for fast attacks
- Multi-mode capture: Scapy (live), psutil (no admin), simulation (demo), and PCAP replay
- Low-noise alerts: confidence thresholds, severity scoring, and cooldown-based deduplication
- Full visibility: SQLite persistence, GeoIP enrichment, and a live Streamlit dashboard

## System pipeline

1. Packet capture (Scapy / psutil / simulation / PCAP)
2. Flow aggregation (5-tuple flows, early emission for scans and bursts)
3. Feature extraction (81 CIC-IDS2017 flow features)
4. ML prediction + rule engine + temporal heuristics
5. Alert logging, SQLite persistence, and dashboard analytics

## Requirements

- Python 3.8+
- Windows: Npcap required for Scapy live capture
- Optional: Scapy for full packet capture; psutil mode works without admin

## Quick start (demo)

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
python setup_and_run.py --dashboard
```

## Run modes

```powershell
# Auto-detect best mode
python run_ids.py --mode auto --duration 120

# psutil (no admin)
python run_ids.py --mode psutil --duration 120

# Scapy live capture (admin + Npcap)
python run_ids.py --mode scapy --iface "Wi-Fi" --duration 120

# Simulation (demo)
python run_ids.py --mode simulation --duration 60

# PCAP replay (Scapy required)
python run_ids.py --mode pcap --pcap path\to\file.pcap
```

## Train the model (one-time)

Place CIC-IDS2017 CSV files in data/raw/ and run:

```powershell
python data_processing.py
python prepare_data.py
python train_model.py
```

## Dashboard

```powershell
python -m streamlit run dashboard/app.py
```

## Outputs

- logs/ids_alerts.log (alert log)
- ids_data.db (SQLite alerts and traffic stats)
- data/processed/unified_ids_model.pkl (trained model bundle)
- data/processed/prepared_data.pkl (train/test splits + scaler + encoder)

## Configuration

Key settings live in config.py, including timeouts, thresholds, and dashboard refresh. You can also override the model path with the IDS_MODEL_PATH environment variable.

## Tests

```powershell
python test_system.py
```

## Project layout (high level)

- data_processing.py, prepare_data.py, train_model.py: training pipeline
- run_ids.py, setup_and_run.py: CLI entry points
- realtime/: packet capture, flow aggregation, feature extraction, rules, DB
- dashboard/: Streamlit UI

## Notes on data and privacy

Raw datasets, processed data, local logs, and database files are typically excluded from version control. Logs can contain IP addresses and other network metadata.

## Tech stack

Python, scikit-learn, pandas, numpy, imbalanced-learn (SMOTE), psutil, optional Scapy, Streamlit, Plotly, SQLite
