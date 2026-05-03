# config.py — Central configuration for Real-Time AI IDS
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Data Directories ──
DATA_DIR = os.path.join(BASE_DIR, "data")
RAW_DATA_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DATA_DIR = os.path.join(DATA_DIR, "processed")

# ── Processed Data Files ──
SAMPLE_DATASET_PATH = os.path.join(PROCESSED_DATA_DIR, "sample_dataset.csv")
PREPARED_DATA_PATH = os.path.join(PROCESSED_DATA_DIR, "prepared_data.pkl")

# ── Model ──
MODEL_PATH = os.path.join(PROCESSED_DATA_DIR, "unified_ids_model.pkl")
FALLBACK_MODEL_PATH = r"D:\CODESSS\6IT\SGP-III\phase 4\data\processed\unified_ids_model.pkl"

def resolve_model_path(model_path=None):
	"""Resolve model path with optional explicit path and safe fallback."""
	candidate = model_path or os.getenv("IDS_MODEL_PATH") or MODEL_PATH
	if os.path.exists(candidate):
		return candidate
	if os.path.exists(FALLBACK_MODEL_PATH):
		return FALLBACK_MODEL_PATH
	return candidate

# ── Database ──
DB_PATH = os.path.join(BASE_DIR, "ids_data.db")

# ── Logging ──
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "ids_alerts.log")

# ── Flow Aggregation ──
FLOW_TIMEOUT = 300          # seconds of inactivity before a flow is considered complete
FLOW_CHECK_INTERVAL = 10    # seconds between flow timeout checks
FLOW_EARLY_PACKET_THRESHOLD = 10
FLOW_EARLY_WINDOW_SECONDS = 2.0
FLOW_SYN_ONLY_INACTIVITY_SECONDS = 5.0
FLOW_IDLE_TIMEOUT = 60       # seconds idle timeout (paper-aligned)

# ── Temporal Window Detection ──
SLIDING_WINDOW_SECONDS = 60
PORTSCAN_WINDOW_SECONDS = 10
PORTSCAN_UNIQUE_PORTS_THRESHOLD = 15
NMAP_SYN_WINDOW_SECONDS = 5
NMAP_SYN_THRESHOLD = 100
NMAP_ACK_MAX_THRESHOLD = 10
DDOS_WINDOW_SECONDS = 10
DDOS_PACKET_RATE_THRESHOLD = 500
DDOS_UNIQUE_SRC_THRESHOLD = 50
SLOW_HTTP_ACTIVE_CONN_THRESHOLD = 50
SLOW_HTTP_LOW_BYTES_THRESHOLD = 200
MIN_PACKETS_FOR_CLASSIFICATION = 3

# ── Cost-sensitive thresholding ──
NORMAL_PROB_THRESHOLD = 0.70
ATTACK_PROB_THRESHOLD = 0.30

# ── Inference behavior ──
ENABLE_RULE_ENGINE = True
ENABLE_TEMPORAL_ENGINE = True
PREFER_HYBRID_DECISIONS = True

# ── Alert policy ──
DETECTION_DEDUP_SECONDS = 30
DEFAULT_ALERT_CONFIDENCE_RULE = 0.95

# ── Whitelist ──
WHITELIST_IPS = [
	"127.0.0.1",
	"::1",
]
WHITELIST_CIDRS = [
	"127.0.0.0/8",
	"::1/128",
]

# ── Alert Deduplication ──
ALERT_COOLDOWN_SECONDS = 30

# ── Simulation ──
SIMULATION_PACKET_DELAY = 0.05   # seconds between simulated packets
SIMULATION_BATCH_SIZE = 5         # packets per simulation burst

# ── psutil Monitor ──
PSUTIL_POLL_INTERVAL = 0.5       # seconds between connection polls
PSUTIL_MIN_CONNECTIONS = 2       # minimum connections to form a flow

# ── Email Alerts (optional) ──
EMAIL_ENABLED = False
EMAIL_SMTP_SERVER = "smtp.gmail.com"
EMAIL_SMTP_PORT = 587
EMAIL_SENDER = ""
EMAIL_PASSWORD = ""
EMAIL_RECIPIENT = ""

# ── GeoIP ──
GEOIP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp"
GEOIP_CACHE_SIZE = 1000
GEOIP_TIMEOUT = 3  # seconds

# ── Dashboard ──
DASHBOARD_REFRESH_SECS = 3
MAX_ALERTS_DISPLAY = 200
