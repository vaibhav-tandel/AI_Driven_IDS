# db.py — SQLite persistence for IDS alerts and stats
import sqlite3
import threading
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DB_PATH


class IDSDatabase:
    """Thread-safe SQLite database for storing IDS alerts and traffic statistics."""

    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH
        self._local = threading.local()
        self._init_db()

    def _get_conn(self):
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                attack_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                severity TEXT,
                detection_method TEXT,
                is_false_alarm INTEGER DEFAULT 0,
                geo_country TEXT,
                geo_city TEXT,
                geo_lat REAL,
                geo_lon REAL,
                geo_isp TEXT,
                flow_duration REAL,
                total_packets INTEGER,
                total_bytes INTEGER,
                packet_count INTEGER,
                byte_count INTEGER
            );

            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_flows INTEGER DEFAULT 0,
                normal_flows INTEGER DEFAULT 0,
                attack_flows INTEGER DEFAULT 0,
                false_alarms INTEGER DEFAULT 0,
                avg_confidence REAL DEFAULT 0.0
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_attack ON alerts(attack_type);
            CREATE INDEX IF NOT EXISTS idx_alerts_src_attack ON alerts(src_ip, attack_type, timestamp);
            CREATE INDEX IF NOT EXISTS idx_stats_timestamp ON traffic_stats(timestamp);
        """)
        self._ensure_alert_columns(conn)
        conn.commit()

    def _ensure_alert_columns(self, conn):
        """Best-effort schema evolution for existing local databases."""
        existing = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
        }
        needed = {
            "detection_method": "TEXT",
            "packet_count": "INTEGER",
            "byte_count": "INTEGER",
        }
        for col, col_type in needed.items():
            if col not in existing:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {col_type}")

    # ── Insert Operations ──

    def insert_alert(self, alert_data: dict):
        conn = self._get_conn()
        payload = dict(alert_data)
        payload.setdefault("timestamp", 0.0)
        payload.setdefault("detection_method", "ml")
        payload.setdefault("packet_count", payload.get("total_packets", 0))
        payload.setdefault("byte_count", payload.get("total_bytes", 0))
        payload.setdefault("is_false_alarm", 0)
        conn.execute("""
            INSERT INTO alerts (timestamp, src_ip, dst_ip, src_port, dst_port,
                protocol, attack_type, confidence, severity, detection_method, is_false_alarm,
                geo_country, geo_city, geo_lat, geo_lon, geo_isp,
                flow_duration, total_packets, total_bytes, packet_count, byte_count)
            VALUES (:timestamp, :src_ip, :dst_ip, :src_port, :dst_port,
                :protocol, :attack_type, :confidence, :severity, :detection_method, :is_false_alarm,
                :geo_country, :geo_city, :geo_lat, :geo_lon, :geo_isp,
                :flow_duration, :total_packets, :total_bytes, :packet_count, :byte_count)
        """, payload)
        conn.commit()

    def insert_traffic_stat(self, stat_data: dict):
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO traffic_stats (timestamp, total_flows, normal_flows,
                attack_flows, false_alarms, avg_confidence)
            VALUES (:timestamp, :total_flows, :normal_flows,
                :attack_flows, :false_alarms, :avg_confidence)
        """, stat_data)
        conn.commit()

    # ── Query Operations ──

    def get_recent_alerts(self, limit=100):
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_alert_counts(self):
        conn = self._get_conn()
        row = conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN attack_type = 'Benign' THEN 1 ELSE 0 END) as normal,
                SUM(CASE WHEN attack_type != 'Benign' THEN 1 ELSE 0 END) as attacks,
                SUM(is_false_alarm) as false_alarms,
                AVG(CASE WHEN attack_type != 'Benign' THEN confidence ELSE NULL END) as avg_conf
            FROM alerts
        """).fetchone()
        return dict(row)

    def get_recent_packet_rate(self, seconds=60):
        """Return per-second packet counts over the recent time window."""
        conn = self._get_conn()
        now = int(__import__("time").time())
        lower = max(0, now - int(seconds))
        rows = conn.execute("""
            SELECT CAST(timestamp AS INTEGER) AS ts_sec,
                   SUM(COALESCE(packet_count, total_packets, 0)) AS packets
            FROM alerts
            WHERE timestamp >= ?
            GROUP BY CAST(timestamp AS INTEGER)
            ORDER BY ts_sec ASC
        """, (lower,)).fetchall()
        points = {int(r["ts_sec"]): int(r["packets"] or 0) for r in rows}
        timeline = []
        for ts in range(lower, now + 1):
            timeline.append({"timestamp": ts, "packets": points.get(ts, 0)})
        return timeline

    def get_attack_distribution(self):
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM alerts WHERE attack_type != 'Benign'
            GROUP BY attack_type ORDER BY count DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def get_geo_data(self):
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT geo_country, geo_city, geo_lat, geo_lon, COUNT(*) as count
            FROM alerts
            WHERE attack_type != 'Benign' AND geo_lat IS NOT NULL
            GROUP BY geo_country, geo_city
            ORDER BY count DESC LIMIT 50
        """).fetchall()
        return [dict(r) for r in rows]

    def get_top_attackers(self, limit=10):
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT src_ip, COUNT(*) as count,
                GROUP_CONCAT(DISTINCT attack_type) as attack_types,
                AVG(confidence) as avg_confidence
            FROM alerts WHERE attack_type != 'Benign'
            GROUP BY src_ip ORDER BY count DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_traffic_timeline(self, limit=100):
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT timestamp, total_flows, normal_flows, attack_flows
            FROM traffic_stats ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in reversed(rows)]

    def get_alerts_timeline(self, limit=200):
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT timestamp, attack_type, confidence
            FROM alerts ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in reversed(rows)]

    def clear_all(self):
        conn = self._get_conn()
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM traffic_stats")
        conn.commit()
