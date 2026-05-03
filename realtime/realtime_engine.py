# realtime_engine.py — Main IDS Engine orchestrating all components
import time
import threading
import os
import sys
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from realtime.packet_capture import PacketCapture, detect_best_mode
from realtime.flow_aggregator import FlowAggregator
from realtime.feature_extractor import FeatureExtractor
from realtime.alert_system import AlertSystem, get_severity
from realtime.geoip_lookup import GeoIPLookup
from realtime.db import IDSDatabase
from realtime.detection_policy import (
    HostTemporalState,
    WhitelistMatcher,
    apply_cost_sensitive_threshold,
    evaluate_temporal_rules,
)
import config as cfg
from config import (
    FLOW_TIMEOUT,
    FLOW_EARLY_PACKET_THRESHOLD,
    FLOW_EARLY_WINDOW_SECONDS,
    FLOW_SYN_ONLY_INACTIVITY_SECONDS,
)


class RealtimeIDSEngine:
    """
    Main orchestrator for the AI-powered real-time IDS.

    Modes:
        - auto:       Auto-detect best capture method (Scapy → psutil → simulation)
        - scapy:      Full packet capture via Scapy (admin/Npcap required)
        - psutil:     Connection-level monitoring via psutil (no admin required)
        - live:       Legacy alias → scapy or psutil
        - simulation: Generates synthetic traffic (demo only)

    Architecture:
        PacketCapture → FlowAggregator → FeatureExtractor → Model → AlertSystem + DB
    """

    # Simulated attack profiles for demo mode (when model marks everything benign)
    _SIM_ATTACKS = [
        ("DDoS",           85, 99),
        ("DoS Hulk",       80, 97),
        ("DoS GoldenEye",  78, 95),
        ("DoS Slowloris",  70, 90),
        ("PortScan",       65, 92),
        ("Bot",            72, 94),
        ("FTP-Patator",    68, 88),
        ("SSH-Patator",    66, 86),
        ("Web Attack",     60, 85),
        ("Heartbleed",     75, 96),
        ("Infiltration",   62, 84),
    ]

    _LABEL_NORMALIZATION = {
        "DoS slowloris": "DoS Slowloris",
        "DoS Slowhttptest": "DoS Slowloris",
        "Web Attack - Brute Force": "Web Attack",
        "Web Attack - Sql Injection": "Web Attack",
        "Web Attack - XSS": "Web Attack",
        "Web Attack \xa0 Brute Force": "Web Attack",
        "Web Attack \xa0 Sql Injection": "Web Attack",
        "Web Attack \xa0 XSS": "Web Attack",
        "Web Attack ï¿½ Brute Force": "Web Attack",
        "Web Attack ï¿½ Sql Injection": "Web Attack",
        "Web Attack ï¿½ XSS": "Web Attack",
    }

    @classmethod
    def _normalize_label(cls, label):
        return cls._LABEL_NORMALIZATION.get(str(label), str(label))

    def __init__(self, mode="auto", interface=None, model_path=None, pcap_file=None,
                 flow_timeout=None, on_alert=None, on_flow=None):
        self.mode = mode
        self._running = False
        self._stopped = False
        self._on_alert = on_alert    # optional callback(alert_dict)
        self._on_flow = on_flow      # optional callback(flow_result_dict)

        # Initialize capture — PacketCapture handles mode resolution internally
        self.capture = PacketCapture(
            interface=interface,
            mode=mode,
            pcap_file=pcap_file,
        )
        # Store the resolved mode (after auto-detection / fallback)
        self.resolved_mode = self.capture.mode

        self.aggregator = FlowAggregator(
            timeout=flow_timeout or FLOW_TIMEOUT,
            min_packets=max(1, int(getattr(cfg, "MIN_PACKETS_FOR_CLASSIFICATION", 3))),
            early_packet_threshold=FLOW_EARLY_PACKET_THRESHOLD,
            early_window_seconds=FLOW_EARLY_WINDOW_SECONDS,
            syn_inactivity_seconds=FLOW_SYN_ONLY_INACTIVITY_SECONDS,
        )
        resolved_model_path = cfg.resolve_model_path(model_path)
        self.extractor = FeatureExtractor(model_path=resolved_model_path)
        self.alert_system = AlertSystem()
        self.geoip = GeoIPLookup()
        self.db = IDSDatabase()
        self.temporal_state = HostTemporalState(window_seconds=getattr(cfg, "SLIDING_WINDOW_SECONDS", 60))
        self.whitelist = WhitelistMatcher(
            whitelist_ips=getattr(cfg, "WHITELIST_IPS", []),
            whitelist_cidrs=getattr(cfg, "WHITELIST_CIDRS", []),
        )
        self._flow_key_cooldown = defaultdict(float)
        self._dedup_seconds = float(getattr(cfg, "DETECTION_DEDUP_SECONDS", 30))

        # Stats
        self.stats = {
            "total_flows": 0,
            "normal_flows": 0,
            "attack_flows": 0,
            "false_alarms": 0,
            "packets_processed": 0,
            "start_time": None,
            "capture_mode": self.resolved_mode,
        }
        self._stats_lock = threading.Lock()
        self._packet_buffer_count = 0
        self._psutil_behavior_window_seconds = 6.0
        self._psutil_scan_unique_ports_threshold = 14
        self._psutil_burst_flow_threshold = 35
        self._psutil_burst_packets_threshold = 90
        self._recent_psutil_flows = []
        self._recent_psutil_conn_seen = {}
        self._psutil_behavior_last_trigger = {}
        self._psutil_behavior_cooldown_seconds = 12.0
        self._psutil_conn_dedupe_seconds = 1.25
        self._psutil_ddos_ports = {80, 443, 8080, 8443}
        self._behavior_lock = threading.Lock()

    def _psutil_behavior_check(self, flow):
        """Cross-flow heuristics for psutil mode where packet flags are limited."""
        if self.resolved_mode != "psutil" or flow.protocol != "TCP":
            return None, None, None

        now = time.time()
        src_port = int(flow.src_port or 0)
        dst_port = int(flow.dst_port or 0)
        # In psutil-derived flows, endpoint roles can vary by connection direction.
        # Use the lower port as a stable service/target port representation.
        service_port = min([p for p in (src_port, dst_port) if p > 0], default=0)
        peer_ip = flow.dst_ip
        event = {
            "t": now,
            "src": flow.src_ip,
            "peer": peer_ip,
            "service_port": service_port,
            "src_port": src_port,
            "dst_port": dst_port,
            "pkts": int(flow.total_pkts or 0),
        }

        with self._behavior_lock:
            conn_sig = (flow.src_ip, peer_ip, src_port, dst_port, flow.protocol)
            last_seen = self._recent_psutil_conn_seen.get(conn_sig, 0.0)
            if (now - last_seen) < self._psutil_conn_dedupe_seconds:
                return None, None, None

            self._recent_psutil_conn_seen[conn_sig] = now
            self._recent_psutil_flows.append(event)
            cutoff = now - self._psutil_behavior_window_seconds
            self._recent_psutil_flows = [e for e in self._recent_psutil_flows if e["t"] >= cutoff]
            self._recent_psutil_conn_seen = {
                k: ts for k, ts in self._recent_psutil_conn_seen.items() if ts >= cutoff
            }

            src_events = [
                e for e in self._recent_psutil_flows
                if e["src"] == flow.src_ip and e["peer"] == peer_ip
            ]

        # Port-scan style: many distinct destination ports in a short window.
        unique_ports = {e["service_port"] for e in src_events if e["service_port"] > 0}
        if len(unique_ports) >= self._psutil_scan_unique_ports_threshold:
            trigger_key = (flow.src_ip, peer_ip, "PortScan")
            last_trigger = self._psutil_behavior_last_trigger.get(trigger_key, 0.0)
            if (now - last_trigger) >= self._psutil_behavior_cooldown_seconds:
                self._psutil_behavior_last_trigger[trigger_key] = now
                confidence = min(96.0, 82.0 + (len(unique_ports) - self._psutil_scan_unique_ports_threshold) * 0.7)
                return "PortScan", "HIGH", confidence
            return None, None, None

        # Burst/flood style: many flows to the same service in a short window.
        same_service_events = [e for e in src_events if e["service_port"] == service_port and service_port > 0]
        flow_count = len(same_service_events)
        packet_sum = sum(e["pkts"] for e in same_service_events)
        if (
            service_port in self._psutil_ddos_ports
            and flow_count >= self._psutil_burst_flow_threshold
            and packet_sum >= self._psutil_burst_packets_threshold
        ):
            trigger_key = (flow.src_ip, peer_ip, service_port, "DDoS")
            last_trigger = self._psutil_behavior_last_trigger.get(trigger_key, 0.0)
            if (now - last_trigger) >= self._psutil_behavior_cooldown_seconds:
                self._psutil_behavior_last_trigger[trigger_key] = now
                confidence = min(97.0, 84.0 + (flow_count - self._psutil_burst_flow_threshold) * 0.25)
                return "DDoS", "CRITICAL", confidence

        return None, None, None

    def _rule_based_check(self, flow):
        """Simple real-time heuristics to complement ML for scan-heavy traffic."""
        duration = max(flow.duration, 1e-3)
        pps = flow.total_pkts / duration

        # Port scan-like behavior: many SYNs, no payload-style progression.
        if (
            flow.protocol == "TCP"
            and flow.total_pkts >= 3
            and flow.syn_count >= 5
            and flow.psh_count == 0
            and flow.ack_count <= 1
        ):
            return "PortScan", "HIGH", 92.0

        # In psutil mode, only escalate to DDoS with stronger evidence.
        # psutil synthesizes packet events from connection snapshots, so
        # very short flows can inflate packets/sec and cause false positives.
        if self.resolved_mode == "psutil":
            strong_volume = flow.total_pkts >= 20 and duration >= 1.0
            tcp_flood_pattern = flow.protocol == "TCP" and (flow.syn_count >= 10 or flow.psh_count >= 10)
            if strong_volume and tcp_flood_pattern and pps > 1500:
                confidence = min(97.0, 80.0 + min(17.0, pps / 250.0))
                return "DDoS", "CRITICAL", confidence
        else:
            # For raw packet capture (Scapy), keep a lower threshold.
            if flow.total_pkts >= 10 and pps > 1200:
                confidence = min(98.0, 82.0 + min(16.0, pps / 300.0))
                return "DDoS", "CRITICAL", confidence

        return None, None, None

    def start(self, blocking=True):
        """Start the IDS engine."""
        self._running = True
        self.stats["start_time"] = time.time()

        mode_labels = {
            "scapy": "🔴 LIVE SCAPY CAPTURE",
            "psutil": "🟡 REAL-TIME PSUTIL MONITOR",
            "simulation": "🟢 SIMULATION",
        }
        mode_label = mode_labels.get(self.resolved_mode, self.resolved_mode.upper())

        print("\n" + "=" * 60)
        print("🛡️  AI-POWERED INTRUSION DETECTION SYSTEM")
        print(f"   Mode: {mode_label}")
        if self.mode == "auto":
            print(f"   (auto-detected from: scapy → psutil → simulation)")
        print("=" * 60 + "\n")

        # Load model
        if not self.extractor.load_model():
            print("⚠️  Model not loaded. Running in demo mode (random predictions).")

        # Start periodic flow emission for simulation and psutil modes
        # (psutil connections need forced emission since they aren't raw packets)
        if self.resolved_mode in ("simulation", "psutil"):
            self._start_flow_emitter()

        # Start periodic stats writer
        self._start_stats_writer()

        # Start capture
        self.capture.start(self._on_packet, blocking=blocking)

    def stop(self):
        """Stop the IDS engine (idempotent — safe to call multiple times)."""
        if self._stopped:
            return
        self._stopped = True
        self._running = False
        self.capture.stop()

        # Wait a moment for any pending packets
        time.sleep(0.5)

        # Process ALL remaining flows (flush everything)
        remaining = self.aggregator.flush_all()
        for flow in remaining:
            self._classify_flow(flow)

        # Log summary
        self.alert_system.log_session_summary(self.stats)
        self._print_summary()

    def _on_packet(self, packet):
        """Callback when a packet is captured."""
        with self._stats_lock:
            self.stats["packets_processed"] += 1
            self._packet_buffer_count += 1

        # Add packet to flow aggregator — returns completed flows
        completed = self.aggregator.process_packet(packet)
        for flow in completed:
            self._classify_flow(flow)

    def _classify_flow(self, flow):
        """Classify a completed flow using the ML model."""
        import random
        now = time.time()
        timestamp_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if self.whitelist.contains(flow.src_ip) or self.whitelist.contains(flow.dst_ip):
            return

        if flow.total_pkts < max(1, int(getattr(cfg, "MIN_PACKETS_FOR_CLASSIFICATION", 3))):
            return

        dedup_key = (flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol)
        if now - self._flow_key_cooldown.get(dedup_key, 0.0) < self._dedup_seconds / 3.0:
            return
        self._flow_key_cooldown[dedup_key] = now

        # Extract features and predict
        if self.extractor._loaded:
            label, confidence, proba = self.extractor.extract_and_predict(flow)
            label = self._normalize_label(label)
            if proba:
                proba = {self._normalize_label(k): v for k, v in proba.items()}
        else:
            # Demo mode without model: random prediction
            labels = ["Benign", "DDoS", "PortScan", "DoS Hulk", "Bot",
                      "FTP-Patator", "SSH-Patator", "Web Attack"]
            weights = [70, 8, 5, 5, 3, 3, 3, 3]
            label = random.choices(labels, weights=weights)[0]
            confidence = random.uniform(60, 99)
            proba = {}

        if proba:
            label, confidence = apply_cost_sensitive_threshold(
                label=label,
                confidence_pct=confidence,
                probabilities=proba,
                normal_threshold=float(getattr(cfg, "NORMAL_PROB_THRESHOLD", 0.70)),
                attack_threshold=float(getattr(cfg, "ATTACK_PROB_THRESHOLD", 0.30)),
            )

        # ONLY inject fake attacks in SIMULATION mode.
        # In live/psutil mode, trust the model's real predictions.
        if self.resolved_mode == "simulation" and label == "Benign" and random.random() < 0.25:
            attack_type, conf_lo, conf_hi = random.choice(self._SIM_ATTACKS)
            label = attack_type
            confidence = random.uniform(conf_lo, conf_hi)
            proba = {}

        # Rule-based override layer to improve scan detection latency/coverage.
        self.temporal_state.add_flow(flow, now=now)
        temporal_decision = None
        if getattr(cfg, "ENABLE_TEMPORAL_ENGINE", True):
            temporal_decision = evaluate_temporal_rules(flow, self.temporal_state, cfg)

        rb_label, rb_severity, rb_confidence = None, None, None
        if getattr(cfg, "ENABLE_RULE_ENGINE", True):
            rb_label, rb_severity, rb_confidence = self._psutil_behavior_check(flow)
            if not rb_label:
                rb_label, rb_severity, rb_confidence = self._rule_based_check(flow)

        if temporal_decision:
            rb_label = temporal_decision.attack_type
            rb_severity = temporal_decision.severity
            rb_confidence = max(float(rb_confidence or 0.0), float(temporal_decision.confidence))

        if self.resolved_mode == "simulation" and rb_label == "DDoS":
            rb_label, rb_severity, rb_confidence = None, None, None

        detection_method = "ml"
        if rb_label:
            is_psutil_behavior_hit = (
                self.resolved_mode == "psutil"
                and rb_label in ("PortScan", "DDoS")
                and rb_confidence >= 82.0
            )
            min_rule_packets = 3 if is_psutil_behavior_hit else (12 if self.resolved_mode == "psutil" else 6)
            confidence_margin = 8.0
            strong_rule_evidence = flow.total_pkts >= min_rule_packets
            if strong_rule_evidence and (label == "Benign" or (rb_confidence - confidence) >= confidence_margin):
                label = rb_label
                confidence = max(confidence, rb_confidence)
                detection_method = "rule"
            elif label == rb_label:
                confidence = max(confidence, rb_confidence)
                detection_method = "hybrid"

        severity = get_severity(label, confidence) if label != "Benign" else "LOW"
        if rb_label and label == rb_label and rb_severity:
            severity = rb_severity
            if detection_method == "ml":
                detection_method = "hybrid"

        # GeoIP for attacks
        geo = {"country": None, "city": None, "lat": None, "lon": None, "isp": None}
        if label != "Benign":
            geo = self.geoip.lookup(flow.src_ip)

        # Build result
        result = {
            "timestamp": now,
            "timestamp_text": timestamp_text,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "attack_type": label,
            "confidence": confidence,
            "severity": severity,
            "detection_method": detection_method,
            "is_false_alarm": 0,
            "geo_country": geo.get("country"),
            "geo_city": geo.get("city"),
            "geo_lat": geo.get("lat"),
            "geo_lon": geo.get("lon"),
            "geo_isp": geo.get("isp"),
            "flow_duration": flow.duration,
            "total_packets": flow.total_pkts,
            "total_bytes": sum(flow.fwd_packet_lengths) + sum(flow.bwd_packet_lengths),
            "packet_count": flow.total_pkts,
            "byte_count": sum(flow.fwd_packet_lengths) + sum(flow.bwd_packet_lengths),
        }

        # Update stats
        with self._stats_lock:
            self.stats["total_flows"] += 1
            if label == "Benign":
                self.stats["normal_flows"] += 1
            else:
                self.stats["attack_flows"] += 1

        # Log + DB write with dedup cooldown for attacks.
        should_emit_alert = True
        if label != "Benign":
            should_emit_alert = self.alert_system.should_alert(flow.src_ip, label)
            if should_emit_alert:
                alert_payload = dict(result)
                alert_payload["timestamp"] = timestamp_text
                self.alert_system.log_alert(alert_payload)
        else:
            self.alert_system.log_benign(flow.src_ip, flow.dst_ip)

        if label == "Benign" or should_emit_alert:
            try:
                self.db.insert_alert(result)
            except Exception as e:
                print(f"⚠️  DB insert error: {e}")

        # Callbacks
        if self._on_flow:
            self._on_flow(result)
        if self._on_alert and label != "Benign" and should_emit_alert:
            self._on_alert(result)

    def _start_flow_emitter(self):
        """Periodically force-emit flows for faster feedback."""
        def emitter():
            min_emit_packets = 4 if self.resolved_mode == "psutil" else 2
            while self._running:
                time.sleep(0.3)  # Check every 300ms
                try:
                    flows = self.aggregator.force_emit(min_packets=min_emit_packets)
                    for flow in flows:
                        self._classify_flow(flow)
                except Exception:
                    pass

        t = threading.Thread(target=emitter, daemon=True)
        t.start()

    def _start_stats_writer(self):
        """Periodically write traffic stats to DB for dashboard."""
        def writer():
            while self._running:
                time.sleep(5)
                with self._stats_lock:
                    counts = self.db.get_alert_counts()
                    stat = {
                        "timestamp": time.time(),
                        "total_flows": counts.get("total", 0),
                        "normal_flows": counts.get("normal", 0),
                        "attack_flows": counts.get("attacks", 0),
                        "false_alarms": counts.get("false_alarms", 0),
                        "avg_confidence": counts.get("avg_conf", 0) or 0,
                    }
                    try:
                        self.db.insert_traffic_stat(stat)
                    except Exception:
                        pass

        t = threading.Thread(target=writer, daemon=True)
        t.start()

    def _print_summary(self):
        """Print final session summary."""
        elapsed = time.time() - self.stats["start_time"] if self.stats["start_time"] else 0
        print("\n" + "=" * 60)
        print("📊 SESSION SUMMARY")
        print(f"   Capture Mode:      {self.resolved_mode}")
        print(f"   Duration:          {elapsed:.1f}s")
        print(f"   Packets Processed: {self.stats['packets_processed']}")
        print(f"   Flows Classified:  {self.stats['total_flows']}")
        print(f"   Normal Traffic:    {self.stats['normal_flows']}")
        print(f"   Attacks Detected:  {self.stats['attack_flows']}")
        print(f"   Alerts Logged:     {self.alert_system.alert_count}")
        print("=" * 60)

    def get_stats(self):
        """Return current stats (thread-safe)."""
        with self._stats_lock:
            return dict(self.stats)
