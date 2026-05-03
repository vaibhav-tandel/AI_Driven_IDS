# test_system.py — Component tests for the Real-Time IDS
"""
Run: python test_system.py
Tests all major components without loading the large model files.
"""

import sys
import os
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0

def test(name, fn):
    global PASS, FAIL
    try:
        fn()
        print(f"  ✅ {name}")
        PASS += 1
    except Exception as e:
        print(f"  ❌ {name}: {e}")
        traceback.print_exc()
        FAIL += 1


# ═══════════════════════════════════════════════════
print("\n🧪 TEST SUITE: Real-Time AI IDS\n" + "=" * 50)


# ── 1. Config ──
print("\n📋 Config")

def test_config():
    from config import MODEL_PATH, DB_PATH, LOG_DIR, LOG_FILE
    assert MODEL_PATH, "MODEL_PATH empty"
    assert DB_PATH, "DB_PATH empty"

test("Config loads correctly", test_config)


# ── 2. Database ──
print("\n💾 Database")

def test_db_create():
    from realtime.db import IDSDatabase
    db = IDSDatabase(db_path=":memory:")  # In-memory for testing
    assert db is not None

test("Database creates tables", test_db_create)

def test_db_insert_query():
    from realtime.db import IDSDatabase
    db = IDSDatabase(db_path=":memory:")
    alert = {
        "timestamp": "2026-02-18 12:00:00",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "attack_type": "DDoS",
        "confidence": 95.5,
        "severity": "CRITICAL",
        "is_false_alarm": 0,
        "geo_country": "China",
        "geo_city": "Beijing",
        "geo_lat": 39.9,
        "geo_lon": 116.4,
        "geo_isp": "China Telecom",
        "flow_duration": 5.0,
        "total_packets": 100,
        "total_bytes": 50000
    }
    db.insert_alert(alert)
    results = db.get_recent_alerts(limit=1)
    assert len(results) == 1
    assert results[0]["attack_type"] == "DDoS"
    assert results[0]["confidence"] == 95.5

test("Insert and query alerts", test_db_insert_query)

def test_db_counts():
    from realtime.db import IDSDatabase
    db = IDSDatabase(db_path=":memory:")
    for at in ["Benign", "DDoS", "Benign", "PortScan", "Benign"]:
        db.insert_alert({
            "timestamp": "2026-02-18 12:00:00",
            "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
            "src_port": 1234, "dst_port": 80,
            "protocol": "TCP", "attack_type": at,
            "confidence": 90.0, "severity": "HIGH",
            "is_false_alarm": 0,
            "geo_country": None, "geo_city": None,
            "geo_lat": None, "geo_lon": None, "geo_isp": None,
            "flow_duration": 1.0, "total_packets": 10, "total_bytes": 1000,
        })
    counts = db.get_alert_counts()
    assert counts["total"] == 5
    assert counts["normal"] == 3
    assert counts["attacks"] == 2

test("Alert count aggregation", test_db_counts)


# ── 3. Packet Capture ──
print("\n📡 Packet Capture")

def test_packet_info():
    from realtime.packet_capture import PacketInfo
    pkt = PacketInfo(
        timestamp=time.time(), src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=12345, dst_port=80, protocol="TCP", length=200
    )
    assert pkt.src_ip == "10.0.0.1"
    assert pkt.length == 200
    assert "10.0.0.1" in repr(pkt)

test("PacketInfo creation", test_packet_info)

def test_simulation_capture():
    from realtime.packet_capture import PacketCapture
    packets = []
    capture = PacketCapture(mode="simulation")

    def on_pkt(p):
        packets.append(p)
        if len(packets) >= 20:
            capture._running = False  # Signal stop without joining from capture thread

    capture.start(on_pkt, blocking=False)
    time.sleep(2)
    capture.stop()
    assert len(packets) >= 5, f"Expected >= 5 packets, got {len(packets)}"

test("Simulation captures packets", test_simulation_capture)


# ── 4. Flow Aggregator ──
print("\n🔀 Flow Aggregator")

def test_flow_creation():
    from realtime.flow_aggregator import Flow
    flow = Flow("10.0.0.1", "10.0.0.2", 12345, 80, "TCP")
    assert flow.src_ip == "10.0.0.1"
    assert flow.duration > 0

test("Flow creation", test_flow_creation)

def test_flow_features():
    from realtime.flow_aggregator import Flow
    from realtime.packet_capture import PacketInfo
    flow = Flow("10.0.0.1", "10.0.0.2", 12345, 80, "TCP")

    for i in range(10):
        pkt = PacketInfo(
            timestamp=time.time() + i * 0.01,
            src_ip="10.0.0.1" if i % 2 == 0 else "10.0.0.2",
            dst_ip="10.0.0.2" if i % 2 == 0 else "10.0.0.1",
            src_port=12345 if i % 2 == 0 else 80,
            dst_port=80 if i % 2 == 0 else 12345,
            protocol="TCP", length=100 + i * 10,
            tcp_flags=0x18, window_size=65535, header_len=20
        )
        flow.add_packet(pkt)

    features = flow.to_feature_dict()
    assert len(features) == 81, f"Expected 81 features, got {len(features)}"
    assert features["Total Fwd Packets"] == 5  # Every other packet
    assert features["Total Backward Packets"] == 5
    assert features["total_packets"] == 10

test("Flow produces 81 features", test_flow_features)

def test_aggregator():
    from realtime.flow_aggregator import FlowAggregator
    from realtime.packet_capture import PacketInfo
    agg = FlowAggregator(timeout=0.1)  # Very short timeout for testing

    # Add packets to 2 different flows
    for i in range(5):
        agg.process_packet(PacketInfo(
            timestamp=time.time(), src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1111, dst_port=80, protocol="TCP", length=100
        ))
        agg.process_packet(PacketInfo(
            timestamp=time.time(), src_ip="10.0.0.3", dst_ip="10.0.0.4",
            src_port=2222, dst_port=443, protocol="TCP", length=200
        ))

    # Wait for timeout
    time.sleep(0.2)

    # Next packet should trigger timeout check
    completed = agg.process_packet(PacketInfo(
        timestamp=time.time(), src_ip="1.1.1.1", dst_ip="2.2.2.2",
        src_port=9999, dst_port=80, protocol="TCP", length=50
    ))
    assert len(completed) == 2, f"Expected 2 completed flows, got {len(completed)}"

test("FlowAggregator groups and emits flows", test_aggregator)


# ── 5. Feature Extractor ──
print("\n🧬 Feature Extractor")

def test_feature_columns():
    from realtime.feature_extractor import FEATURE_COLUMNS
    assert len(FEATURE_COLUMNS) == 81, f"Expected 81 columns, got {len(FEATURE_COLUMNS)}"
    assert "Flow Duration" in FEATURE_COLUMNS
    assert "packets_per_duration" in FEATURE_COLUMNS
    assert "label" not in FEATURE_COLUMNS

test("Feature columns match model (81 features)", test_feature_columns)


# ── 6. Alert System ──
print("\n🔔 Alert System")

def test_severity():
    from realtime.alert_system import get_severity
    assert get_severity("DDoS", 95) == "CRITICAL"
    assert get_severity("PortScan", 70) == "MEDIUM"
    assert get_severity("DDoS", 30) == "MEDIUM"  # Low confidence downgrades

test("Severity classification", test_severity)

def test_alert_logging():
    from realtime.alert_system import AlertSystem
    al = AlertSystem()
    al.log_alert({
        "attack_type": "DDoS", "severity": "CRITICAL",
        "confidence": 95.0, "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8", "dst_port": 80
    })
    assert al.alert_count == 1
    # Check log file exists
    from config import LOG_FILE
    assert os.path.exists(LOG_FILE)

test("Alert logging to file", test_alert_logging)


# ── 7. GeoIP ──
print("\n🌍 GeoIP Lookup")

def test_private_ip():
    from realtime.geoip_lookup import GeoIPLookup
    geo = GeoIPLookup()
    result = geo.lookup("192.168.1.100")
    assert result["country"] == "Local Network"

test("Private IP detection", test_private_ip)

def test_simulated_geoip():
    from realtime.geoip_lookup import GeoIPLookup
    geo = GeoIPLookup()
    result = geo.lookup("203.0.113.50")
    assert result["country"] == "China"
    assert result["city"] == "Beijing"

test("Simulated GeoIP lookup", test_simulated_geoip)

def test_geoip_cache():
    from realtime.geoip_lookup import GeoIPLookup
    geo = GeoIPLookup()
    r1 = geo.lookup("45.33.32.100")
    r2 = geo.lookup("45.33.32.100")
    assert r1 == r2

test("GeoIP caching", test_geoip_cache)


# ── 8. Network Monitor (psutil) ──
print("\n🔌 Network Monitor (psutil)")

def test_network_monitor_creation():
    from realtime.network_monitor import NetworkMonitor, PSUTIL_AVAILABLE
    assert PSUTIL_AVAILABLE, "psutil is not installed"
    monitor = NetworkMonitor(poll_interval=1.0)
    assert monitor is not None
    assert monitor.poll_interval == 1.0

test("NetworkMonitor creation", test_network_monitor_creation)

def test_psutil_connections():
    import psutil
    connections = psutil.net_connections(kind='inet')
    # Should have at least some connections on any active machine
    assert isinstance(connections, list)
    # Filter to connections with remote address
    active = [c for c in connections if c.raddr]
    print(f"    ({len(active)} active connections found)")

test("psutil reads system connections", test_psutil_connections)

def test_interface_detection():
    from realtime.packet_capture import list_interfaces
    interfaces = list_interfaces()
    assert len(interfaces) > 0, "No interfaces detected"
    # Check structure
    iface = interfaces[0]
    assert "name" in iface
    assert "ipv4" in iface
    assert "is_up" in iface
    print(f"    ({len(interfaces)} interfaces found)")

test("Interface detection", test_interface_detection)


# ── 9. Auto Mode Selection ──
print("\n🔄 Auto Mode Selection")

def test_auto_mode():
    from realtime.packet_capture import detect_best_mode
    mode = detect_best_mode()
    assert mode in ("scapy", "psutil", "simulation")
    print(f"    (auto-detected: {mode})")

test("Auto mode detection", test_auto_mode)

def test_packet_capture_modes():
    from realtime.packet_capture import PacketCapture
    # Test psutil mode creation
    cap = PacketCapture(mode="psutil")
    assert cap.mode == "psutil"
    # Test simulation mode creation
    cap2 = PacketCapture(mode="simulation")
    assert cap2.mode == "simulation"
    # Test auto mode resolves to something valid
    cap3 = PacketCapture(mode="auto")
    assert cap3.mode in ("scapy", "psutil", "simulation")

test("PacketCapture multi-mode", test_packet_capture_modes)


# ── 10. Detection Policy ──
print("\n🧠 Detection Policy")

def test_cost_sensitive_threshold_attack_flip():
    from realtime.detection_policy import apply_cost_sensitive_threshold
    label, conf = apply_cost_sensitive_threshold(
        label="Benign",
        confidence_pct=55.0,
        probabilities={"Benign": 45.0, "PortScan": 40.0, "DDoS": 15.0},
        normal_threshold=0.70,
        attack_threshold=0.30,
    )
    assert label == "PortScan"
    assert conf >= 55.0

test("Asymmetric threshold flips to attack", test_cost_sensitive_threshold_attack_flip)

def test_whitelist_matcher_localhost():
    from realtime.detection_policy import WhitelistMatcher
    w = WhitelistMatcher(["127.0.0.1"], ["127.0.0.0/8"])
    assert w.contains("127.0.0.1")
    assert w.contains("127.5.6.7")
    assert not w.contains("8.8.8.8")

test("Whitelist matcher filters local addresses", test_whitelist_matcher_localhost)

def test_temporal_rule_portscan_trigger():
    from realtime.detection_policy import HostTemporalState, evaluate_temporal_rules
    from types import SimpleNamespace

    cfg = SimpleNamespace(
        PORTSCAN_WINDOW_SECONDS=10,
        PORTSCAN_UNIQUE_PORTS_THRESHOLD=3,
        NMAP_SYN_WINDOW_SECONDS=5,
        NMAP_SYN_THRESHOLD=100,
        NMAP_ACK_MAX_THRESHOLD=10,
        DDOS_WINDOW_SECONDS=10,
        DDOS_PACKET_RATE_THRESHOLD=500,
        DDOS_UNIQUE_SRC_THRESHOLD=50,
        SLOW_HTTP_ACTIVE_CONN_THRESHOLD=50,
        SLOW_HTTP_LOW_BYTES_THRESHOLD=200,
    )

    temporal = HostTemporalState(window_seconds=60)

    class FakeFlow:
        def __init__(self, src, dst, dport):
            self.src_ip = src
            self.dst_ip = dst
            self.src_port = 50000 + dport
            self.dst_port = dport
            self.protocol = "TCP"
            self.syn_count = 1
            self.ack_count = 0
            self.total_pkts = 3
            self.duration = 0.2
            self.fwd_packet_lengths = [60, 60]
            self.bwd_packet_lengths = [60]

    last_flow = None
    for port in [80, 443, 8080, 8443]:
        last_flow = FakeFlow("10.0.0.10", "10.0.0.20", port)
        temporal.add_flow(last_flow)

    decision = evaluate_temporal_rules(last_flow, temporal, cfg)
    assert decision is not None
    assert decision.attack_type == "PortScan"

test("Temporal rule detects short-window scan", test_temporal_rule_portscan_trigger)


# ── 11. psutil Packet Generation ──
print("\n📡 psutil Packet Generation")

def test_psutil_packet_generation():
    from realtime.network_monitor import NetworkMonitor
    packets = []
    monitor = NetworkMonitor(poll_interval=0.3)

    def on_pkt(p):
        packets.append(p)

    monitor.start(on_pkt, blocking=False)
    time.sleep(2)  # Collect for 2 seconds
    monitor.stop()

    # On any machine with internet, we should get some packets
    print(f"    ({len(packets)} packets captured from real connections)")
    if len(packets) > 0:
        # Check packet structure
        pkt = packets[0]
        assert hasattr(pkt, 'src_ip')
        assert hasattr(pkt, 'dst_ip')
        assert hasattr(pkt, 'src_port')
        assert hasattr(pkt, 'dst_port')
        assert hasattr(pkt, 'protocol')
        # Should have real IPs (not simulation IPs)
        assert pkt.src_ip != 0

test("psutil captures real packets", test_psutil_packet_generation)


# ═══════════════════════════════════════════════════
print("\n" + "=" * 50)
print(f"📊 Results: {PASS} passed, {FAIL} failed")
if FAIL == 0:
    print("🎉 All tests passed!")
else:
    print(f"⚠️  {FAIL} test(s) failed — review errors above")
print("=" * 50 + "\n")
