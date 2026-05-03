# realtime — Real-Time AI IDS Engine
"""
Real-time intrusion detection system package.
Modules:
  - packet_capture: Unified capture (Scapy / psutil / simulation)
  - network_monitor: Real-time connection monitoring via psutil
  - flow_aggregator: Groups packets into network flows
  - feature_extractor: Converts flows to ML model features
  - realtime_engine: Main orchestrator
  - alert_system: Logging and email notifications
  - geoip_lookup: IP geolocation
  - db: SQLite persistence for dashboard
"""
