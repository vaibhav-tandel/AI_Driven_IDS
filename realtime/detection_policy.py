"""Detection policy and temporal heuristics for hybrid IDS decisions."""

from __future__ import annotations

import ipaddress
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Iterable, Optional, Set, Tuple


@dataclass
class RuleDecision:
    attack_type: str
    severity: str
    confidence: float
    detection_method: str
    reason: str


class HostTemporalState:
    """Tracks short-window host behavior for scan and flood signatures."""

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = float(window_seconds)
        self.by_src: Dict[str, Deque[dict]] = defaultdict(deque)
        self.by_dst: Dict[str, Deque[dict]] = defaultdict(deque)

    def _prune(self, queue: Deque[dict], now: float):
        cutoff = now - self.window_seconds
        while queue and queue[0]["t"] < cutoff:
            queue.popleft()

    def add_flow(self, flow, now: Optional[float] = None):
        now = now or time.time()
        event = {
            "t": now,
            "src": flow.src_ip,
            "dst": flow.dst_ip,
            "src_port": int(flow.src_port or 0),
            "dst_port": int(flow.dst_port or 0),
            "proto": flow.protocol,
            "syn": int(getattr(flow, "syn_count", 0) or 0),
            "ack": int(getattr(flow, "ack_count", 0) or 0),
            "pkts": int(getattr(flow, "total_pkts", 0) or 0),
            "bytes": int(sum(getattr(flow, "fwd_packet_lengths", [])) + sum(getattr(flow, "bwd_packet_lengths", []))),
            "dur": float(getattr(flow, "duration", 0.0) or 0.0),
        }
        self.by_src[event["src"]].append(event)
        self.by_dst[event["dst"]].append(event)
        self._prune(self.by_src[event["src"]], now)
        self._prune(self.by_dst[event["dst"]], now)

    def src_events(self, src_ip: str, now: Optional[float] = None) -> Deque[dict]:
        now = now or time.time()
        q = self.by_src[src_ip]
        self._prune(q, now)
        return q

    def dst_events(self, dst_ip: str, now: Optional[float] = None) -> Deque[dict]:
        now = now or time.time()
        q = self.by_dst[dst_ip]
        self._prune(q, now)
        return q


class WhitelistMatcher:
    def __init__(self, whitelist_ips: Iterable[str], whitelist_cidrs: Iterable[str]):
        self._ips: Set[str] = {ip for ip in whitelist_ips if ip}
        self._nets = []
        for cidr in whitelist_cidrs:
            if not cidr:
                continue
            try:
                self._nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue

    def contains(self, ip_text: Optional[str]) -> bool:
        if not ip_text:
            return False
        if ip_text in self._ips:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except ValueError:
            return False
        return any(ip_obj in net for net in self._nets)


def apply_cost_sensitive_threshold(
    label: str,
    confidence_pct: float,
    probabilities: Dict[str, float],
    normal_threshold: float,
    attack_threshold: float,
) -> Tuple[str, float]:
    """
    Re-label predictions using asymmetric thresholds.

    probabilities values are in percentages from 0..100.
    Returns (final_label, final_confidence_pct).
    """
    benign_prob = float(probabilities.get("Benign", 0.0)) / 100.0

    best_attack_label = None
    best_attack_prob = 0.0
    for lbl, p in probabilities.items():
        if lbl == "Benign":
            continue
        p01 = float(p) / 100.0
        if p01 > best_attack_prob:
            best_attack_prob = p01
            best_attack_label = lbl

    if benign_prob >= normal_threshold and best_attack_prob < attack_threshold:
        return "Benign", max(confidence_pct, benign_prob * 100.0)

    if best_attack_label and best_attack_prob >= attack_threshold:
        return best_attack_label, max(confidence_pct, best_attack_prob * 100.0)

    return label, confidence_pct


def evaluate_temporal_rules(flow, temporal: HostTemporalState, cfg) -> Optional[RuleDecision]:
    """Return a high-confidence rule decision for strong temporal signatures."""
    now = time.time()
    src_events = list(temporal.src_events(flow.src_ip, now=now))
    dst_events = list(temporal.dst_events(flow.dst_ip, now=now))

    # Port scan signature: many unique destination ports from one source in short window.
    portscan_window = float(getattr(cfg, "PORTSCAN_WINDOW_SECONDS", 10))
    portscan_threshold = int(getattr(cfg, "PORTSCAN_UNIQUE_PORTS_THRESHOLD", 15))
    recent_src = [e for e in src_events if now - e["t"] <= portscan_window]
    unique_dst_ports = {e["dst_port"] for e in recent_src if e["dst_port"] > 0}
    if len(unique_dst_ports) > portscan_threshold:
        over = max(0, len(unique_dst_ports) - portscan_threshold)
        confidence = min(98.0, 85.0 + (over * 1.2))
        return RuleDecision(
            attack_type="PortScan",
            severity="HIGH",
            confidence=confidence,
            detection_method="rule",
            reason="unique_dst_ports_threshold",
        )

    # SYN scan signature.
    syn_window = float(getattr(cfg, "NMAP_SYN_WINDOW_SECONDS", 5))
    syn_threshold = int(getattr(cfg, "NMAP_SYN_THRESHOLD", 100))
    ack_max_threshold = int(getattr(cfg, "NMAP_ACK_MAX_THRESHOLD", 10))
    syn_recent = [e for e in recent_src if now - e["t"] <= syn_window]
    syn_count = sum(e["syn"] for e in syn_recent)
    ack_count = sum(e["ack"] for e in syn_recent)
    if syn_count > syn_threshold and ack_count < ack_max_threshold:
        syn_over = max(0, syn_count - syn_threshold)
        ack_penalty = min(5.0, ack_count * 0.5)
        confidence = min(99.0, 90.0 + min(8.0, syn_over * 0.05) - ack_penalty)
        return RuleDecision(
            attack_type="PortScan",
            severity="CRITICAL",
            confidence=confidence,
            detection_method="rule",
            reason="nmap_syn_signature",
        )

    # DDoS signatures.
    ddos_window = float(getattr(cfg, "DDOS_WINDOW_SECONDS", 10))
    dst_recent = [e for e in dst_events if now - e["t"] <= ddos_window]
    src_recent_for_flow = [e for e in recent_src if now - e["t"] <= ddos_window]

    pkt_rate = (sum(e["pkts"] for e in src_recent_for_flow) / max(ddos_window, 1.0))
    unique_src = {e["src"] for e in dst_recent if e["src"]}

    ddos_rate_threshold = float(getattr(cfg, "DDOS_PACKET_RATE_THRESHOLD", 500))
    ddos_src_threshold = int(getattr(cfg, "DDOS_UNIQUE_SRC_THRESHOLD", 50))
    if pkt_rate > ddos_rate_threshold or len(unique_src) > ddos_src_threshold:
        rate_score = min(1.0, pkt_rate / max(ddos_rate_threshold, 1.0))
        src_score = min(1.0, len(unique_src) / max(ddos_src_threshold, 1))
        score = max(rate_score, src_score)
        confidence = min(98.0, 82.0 + (score * 12.0))
        return RuleDecision(
            attack_type="DDoS",
            severity="CRITICAL",
            confidence=confidence,
            detection_method="rule",
            reason="ddos_rate_or_fan_in",
        )

    # Slow-HTTP style signature approximation.
    active_connections = len([e for e in dst_recent if e["proto"] == "TCP"])
    total_bytes = sum(e["bytes"] for e in dst_recent)
    low_bytes_per_conn = (total_bytes / max(active_connections, 1))
    slow_conn_threshold = int(getattr(cfg, "SLOW_HTTP_ACTIVE_CONN_THRESHOLD", 50))
    slow_bytes_threshold = float(getattr(cfg, "SLOW_HTTP_LOW_BYTES_THRESHOLD", 200))
    if active_connections > slow_conn_threshold and low_bytes_per_conn < slow_bytes_threshold:
        conn_pressure = min(1.0, (active_connections - slow_conn_threshold) / max(slow_conn_threshold, 1))
        bytes_pressure = min(1.0, max(0.0, (slow_bytes_threshold - low_bytes_per_conn)) / max(slow_bytes_threshold, 1.0))
        pressure = max(conn_pressure, bytes_pressure)
        confidence = min(97.0, 85.0 + (pressure * 10.0))
        return RuleDecision(
            attack_type="DoS Slowloris",
            severity="HIGH",
            confidence=confidence,
            detection_method="rule",
            reason="slow_http_connection_pattern",
        )

    return None
