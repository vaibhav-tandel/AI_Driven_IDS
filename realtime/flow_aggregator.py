# flow_aggregator.py — Groups raw packets into network flows
import time
import threading
import numpy as np


class Flow:
    """
    Represents a single network flow (bidirectional).
    A flow is identified by (src_ip, dst_ip, src_port, dst_port, protocol).
    Tracks all statistics needed for CIC-IDS2017 feature extraction.
    """

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        self.start_time = time.time()
        self.last_time = self.start_time

        # Forward = src→dst, Backward = dst→src
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        self.fwd_timestamps = []
        self.bwd_timestamps = []
        self.fwd_header_lengths = []
        self.bwd_header_lengths = []
        self.fwd_window_sizes = []
        self.bwd_window_sizes = []

        # TCP flags
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.cwe_count = 0
        self.ece_count = 0

        # Active/Idle tracking
        self.active_times = []
        self.idle_times = []
        self._last_active = self.start_time
        self._idle_threshold = 1.0  # 1 second

        self.total_pkts = 0

    @property
    def flow_key(self):
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)

    @property
    def duration(self):
        return max(self.last_time - self.start_time, 1e-6)

    def add_packet(self, packet):
        """Add a packet to this flow. Determines direction automatically."""
        now = packet.timestamp or time.time()
        self.last_time = now
        self.total_pkts += 1

        # Determine direction
        is_forward = (packet.src_ip == self.src_ip and packet.src_port == self.src_port)

        length = packet.length
        header_len = packet.header_len
        window = packet.window_size

        if is_forward:
            self.fwd_packet_lengths.append(length)
            self.fwd_timestamps.append(now)
            self.fwd_header_lengths.append(header_len)
            self.fwd_window_sizes.append(window)
        else:
            self.bwd_packet_lengths.append(length)
            self.bwd_timestamps.append(now)
            self.bwd_header_lengths.append(header_len)
            self.bwd_window_sizes.append(window)

        # TCP flags
        flags = packet.tcp_flags
        if flags:
            if flags & 0x01: self.fin_count += 1
            if flags & 0x02: self.syn_count += 1
            if flags & 0x04: self.rst_count += 1
            if flags & 0x08:
                self.psh_count += 1
                if is_forward:
                    self.fwd_psh_flags += 1
                else:
                    self.bwd_psh_flags += 1
            if flags & 0x10: self.ack_count += 1
            if flags & 0x20:
                self.urg_count += 1
                if is_forward:
                    self.fwd_urg_flags += 1
                else:
                    self.bwd_urg_flags += 1
            if flags & 0x40: self.ece_count += 1
            if flags & 0x80: self.cwe_count += 1

        # Active/Idle tracking
        gap = now - self._last_active
        if gap > self._idle_threshold:
            self.idle_times.append(gap)
        else:
            self.active_times.append(gap)
        self._last_active = now

    def _safe_stats(self, arr):
        """Return (mean, std, max, min) for an array, defaulting to 0."""
        if not arr:
            return 0.0, 0.0, 0.0, 0.0
        a = np.array(arr, dtype=float)
        return float(np.mean(a)), float(np.std(a)), float(np.max(a)), float(np.min(a))

    def _iat(self, timestamps):
        """Compute inter-arrival times from a list of timestamps."""
        if len(timestamps) < 2:
            return []
        ts = sorted(timestamps)
        return [ts[i+1] - ts[i] for i in range(len(ts)-1)]

    def to_feature_dict(self):
        """
        Convert flow data to a dictionary of CIC-IDS2017 features.
        Returns all 81 features matching the trained model.
        """
        dur = self.duration
        all_lengths = self.fwd_packet_lengths + self.bwd_packet_lengths
        all_timestamps = sorted(self.fwd_timestamps + self.bwd_timestamps)

        fwd_n = len(self.fwd_packet_lengths)
        bwd_n = len(self.bwd_packet_lengths)
        total_n = fwd_n + bwd_n

        # Packet length stats
        fwd_mean, fwd_std, fwd_max, fwd_min = self._safe_stats(self.fwd_packet_lengths)
        bwd_mean, bwd_std, bwd_max, bwd_min = self._safe_stats(self.bwd_packet_lengths)
        all_mean, all_std, all_max, all_min = self._safe_stats(all_lengths)

        # Inter-arrival times
        flow_iat = self._iat(all_timestamps)
        fwd_iat = self._iat(self.fwd_timestamps)
        bwd_iat = self._iat(self.bwd_timestamps)

        flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = self._safe_stats(flow_iat)
        fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = self._safe_stats(fwd_iat)
        bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = self._safe_stats(bwd_iat)

        fwd_iat_total = sum(fwd_iat) if fwd_iat else 0
        bwd_iat_total = sum(bwd_iat) if bwd_iat else 0

        total_fwd_bytes = sum(self.fwd_packet_lengths)
        total_bwd_bytes = sum(self.bwd_packet_lengths)
        total_bytes_all = total_fwd_bytes + total_bwd_bytes

        # Active/idle stats
        active_mean, active_std, active_max, active_min = self._safe_stats(self.active_times)
        idle_mean, idle_std, idle_max, idle_min = self._safe_stats(self.idle_times)

        # Header lengths
        fwd_hdr_len = sum(self.fwd_header_lengths)
        bwd_hdr_len = sum(self.bwd_header_lengths)

        # Rates
        flow_bytes_per_s = total_bytes_all / dur if dur > 0 else 0
        flow_pkts_per_s = total_n / dur if dur > 0 else 0
        fwd_pkts_per_s = fwd_n / dur if dur > 0 else 0
        bwd_pkts_per_s = bwd_n / dur if dur > 0 else 0

        # Down/Up ratio
        down_up_ratio = bwd_n / fwd_n if fwd_n > 0 else 0

        # Init window bytes
        init_win_fwd = self.fwd_window_sizes[0] if self.fwd_window_sizes else 0
        init_win_bwd = self.bwd_window_sizes[0] if self.bwd_window_sizes else 0

        # Build feature dict — order matches sample_dataset.csv columns exactly
        features = {
            "Flow Duration": dur * 1e6,  # convert to microseconds like CIC
            "Total Fwd Packets": fwd_n,
            "Total Backward Packets": bwd_n,
            "Total Length of Fwd Packets": total_fwd_bytes,
            "Total Length of Bwd Packets": total_bwd_bytes,
            "Fwd Packet Length Max": fwd_max,
            "Fwd Packet Length Min": fwd_min,
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": fwd_std,
            "Bwd Packet Length Max": bwd_max,
            "Bwd Packet Length Min": bwd_min,
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": bwd_std,
            "Flow Bytes/s": flow_bytes_per_s,
            "Flow Packets/s": flow_pkts_per_s,
            "Flow IAT Mean": flow_iat_mean * 1e6,
            "Flow IAT Std": flow_iat_std * 1e6,
            "Flow IAT Max": flow_iat_max * 1e6,
            "Flow IAT Min": flow_iat_min * 1e6,
            "Fwd IAT Total": fwd_iat_total * 1e6,
            "Fwd IAT Mean": fwd_iat_mean * 1e6,
            "Fwd IAT Std": fwd_iat_std * 1e6,
            "Fwd IAT Max": fwd_iat_max * 1e6,
            "Fwd IAT Min": fwd_iat_min * 1e6,
            "Bwd IAT Total": bwd_iat_total * 1e6,
            "Bwd IAT Mean": bwd_iat_mean * 1e6,
            "Bwd IAT Std": bwd_iat_std * 1e6,
            "Bwd IAT Max": bwd_iat_max * 1e6,
            "Bwd IAT Min": bwd_iat_min * 1e6,
            "Fwd PSH Flags": self.fwd_psh_flags,
            "Bwd PSH Flags": self.bwd_psh_flags,
            "Fwd URG Flags": self.fwd_urg_flags,
            "Bwd URG Flags": self.bwd_urg_flags,
            "Fwd Header Length": fwd_hdr_len,
            "Bwd Header Length": bwd_hdr_len,
            "Fwd Packets/s": fwd_pkts_per_s,
            "Bwd Packets/s": bwd_pkts_per_s,
            "Min Packet Length": all_min,
            "Max Packet Length": all_max,
            "Packet Length Mean": all_mean,
            "Packet Length Std": all_std,
            "Packet Length Variance": all_std ** 2,
            "FIN Flag Count": self.fin_count,
            "SYN Flag Count": self.syn_count,
            "RST Flag Count": self.rst_count,
            "PSH Flag Count": self.psh_count,
            "ACK Flag Count": self.ack_count,
            "URG Flag Count": self.urg_count,
            "CWE Flag Count": self.cwe_count,
            "ECE Flag Count": self.ece_count,
            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": all_mean,
            "Avg Fwd Segment Size": fwd_mean,
            "Avg Bwd Segment Size": bwd_mean,
            "Fwd Header Length.1": fwd_hdr_len,
            "Fwd Avg Bytes/Bulk": 0,
            "Fwd Avg Packets/Bulk": 0,
            "Fwd Avg Bulk Rate": 0,
            "Bwd Avg Bytes/Bulk": 0,
            "Bwd Avg Packets/Bulk": 0,
            "Bwd Avg Bulk Rate": 0,
            "Subflow Fwd Packets": fwd_n,
            "Subflow Fwd Bytes": total_fwd_bytes,
            "Subflow Bwd Packets": bwd_n,
            "Subflow Bwd Bytes": total_bwd_bytes,
            "Init_Win_bytes_forward": init_win_fwd,
            "Init_Win_bytes_backward": init_win_bwd,
            "act_data_pkt_fwd": fwd_n,
            "min_seg_size_forward": min(self.fwd_header_lengths) if self.fwd_header_lengths else 0,
            "Active Mean": active_mean * 1e6,
            "Active Std": active_std * 1e6,
            "Active Max": active_max * 1e6,
            "Active Min": active_min * 1e6,
            "Idle Mean": idle_mean * 1e6,
            "Idle Std": idle_std * 1e6,
            "Idle Max": idle_max * 1e6,
            "Idle Min": idle_min * 1e6,
            # Derived features (from data_processing.py)
            "total_bytes": total_bytes_all,
            "total_packets": total_n,
            "bytes_per_packet": total_bytes_all / (total_n + 1e-6),
            "packets_per_duration": total_n / (dur * 1e6 + 1e-6),
        }
        return features


class FlowAggregator:
    """
    Manages a table of active flows. Packets are added and grouped
    into flows by their 5-tuple. Completed (timed-out) flows are
    returned for classification.
    """

    def __init__(
        self,
        timeout=120.0,
        min_packets=2,
        early_packet_threshold=10,
        early_window_seconds=2.0,
        syn_inactivity_seconds=5.0,
    ):
        self.timeout = timeout
        self.min_packets = min_packets
        self.early_packet_threshold = early_packet_threshold
        self.early_window_seconds = early_window_seconds
        self.syn_inactivity_seconds = syn_inactivity_seconds
        self.flows = {}
        self._lock = threading.Lock()

    def _early_emit_reason(self, flow, now):
        """Return reason for early emission, or None if flow should stay active."""
        if flow.total_pkts >= self.early_packet_threshold and flow.duration <= self.early_window_seconds:
            return "fast_burst"

        # SYN-only / handshake-incomplete patterns are common in scans.
        is_syn_only = (
            flow.protocol == "TCP"
            and flow.syn_count > 0
            and flow.ack_count == 0
            and flow.psh_count == 0
        )
        if is_syn_only and (
            flow.fin_count > 0
            or flow.rst_count > 0
            or (now - flow.last_time) >= self.syn_inactivity_seconds
        ):
            return "syn_only"

        return None

    def process_packet(self, packet):
        """
        Add a packet to the flow table. Returns a list of completed flows
        (those that have timed out since the last check).
        """
        key_fwd = (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol)
        key_bwd = (packet.dst_ip, packet.src_ip, packet.dst_port, packet.src_port, packet.protocol)

        completed = []
        with self._lock:
            # Check if this packet belongs to an existing flow (forward or backward)
            current_key = None
            if key_fwd in self.flows:
                self.flows[key_fwd].add_packet(packet)
                current_key = key_fwd
            elif key_bwd in self.flows:
                self.flows[key_bwd].add_packet(packet)
                current_key = key_bwd
            else:
                # Create new flow
                flow = Flow(
                    packet.src_ip, packet.dst_ip,
                    packet.src_port, packet.dst_port,
                    packet.protocol
                )
                flow.add_packet(packet)
                self.flows[key_fwd] = flow
                current_key = key_fwd

            now = time.time()

            # Early emit for fast scans / short attack bursts
            if current_key in self.flows:
                flow = self.flows[current_key]
                reason = self._early_emit_reason(flow, now)
                if reason == "fast_burst" and flow.total_pkts >= self.min_packets:
                    completed.append(flow)
                    del self.flows[current_key]
                elif reason == "syn_only" and flow.total_pkts >= 1:
                    completed.append(flow)
                    del self.flows[current_key]

            # Check for timed-out flows
            expired_keys = []
            for k, f in list(self.flows.items()):
                if now - f.last_time > self.timeout:
                    if f.total_pkts >= self.min_packets:
                        completed.append(f)
                    expired_keys.append(k)

            for k in expired_keys:
                del self.flows[k]

        return completed

    def flush_all(self):
        """Force-complete all active flows."""
        completed = []
        with self._lock:
            for f in self.flows.values():
                if f.total_pkts >= self.min_packets:
                    completed.append(f)
            self.flows.clear()
        return completed

    def force_emit(self, min_packets=3):
        """
        Force-emit flows that have accumulated enough packets,
        useful in simulation mode for faster feedback.
        """
        completed = []
        with self._lock:
            emit_keys = []
            for k, f in self.flows.items():
                if f.total_pkts >= min_packets:
                    completed.append(f)
                    emit_keys.append(k)
            for k in emit_keys:
                del self.flows[k]
        return completed

    @property
    def active_flow_count(self):
        return len(self.flows)
