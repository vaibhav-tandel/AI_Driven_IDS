# network_monitor.py — Real-time network monitoring using psutil (no admin required)
"""
Uses psutil to monitor real network connections on the system.
Works on Windows, Linux, and macOS without admin/root privileges.
Converts active connections into PacketInfo objects for the IDS pipeline.
"""

import time
import threading
import random
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from realtime.packet_capture import PacketInfo


class NetworkMonitor:
    """
    Monitors real network connections using psutil.
    Converts system TCP/UDP connections into PacketInfo objects
    that feed into the existing IDS pipeline (FlowAggregator → FeatureExtractor → Model).

    No admin/root privileges required.
    """

    def __init__(self, poll_interval=0.5):
        self.poll_interval = poll_interval
        self._running = False
        self._thread = None
        self._seen_connections = set()
        self._prev_io = None
        self._prev_io_time = None

    @staticmethod
    def is_available():
        """Check if psutil monitoring is available."""
        return PSUTIL_AVAILABLE

    @staticmethod
    def list_interfaces():
        """List available network interfaces with their addresses and stats."""
        if not PSUTIL_AVAILABLE:
            return []

        interfaces = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for iface_name, addr_list in addrs.items():
            iface_stats = stats.get(iface_name)
            is_up = iface_stats.isup if iface_stats else False

            # Get IPv4 address
            ipv4 = None
            for addr in addr_list:
                if addr.family.name == 'AF_INET':
                    ipv4 = addr.address
                    break

            interfaces.append({
                "name": iface_name,
                "ipv4": ipv4,
                "is_up": is_up,
                "speed": iface_stats.speed if iface_stats else 0,
            })

        return interfaces

    def start(self, callback, blocking=True):
        """Start monitoring network connections. Calls callback(PacketInfo) for each."""
        if not PSUTIL_AVAILABLE:
            raise RuntimeError("psutil is not installed. Run: pip install psutil")

        self._running = True
        if blocking:
            self._monitor_loop(callback)
        else:
            self._thread = threading.Thread(
                target=self._monitor_loop, args=(callback,), daemon=True
            )
            self._thread.start()

    def stop(self):
        """Stop monitoring."""
        self._running = False
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=5)

    def _monitor_loop(self, callback):
        """Main monitoring loop — polls system connections periodically."""
        print("🟢 psutil network monitor — capturing real connections (no admin required)")
        print(f"   Poll interval: {self.poll_interval}s")

        # Show active interfaces
        interfaces = self.list_interfaces()
        active = [i for i in interfaces if i["is_up"] and i["ipv4"]]
        if active:
            print(f"   Active interfaces: {', '.join(f'{i['name']} ({i['ipv4']})' for i in active)}")

        self._prev_io = psutil.net_io_counters()
        self._prev_io_time = time.time()

        while self._running:
            try:
                self._poll_connections(callback)
            except Exception as e:
                # psutil can raise AccessDenied on some connections — skip them
                if "Access" not in str(type(e).__name__):
                    print(f"⚠️  Monitor error: {e}")
            time.sleep(self.poll_interval)

    def _poll_connections(self, callback):
        """Poll current connections and generate PacketInfo objects."""
        now = time.time()

        # Get IO counters for byte/packet estimation
        try:
            current_io = psutil.net_io_counters()
        except Exception:
            current_io = self._prev_io

        # Calculate deltas for packet size estimation
        dt = now - self._prev_io_time if self._prev_io_time else 1.0
        if dt < 0.01:
            dt = 0.01

        bytes_sent_delta = current_io.bytes_sent - self._prev_io.bytes_sent
        bytes_recv_delta = current_io.bytes_recv - self._prev_io.bytes_recv
        pkts_sent_delta = current_io.packets_sent - self._prev_io.packets_sent
        pkts_recv_delta = current_io.packets_recv - self._prev_io.packets_recv

        total_pkts = max(pkts_sent_delta + pkts_recv_delta, 1)
        total_bytes = bytes_sent_delta + bytes_recv_delta
        avg_pkt_size = total_bytes / total_pkts if total_pkts > 0 else 100

        self._prev_io = current_io
        self._prev_io_time = now

        # Get all active connections
        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, PermissionError):
            # On some systems, net_connections needs elevated privileges
            # Fall back to TCP only which usually works
            try:
                connections = psutil.net_connections(kind='tcp')
            except Exception:
                connections = []

        current_conn_keys = set()

        for conn in connections:
            # Skip connections without remote address (listening sockets)
            if not conn.raddr:
                continue

            local_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
            local_port = conn.laddr.port if conn.laddr else 0
            remote_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
            remote_port = conn.raddr.port if conn.raddr else 0

            # Skip IPv6 for now (model trained on IPv4)
            if ':' in local_ip or ':' in remote_ip:
                continue

            # Skip loopback
            if local_ip.startswith("127.") or remote_ip.startswith("127."):
                continue

            protocol = "TCP" if conn.type == 1 else "UDP"  # SOCK_STREAM=1, SOCK_DGRAM=2
            conn_key = (local_ip, remote_ip, local_port, remote_port, protocol)

            current_conn_keys.add(conn_key)

            # Estimate packet size based on connection type and IO deltas
            if remote_port == 443:
                est_size = random.randint(200, 1400)   # HTTPS
            elif remote_port == 80:
                est_size = random.randint(100, 1200)   # HTTP
            elif remote_port == 53:
                est_size = random.randint(40, 512)     # DNS
            elif remote_port == 22:
                est_size = random.randint(60, 500)     # SSH
            else:
                est_size = int(avg_pkt_size) if avg_pkt_size > 0 else random.randint(60, 800)

            # Ensure estimated size is always in a valid packet-size range.
            est_size = max(60, est_size)

            # Determine TCP flags based on connection status
            tcp_flags = 0x10  # ACK by default
            status = conn.status if hasattr(conn, 'status') else ""
            if status == "SYN_SENT":
                tcp_flags = 0x02  # SYN
            elif status == "SYN_RECV":
                tcp_flags = 0x12  # SYN+ACK
            elif status == "ESTABLISHED":
                tcp_flags = random.choice([0x10, 0x18])  # ACK or PSH+ACK
            elif status == "FIN_WAIT1" or status == "FIN_WAIT2":
                tcp_flags = 0x11  # FIN+ACK
            elif status == "CLOSE_WAIT":
                tcp_flags = 0x11  # FIN+ACK
            elif status == "TIME_WAIT":
                tcp_flags = 0x10  # ACK

            # Generate forward packet (local → remote)
            fwd_pkt = PacketInfo(
                timestamp=now,
                src_ip=local_ip,
                dst_ip=remote_ip,
                src_port=local_port,
                dst_port=remote_port,
                protocol=protocol,
                length=est_size,
                payload_len=max(0, est_size - 40),
                tcp_flags=tcp_flags,
                window_size=random.randint(8192, 65535),
                header_len=random.choice([20, 32, 40]),
            )
            callback(fwd_pkt)

            # Generate backward packet (remote → local) for ~60% of connections
            if random.random() < 0.6:
                bwd_size = random.randint(60, max(60, est_size))
                bwd_pkt = PacketInfo(
                    timestamp=now + random.uniform(0.001, 0.01),
                    src_ip=remote_ip,
                    dst_ip=local_ip,
                    src_port=remote_port,
                    dst_port=local_port,
                    protocol=protocol,
                    length=bwd_size,
                    payload_len=max(0, bwd_size - 40),
                    tcp_flags=0x10,  # ACK
                    window_size=random.randint(8192, 65535),
                    header_len=random.choice([20, 32, 40]),
                )
                callback(bwd_pkt)

        # Track new and closed connections
        new_conns = current_conn_keys - self._seen_connections
        closed_conns = self._seen_connections - current_conn_keys

        # Generate RST/FIN packets for closed connections
        for conn_key in closed_conns:
            local_ip, remote_ip, local_port, remote_port, protocol = conn_key
            if ':' in local_ip or ':' in remote_ip:
                continue
            fin_pkt = PacketInfo(
                timestamp=now,
                src_ip=local_ip,
                dst_ip=remote_ip,
                src_port=local_port,
                dst_port=remote_port,
                protocol=protocol,
                length=40,
                payload_len=0,
                tcp_flags=0x01,  # FIN
                window_size=0,
                header_len=20,
            )
            callback(fin_pkt)

        self._seen_connections = current_conn_keys

    def get_process_name(self, pid):
        """Get the process name for a given PID."""
        if not pid or not PSUTIL_AVAILABLE:
            return "unknown"
        try:
            proc = psutil.Process(pid)
            return proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"
