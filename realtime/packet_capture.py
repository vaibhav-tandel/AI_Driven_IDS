# packet_capture.py — Unified packet capture: Scapy, psutil, or simulation
import time
import random
import threading
import os
import sys
import queue

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Try to import Scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, get_if_list, PcapReader
    try:
        from scapy.arch.windows import get_windows_if_list
    except Exception:
        get_windows_if_list = None
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    get_windows_if_list = None

# Try to import psutil
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class PacketInfo:
    """Normalized packet representation from any capture source."""

    __slots__ = [
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "length", "payload_len", "tcp_flags",
        "window_size", "header_len"
    ]

    def __init__(self, **kwargs):
        for slot in self.__slots__:
            setattr(self, slot, kwargs.get(slot, 0))

    def __repr__(self):
        return (f"<Packet {self.src_ip}:{self.src_port} → "
                f"{self.dst_ip}:{self.dst_port} [{self.protocol}] "
                f"{self.length}B>")


def detect_best_mode(interface=None):
    """
    Auto-detect the best available capture mode.
    Returns: 'scapy', 'psutil', or 'simulation'
    """
    # Try Scapy first (requires admin + Npcap on Windows)
    if SCAPY_AVAILABLE:
        try:
            if os.name == "nt":
                # On Windows, Scapy without Npcap often exposes no NPF interfaces
                scapy_ifaces = get_if_list() or []
                if interface:
                    resolved = resolve_scapy_interface(interface)
                    if resolved:
                        return "scapy"
                elif any("NPF" in str(i) for i in scapy_ifaces):
                    return "scapy"
            else:
                return "scapy"
        except Exception:
            pass

    # psutil is the universal fallback (no admin needed)
    if PSUTIL_AVAILABLE:
        return "psutil"

    # Last resort: simulation
    return "simulation"


def list_interfaces():
    """
    List available network interfaces with details.
    Works with both psutil and Scapy.
    """
    interfaces = []

    if PSUTIL_AVAILABLE:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for name, addr_list in addrs.items():
            iface_stats = stats.get(name)
            is_up = iface_stats.isup if iface_stats else False
            speed = iface_stats.speed if iface_stats else 0

            ipv4 = None
            for addr in addr_list:
                if addr.family.name == 'AF_INET':
                    ipv4 = addr.address
                    break

            interfaces.append({
                "name": name,
                "ipv4": ipv4 or "N/A",
                "is_up": is_up,
                "speed": speed,
            })

    return interfaces


def list_scapy_interfaces():
    """
    List Scapy-visible interfaces and Windows NPF mappings (if available).
    """
    if not SCAPY_AVAILABLE:
        return []

    interfaces = []
    seen = set()

    try:
        for iface in get_if_list() or []:
            iface_str = str(iface)
            if iface_str in seen:
                continue
            seen.add(iface_str)
            interfaces.append({
                "name": iface_str,
                "scapy_name": iface_str,
                "description": "Scapy interface",
            })
    except Exception:
        pass

    if os.name == "nt" and get_windows_if_list:
        try:
            for item in get_windows_if_list():
                guid = (item.get("guid") or "").strip("{}")
                npf_name = f"\\\\Device\\NPF_{{{guid}}}" if guid else None
                candidates = [
                    item.get("name"),
                    item.get("description"),
                    item.get("network_name"),
                    npf_name,
                ]
                key = "|".join([str(c) for c in candidates if c])
                if not key or key in seen:
                    continue
                seen.add(key)
                interfaces.append({
                    "name": item.get("name") or item.get("network_name") or npf_name,
                    "scapy_name": npf_name or item.get("name"),
                    "description": item.get("description") or "Windows adapter",
                })
        except Exception:
            pass

    return interfaces


def resolve_scapy_interface(interface):
    """
    Resolve a user-friendly interface name to a Scapy-valid interface string.
    On Windows, maps names/descriptions/GUIDs to \\Device\\NPF_{GUID} when possible.
    """
    if not interface:
        return None

    text = str(interface).strip()
    if not text:
        return None

    # Already looks like an NPF adapter path
    if "NPF" in text:
        return text

    if SCAPY_AVAILABLE:
        try:
            for iface in get_if_list() or []:
                if text == str(iface):
                    return str(iface)
        except Exception:
            pass

    if os.name == "nt" and get_windows_if_list:
        lower_text = text.lower()
        try:
            for item in get_windows_if_list():
                guid = (item.get("guid") or "").strip("{}")
                npf_name = f"\\\\Device\\NPF_{{{guid}}}" if guid else None
                candidates = [
                    item.get("name"),
                    item.get("description"),
                    item.get("network_name"),
                    npf_name,
                    guid,
                ]
                for candidate in candidates:
                    if candidate and lower_text == str(candidate).lower():
                        return npf_name or str(candidate)
        except Exception:
            pass

    return text


class PacketCapture:
    """
    Unified packet capture supporting three modes:
      - scapy:      Full packet capture via Scapy (admin/Npcap required)
      - psutil:     Connection-level monitoring via psutil (no admin)
      - simulation: Synthetic traffic generation (demo/testing)
      - auto:       Auto-detect best available mode

    Uses a callback pattern: capture.start(on_packet_fn)
    """

    def __init__(self, interface=None, mode="auto", pcap_file=None):
        """
        Args:
            interface: Network interface name (for Scapy mode)
            mode: 'auto', 'scapy', 'psutil', 'pcap', or 'simulation'
        """
        self.interface = interface
        self.pcap_file = pcap_file
        self._running = False
        self._thread = None
        self._monitor = None  # psutil NetworkMonitor instance
        self._packet_queue = queue.Queue(maxsize=10000)
        self._queue_worker = None

        # Resolve mode
        if mode == "auto":
            self.mode = detect_best_mode(interface)
        elif mode == "live":
            # Legacy "live" mode maps to scapy or psutil
            if SCAPY_AVAILABLE:
                self.mode = "scapy"
            elif PSUTIL_AVAILABLE:
                self.mode = "psutil"
            else:
                print("⚠️  Neither Scapy nor psutil available. Falling back to simulation.")
                self.mode = "simulation"
        elif mode == "scapy":
            if not SCAPY_AVAILABLE:
                print("⚠️  Scapy not available. Falling back to psutil.")
                self.mode = "psutil" if PSUTIL_AVAILABLE else "simulation"
            else:
                self.mode = "scapy"
        elif mode == "psutil":
            if not PSUTIL_AVAILABLE:
                print("⚠️  psutil not available. Falling back to simulation.")
                self.mode = "simulation"
            else:
                self.mode = "psutil"
        elif mode == "pcap":
            if not SCAPY_AVAILABLE:
                print("⚠️  Scapy not available. Falling back to simulation.")
                self.mode = "simulation"
            else:
                self.mode = "pcap"
        else:
            self.mode = "simulation"

        # For backward compatibility
        self.simulation_mode = (self.mode == "simulation")

    def start(self, callback, blocking=True):
        """Start capturing packets. Calls callback(PacketInfo) for each packet."""
        self._running = True
        if blocking:
            self._capture_loop(callback)
        else:
            self._thread = threading.Thread(
                target=self._capture_loop, args=(callback,), daemon=True
            )
            self._thread.start()

    def stop(self):
        self._running = False
        if self._monitor:
            self._monitor.stop()
        if self._queue_worker and self._queue_worker is not threading.current_thread():
            self._queue_worker.join(timeout=2)
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=5)

    def _capture_loop(self, callback):
        if self.mode == "simulation":
            self._simulate(callback)
        elif self.mode == "scapy":
            self._live_capture(callback)
        elif self.mode == "psutil":
            self._psutil_capture(callback)
        elif self.mode == "pcap":
            self._pcap_replay(callback)

    # ── Live Capture (Scapy) ──

    def _live_capture(self, callback):
        """Capture real packets using Scapy."""
        resolved_iface = resolve_scapy_interface(self.interface)

        def process(pkt):
            if not self._running:
                return
            info = self._scapy_to_packet_info(pkt)
            if info:
                try:
                    self._packet_queue.put_nowait(info)
                except queue.Full:
                    # Drop packet when processing can't keep up; never block capture.
                    pass

        def consume_queue():
            while self._running or not self._packet_queue.empty():
                try:
                    info = self._packet_queue.get(timeout=0.2)
                except queue.Empty:
                    continue
                try:
                    callback(info)
                except Exception:
                    pass

        self._queue_worker = threading.Thread(target=consume_queue, daemon=True)
        self._queue_worker.start()

        print(f"🔴 Live Scapy capture on interface: {resolved_iface or 'default'}")
        print("   (Requires admin/root + Npcap on Windows)")
        if os.name == "nt" and not resolved_iface:
            print("⚠️  No interface provided. Use --list-interfaces and pass a valid NPF interface.")
        try:
            sniff(
                iface=resolved_iface,
                prn=process,
                store=False,
                stop_filter=lambda _: not self._running
            )
        except PermissionError:
            print("❌ Permission denied. Run as administrator for Scapy capture.")
            if PSUTIL_AVAILABLE:
                print("⚠️  Switching to psutil mode (no admin required)...")
                self.mode = "psutil"
                self._psutil_capture(callback)
            else:
                print("⚠️  Switching to simulation mode...")
                self.mode = "simulation"
                self.simulation_mode = True
                self._simulate(callback)
        except Exception as e:
            print(f"❌ Scapy capture error: {e}")
            if PSUTIL_AVAILABLE:
                print("⚠️  Switching to psutil mode...")
                self.mode = "psutil"
                self._psutil_capture(callback)
            else:
                print("⚠️  Switching to simulation mode...")
                self.mode = "simulation"
                self.simulation_mode = True
                self._simulate(callback)
        finally:
            if self._queue_worker and self._queue_worker is not threading.current_thread():
                self._queue_worker.join(timeout=2)

    def _scapy_to_packet_info(self, pkt):
        """Convert a Scapy packet to our PacketInfo format."""
        if not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]
        info = PacketInfo(
            timestamp=time.time(),
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            length=len(pkt),
            payload_len=len(ip_layer.payload) if ip_layer.payload else 0,
            header_len=ip_layer.ihl * 4
        )

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            info.src_port = tcp.sport
            info.dst_port = tcp.dport
            info.protocol = "TCP"
            info.tcp_flags = int(tcp.flags)
            info.window_size = tcp.window
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            info.src_port = udp.sport
            info.dst_port = udp.dport
            info.protocol = "UDP"
        elif pkt.haslayer(ICMP):
            info.protocol = "ICMP"
        else:
            info.protocol = "OTHER"

        return info

    # ── psutil Capture ──

    def _psutil_capture(self, callback):
        """Capture real network activity using psutil (no admin required)."""
        from realtime.network_monitor import NetworkMonitor
        self._monitor = NetworkMonitor(poll_interval=0.5)
        self._monitor.start(callback, blocking=True)

    def _pcap_replay(self, callback):
        """Replay packets from a PCAP file into the processing pipeline."""
        if not self.pcap_file:
            print("❌ PCAP mode selected but no --pcap file was provided.")
            self._running = False
            return
        if not os.path.exists(self.pcap_file):
            print(f"❌ PCAP file not found: {self.pcap_file}")
            self._running = False
            return

        print(f"🟣 PCAP replay mode: {self.pcap_file}")
        try:
            with PcapReader(self.pcap_file) as reader:
                for pkt in reader:
                    if not self._running:
                        break
                    info = self._scapy_to_packet_info(pkt)
                    if info:
                        callback(info)
        except Exception as e:
            print(f"❌ PCAP replay error: {e}")
        finally:
            self._running = False

    # ── Simulation ──

    _ATTACK_PROFILES = {
        "Benign":       {"port_range": (1024, 65535), "size_range": (60, 1500), "burst": (1, 3)},
        "DDoS":         {"port_range": (80, 443),     "size_range": (60, 200),  "burst": (10, 50)},
        "DoS Hulk":     {"port_range": (80, 80),      "size_range": (800, 1500),"burst": (5, 20)},
        "DoS GoldenEye":{"port_range": (80, 443),     "size_range": (200, 600), "burst": (3, 15)},
        "DoS Slowloris":{"port_range": (80, 80),      "size_range": (60, 100),  "burst": (1, 3)},
        "PortScan":     {"port_range": (1, 1024),     "size_range": (40, 60),   "burst": (5, 30)},
        "FTP-Patator":  {"port_range": (21, 21),      "size_range": (60, 200),  "burst": (3, 10)},
        "SSH-Patator":  {"port_range": (22, 22),      "size_range": (60, 200),  "burst": (3, 10)},
        "Bot":          {"port_range": (1024, 65535),  "size_range": (100, 500), "burst": (1, 5)},
        "Web Attack":   {"port_range": (80, 443),     "size_range": (200, 2000),"burst": (1, 5)},
        "Heartbleed":   {"port_range": (443, 443),    "size_range": (40, 16384),"burst": (1, 2)},
        "Infiltration": {"port_range": (1024, 65535),  "size_range": (100, 1000),"burst": (1, 3)},
    }

    _ATTACK_WEIGHTS = {
        "DDoS": 1,
        "DoS Hulk": 1,
        "DoS GoldenEye": 1,
        "DoS Slowloris": 1,
        "PortScan": 2,
        "FTP-Patator": 2,
        "SSH-Patator": 2,
        "Bot": 2,
        "Web Attack": 2,
        "Heartbleed": 1,
        "Infiltration": 2,
    }

    _COMMON_SRC_IPS = [
        "192.168.1.{}",  "10.0.0.{}",  "172.16.0.{}",     # Internal
        "203.0.113.{}",  "198.51.100.{}",  "45.33.32.{}",  # External
        "185.220.101.{}", "91.219.236.{}",  "77.247.181.{}",  # Suspicious
    ]

    def _simulate(self, callback):
        """Generate realistic simulated network traffic."""
        print("🟢 Simulation mode — generating synthetic traffic")
        seq = 0
        attack_labels = [name for name in self._ATTACK_PROFILES.keys() if name != "Benign"]
        attack_weights = [self._ATTACK_WEIGHTS.get(name, 1) for name in attack_labels]
        while self._running:
            # 70% benign, 30% attacks
            if random.random() < 0.70:
                profile_name = "Benign"
            else:
                profile_name = random.choices(attack_labels, weights=attack_weights, k=1)[0]

            profile = self._ATTACK_PROFILES.get(profile_name, self._ATTACK_PROFILES["Benign"])
            burst = random.randint(*profile["burst"])
            src_template = random.choice(self._COMMON_SRC_IPS)
            src_ip = src_template.format(random.randint(1, 254))
            dst_ip = f"192.168.1.{random.randint(1, 10)}"

            # Set port and protocol ONCE per burst so all packets
            # in this burst belong to the same flow (same 5-tuple)
            src_port = random.randint(1024, 65535)
            dst_port = random.randint(*profile["port_range"])
            proto = random.choice(["TCP", "TCP", "TCP", "UDP"])

            for i in range(burst):
                if not self._running:
                    return
                pkt = PacketInfo(
                    timestamp=time.time(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    length=random.randint(*profile["size_range"]),
                    payload_len=random.randint(0, profile["size_range"][1] - 40),
                    tcp_flags=random.choice([0x02, 0x10, 0x18, 0x11, 0x04, 0x14]),
                    window_size=random.randint(1024, 65535),
                    header_len=random.choice([20, 32, 40])
                )
                # Alternate direction: odd packets go "backward" (dst→src)
                if i % 3 == 2:
                    pkt.src_ip, pkt.dst_ip = pkt.dst_ip, pkt.src_ip
                    pkt.src_port, pkt.dst_port = pkt.dst_port, pkt.src_port
                callback(pkt)
                seq += 1

            time.sleep(random.uniform(0.01, 0.08))
