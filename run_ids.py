# run_ids.py — CLI entry point for the Real-Time AI IDS Engine
"""
Usage:
    python run_ids.py                          # Auto-detect best mode
    python run_ids.py --mode auto              # Auto-detect (same as default)
    python run_ids.py --mode psutil            # Real connections via psutil (no admin)
    python run_ids.py --mode simulation        # Synthetic traffic (demo)
    python run_ids.py --mode live --iface "Wi-Fi"  # Scapy live capture (admin)
    python run_ids.py --list-interfaces        # Show available interfaces
"""

import argparse
import signal
import sys
import os
import time
import socket
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from realtime.realtime_engine import RealtimeIDSEngine
from realtime.packet_capture import (
    list_interfaces,
    list_scapy_interfaces,
    detect_best_mode,
)
from config import FLOW_TIMEOUT


def show_interfaces():
    """Print available network interfaces."""
    print("\n" + "=" * 60)
    print("🌐 AVAILABLE NETWORK INTERFACES (PSUTIL)")
    print("=" * 60)
    interfaces = list_interfaces()
    if interfaces:
        for iface in interfaces:
            status = "🟢 UP" if iface["is_up"] else "🔴 DOWN"
            speed = f"{iface['speed']}Mbps" if iface["speed"] else "N/A"
            print(f"  {status}  {iface['name']:<30} IP: {iface['ipv4']:<16} Speed: {speed}")
    else:
        print("  (No interfaces detected via psutil)")

    print("\n" + "=" * 60)
    print("🕷️  SCAPY INTERFACES")
    print("=" * 60)
    scapy_interfaces = list_scapy_interfaces()
    if scapy_interfaces:
        for iface in scapy_interfaces:
            name = str(iface.get("name") or "?")
            scapy_name = str(iface.get("scapy_name") or "?")
            desc = str(iface.get("description") or "")
            print(f"  Name: {name}")
            print(f"    Scapy: {scapy_name}")
            if desc:
                print(f"    Desc:  {desc}")
    else:
        print("  (No Scapy interfaces visible. Install Npcap in WinPcap-compatible mode.)")

    print("=" * 60 + "\n")


def start_self_test_traffic(target_host, target_port, duration, rate_per_second=20):
    """Generate short TCP connection bursts for local IDS validation.

    This is for lab verification only and avoids requiring a local test server.
    """
    stop_event = threading.Event()

    def worker():
        end_time = time.time() + max(1, duration)
        batch_interval = 0.5
        per_batch = max(1, int(rate_per_second * batch_interval))
        scan_ports = [
            target_port, 80, 443, 8080, 8443, 22, 21, 25,
            110, 143, 3306, 3389, 445, 139, 53
        ]
        scan_index = 0

        print(
            f"\n🧪 Self-test traffic enabled: {target_host}:{target_port} | "
            f"~{rate_per_second} connects/sec for {duration}s"
        )

        while not stop_event.is_set() and time.time() < end_time:
            for _ in range(per_batch):
                if stop_event.is_set():
                    break
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.settimeout(0.35)
                    # Mostly burst traffic to one service, with periodic
                    # multi-port probes to exercise scan detection.
                    if (_ % 5) == 0:
                        port = scan_ports[scan_index % len(scan_ports)]
                        scan_index += 1
                    else:
                        port = target_port
                    s.connect_ex((target_host, int(port)))
                except Exception:
                    pass
                finally:
                    s.close()
            time.sleep(batch_interval)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return stop_event, t


def main():
    parser = argparse.ArgumentParser(
        description="AI-Powered Real-Time IDS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Capture Modes:
  auto        Auto-detect best available (Scapy → psutil → simulation)
  psutil      Monitor real connections via psutil (no admin/Npcap needed)
  live/scapy  Full packet capture via Scapy (requires admin + Npcap)
  simulation  Generate synthetic traffic (demo/testing only)

Examples:
  python run_ids.py                          # Auto-detect, run 60s
  python run_ids.py --mode psutil -d 120     # Real monitoring for 2 min
    python run_ids.py --mode psutil -d 120 --self-test-traffic
  python run_ids.py --mode simulation -d 30  # Demo for 30s
  python run_ids.py --list-interfaces        # Show network interfaces
        """
    )
    parser.add_argument("--mode", "-m",
                        choices=["auto", "simulation", "psutil", "live", "scapy", "pcap"],
                        default="auto",
                        help="Capture mode (default: auto)")
    parser.add_argument("--iface", "-i", type=str, default=None,
                        help="Network interface for Scapy capture (e.g., 'Wi-Fi', 'eth0')")
    parser.add_argument("--timeout", "-t", type=int, default=FLOW_TIMEOUT,
                        help=f"Flow timeout in seconds (default: {FLOW_TIMEOUT})")
    parser.add_argument("--duration", "-d", type=int, default=60,
                        help="Run duration in seconds (default: 60)")
    parser.add_argument("--pcap", type=str, default=None,
                        help="PCAP file path for --mode pcap replay")
    parser.add_argument("--model-path", type=str, default=None,
                        help="Optional model path override (.pkl)")
    parser.add_argument("--list-interfaces", "-l", action="store_true",
                        help="List available network interfaces and exit")
    parser.add_argument("--self-test-traffic", action="store_true",
                        help="Generate built-in lab traffic (no local test server needed)")
    parser.add_argument("--self-test-host", type=str, default="1.1.1.1",
                        help="Target host for self-test traffic (default: 1.1.1.1)")
    parser.add_argument("--self-test-port", type=int, default=443,
                        help="Target TCP port for self-test traffic (default: 443)")
    parser.add_argument("--self-test-rate", type=int, default=20,
                        help="Approximate connection attempts/sec for self-test (default: 20)")

    args = parser.parse_args()

    # Handle --list-interfaces
    if args.list_interfaces:
        show_interfaces()
        sys.exit(0)

    # Map legacy "live" to "scapy"
    mode = args.mode
    if mode == "live":
        mode = "scapy"

    # Show what mode will be used
    if mode == "auto":
        detected = detect_best_mode(args.iface)
        print(f"\n🔍 Auto-detected capture mode: {detected}")

    if mode == "scapy" and not args.iface:
        print("⚠️  Scapy mode selected without --iface. Use --list-interfaces to choose a valid adapter.")
    if mode == "pcap" and not args.pcap:
        print("❌ --mode pcap requires --pcap <file>.")
        sys.exit(1)

    engine = RealtimeIDSEngine(
        mode=mode,
        interface=args.iface,
        pcap_file=args.pcap,
        model_path=args.model_path,
        flow_timeout=args.timeout,
    )

    # Guard against double-stop
    stopped = False

    def shutdown():
        nonlocal stopped
        if stopped:
            return
        stopped = True
        print("\n\n⏹  Stopping IDS...")
        engine.stop()

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Start engine in background
    engine.start(blocking=False)

    traffic_stop = None
    traffic_thread = None
    if args.self_test_traffic:
        self_test_duration = min(max(10, args.duration - 5), args.duration)
        traffic_stop, traffic_thread = start_self_test_traffic(
            target_host=args.self_test_host,
            target_port=args.self_test_port,
            duration=self_test_duration,
            rate_per_second=max(1, args.self_test_rate),
        )

    try:
        remaining = args.duration
        while remaining > 0 and not stopped:
            time.sleep(1)
            remaining -= 1
            stats = engine.get_stats()
            mode_icon = {"scapy": "🔴", "psutil": "🟡", "simulation": "🟢"}.get(
                engine.resolved_mode, "⚪")
            sys.stdout.write(
                f"\r{mode_icon} {remaining}s left | "
                f"📦 {stats['packets_processed']} packets | "
                f"🔍 {stats['total_flows']} flows | "
                f"🚨 {stats['attack_flows']} attacks   "
            )
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        if traffic_stop:
            traffic_stop.set()
        if traffic_thread and traffic_thread.is_alive():
            traffic_thread.join(timeout=2)
        shutdown()


if __name__ == "__main__":
    main()
