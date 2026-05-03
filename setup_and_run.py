# setup_and_run.py — One-click launcher for the AI-Powered IDS
"""
Downloads any missing dependencies, checks for a trained model,
lists network interfaces, and starts the IDS in the best available mode.

Usage:
    python setup_and_run.py              # Auto setup + run
    python setup_and_run.py --skip-deps  # Skip dependency check
    python setup_and_run.py --dashboard  # Also launch Streamlit dashboard
"""

import subprocess
import sys
import os
import time

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)


def print_banner():
    print("\n" + "=" * 60)
    print("🛡️  AI-POWERED INTRUSION DETECTION SYSTEM — SETUP")
    print("=" * 60)


def check_python():
    """Check Python version."""
    v = sys.version_info
    print(f"\n✅ Python {v.major}.{v.minor}.{v.micro}")
    if v.major < 3 or (v.major == 3 and v.minor < 8):
        print("❌ Python 3.8+ is required.")
        sys.exit(1)


def install_dependencies():
    """Install dependencies from requirements.txt."""
    req_file = os.path.join(PROJECT_DIR, "requirements.txt")
    if not os.path.exists(req_file):
        print("❌ requirements.txt not found.")
        return False

    print("\n📦 Checking dependencies...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", req_file, "-q"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0:
            print("✅ All dependencies installed.")
            return True
        else:
            print(f"⚠️  pip install had issues: {result.stderr[:200]}")
            return True  # Continue anyway
    except Exception as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False


def check_model():
    """Check if a trained model exists."""
    from config import MODEL_PATH
    if os.path.exists(MODEL_PATH):
        size_mb = os.path.getsize(MODEL_PATH) / (1024 * 1024)
        print(f"\n✅ Trained model found ({size_mb:.0f} MB): {os.path.basename(MODEL_PATH)}")
        return True
    else:
        print(f"\n⚠️  No trained model found at: {MODEL_PATH}")
        print("   The IDS will run in demo mode (random predictions).")
        print("   To train a model, place CIC-IDS2017 CSVs in data/raw/ and run:")
        print("     python data_processing.py")
        print("     python prepare_data.py")
        print("     python train_model.py")
        return False


def show_interfaces():
    """Show available network interfaces."""
    try:
        from realtime.packet_capture import list_interfaces
        interfaces = list_interfaces()
        if interfaces:
            print("\n🌐 Network Interfaces:")
            for iface in interfaces:
                status = "🟢 UP" if iface["is_up"] else "🔴 DOWN"
                print(f"   {status}  {iface['name']:<30} IP: {iface['ipv4']:<16}")
        else:
            print("\n⚠️  No interfaces detected")
    except Exception as e:
        print(f"\n⚠️  Could not list interfaces: {e}")


def detect_mode():
    """Detect the best capture mode."""
    try:
        from realtime.packet_capture import detect_best_mode
        mode = detect_best_mode()
        mode_labels = {
            "scapy": "Scapy (full packet capture, admin required)",
            "psutil": "psutil (connection monitoring, no admin needed)",
            "simulation": "Simulation (synthetic traffic, demo only)"
        }
        print(f"\n🔍 Best capture mode: {mode_labels.get(mode, mode)}")
        return mode
    except Exception:
        return "simulation"


def run_ids(mode, duration):
    """Start the IDS engine."""
    print(f"\n🚀 Starting IDS in '{mode}' mode for {duration} seconds...")
    print("   Press Ctrl+C to stop early.\n")

    try:
        subprocess.run(
            [sys.executable, "run_ids.py", "--mode", mode, "--duration", str(duration)],
            cwd=PROJECT_DIR
        )
    except KeyboardInterrupt:
        print("\n⏹  Stopped by user.")


def launch_dashboard():
    """Launch the Streamlit dashboard in a new process."""
    print("\n🌐 Launching Streamlit dashboard...")
    try:
        subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", "dashboard/app.py",
             "--server.headless", "true"],
            cwd=PROJECT_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("   Dashboard starting at http://localhost:8501")
        time.sleep(2)  # Give it a moment to start
    except Exception as e:
        print(f"⚠️  Could not launch dashboard: {e}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="IDS Setup & Launcher")
    parser.add_argument("--skip-deps", action="store_true", help="Skip dependency install")
    parser.add_argument("--dashboard", action="store_true", help="Also launch Streamlit dashboard")
    parser.add_argument("--duration", type=int, default=120, help="Run duration (default: 120s)")
    parser.add_argument("--mode", default="auto", help="Capture mode (default: auto)")
    args = parser.parse_args()

    print_banner()
    check_python()

    if not args.skip_deps:
        install_dependencies()

    check_model()
    show_interfaces()
    mode = args.mode if args.mode != "auto" else detect_mode()

    if args.dashboard:
        launch_dashboard()

    run_ids(mode, args.duration)


if __name__ == "__main__":
    main()
