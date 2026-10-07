"""
AI-NIDS Live Packet Capture Agent
==================================
Run this script as Administrator to start capturing packets from a
network interface. Completed flows are scored by the Random Forest
in real-time and streamed to the dashboard.

Usage
-----
    python capture_agent.py                        # auto-detect active interface
    python capture_agent.py --iface "Wi-Fi"        # use specific interface
    python capture_agent.py --list                 # list available interfaces

Requirements
------------
    • Npcap installed (https://npcap.com) — free, from the Nmap project
    • Run as Administrator (packet capture requires elevated privileges)
    • pip install scapy  (already done if you followed setup)

How it works
------------
1. Scapy sniffs packets on the chosen interface.
2. Each packet is handed to capture_service.record_packet() which groups
   packets into bidirectional flows by 5-tuple.
3. When a flow ends (FIN/RST, idle timeout, or packet cap), its ~35
   CICIDS2017 features are computed and pushed onto capture_service.flow_queue.
4. The FastAPI /api/capture/stream endpoint reads from that queue, scores
   each flow through the production Random Forest, and streams results
   to the dashboard over SSE.

You do NOT need to restart the backend when starting/stopping the agent.
The SSE endpoint polls the queue and will start showing results as soon
as the agent begins pushing flows.
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path

# --------------------------------------------------------------------------- #
# Make sure the backend package is importable
# --------------------------------------------------------------------------- #
BACKEND_DIR = Path(__file__).parent
sys.path.insert(0, str(BACKEND_DIR))

try:
    from app.services import capture_service
except ImportError as exc:
    print(f"[ERROR] Cannot import capture_service: {exc}")
    print("Run this script from the backend/ directory.")
    sys.exit(1)

# --------------------------------------------------------------------------- #
# Scapy import (warn clearly if missing)
# --------------------------------------------------------------------------- #
try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import IP, TCP, UDP, conf, sniff
    from scapy.arch.windows import get_windows_if_list
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def list_interfaces() -> list[dict]:
    if not SCAPY_OK:
        return []
    try:
        return get_windows_if_list()
    except Exception:
        return []


def pick_interface(name: str | None) -> str | None:
    """Return the Npcap device name for the given friendly name (or auto-detect)."""
    ifaces = list_interfaces()
    if not ifaces:
        return None

    if name:
        name_lower = name.lower()
        for iface in ifaces:
            if (iface.get("name", "").lower() == name_lower or
                    iface.get("description", "").lower().startswith(name_lower)):
                return iface.get("name")
        print(f"[WARN] Interface '{name}' not found. Available:")
        for iface in ifaces:
            print(f"  {iface['name']} — {iface.get('description','')}")
        return None

    # Auto-detect: prefer Wi-Fi or Ethernet with an actual IPv4 address
    for iface in ifaces:
        ips = iface.get("ips", [])
        has_ipv4 = any("." in ip and not ip.startswith("169.254") for ip in ips)
        desc = iface.get("description", "").lower()
        if has_ipv4 and ("wi-fi" in desc or "wifi" in desc or
                         "intel" in desc or "wireless" in desc):
            return iface.get("name")

    for iface in ifaces:
        ips = iface.get("ips", [])
        has_ipv4 = any("." in ip and not ip.startswith("169.254") for ip in ips)
        if has_ipv4:
            return iface.get("name")

    return ifaces[0].get("name") if ifaces else None


def _process_packet(pkt) -> None:
    """Scapy packet callback — called once per captured packet."""
    try:
        if IP not in pkt:
            return

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else ip.proto)
        size = len(ip.payload)
        ts = float(pkt.time)

        tcp_flags = 0
        tcp_window = 0
        tcp_hdr_len = 0
        has_payload = False
        src_port = 0
        dst_port = 0

        if TCP in pkt:
            tcp = pkt[TCP]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            tcp_flags = int(tcp.flags)
            tcp_window = int(tcp.window)
            tcp_hdr_len = int(tcp.dataofs) * 4 if tcp.dataofs else 20
            has_payload = len(tcp.payload) > 0
        elif UDP in pkt:
            udp = pkt[UDP]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            has_payload = len(udp.payload) > 0

        capture_service.record_packet(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto=str(proto),
            size=size,
            timestamp=ts,
            tcp_flags=tcp_flags,
            tcp_window=tcp_window,
            tcp_hdr_len=tcp_hdr_len,
            has_payload=has_payload,
        )
    except Exception:
        pass  # never crash the sniff loop


# --------------------------------------------------------------------------- #
# Idle-flow expiry thread
# --------------------------------------------------------------------------- #
def _expire_loop(stop_event: threading.Event) -> None:
    """Periodically flush flows that went idle without a FIN/RST."""
    while not stop_event.is_set():
        try:
            expired = capture_service.expire_idle_flows()
            if expired:
                print(f"  [expire] flushed {expired} idle flow(s)", flush=True)
        except Exception:
            pass
        stop_event.wait(timeout=capture_service.IDLE_TIMEOUT_S / 2)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-NIDS Live Packet Capture Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--iface", "-i",
        default=None,
        help="Network interface name (e.g. 'Wi-Fi', 'Ethernet'). "
             "Auto-detected if omitted.",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    parser.add_argument(
        "--filter", "-f",
        default="ip",
        help="BPF filter string (default: 'ip'). "
             "Example: 'tcp port 80' or 'not host 127.0.0.1'.",
    )
    args = parser.parse_args()

    if not SCAPY_OK:
        print("[ERROR] scapy is not installed. Run:  pip install scapy")
        sys.exit(1)

    # --list
    if args.list:
        print("Available network interfaces:")
        for iface in list_interfaces():
            ips = ", ".join(iface.get("ips", []))
            print(f"  {iface['name']!r:40s}  {iface.get('description','')}  [{ips}]")
        return

    iface = pick_interface(args.iface)
    if iface is None:
        print("[ERROR] Could not find a suitable network interface.")
        print("        Try --list to see available interfaces, then --iface <name>.")
        sys.exit(1)

    # Suppress scapy's default verbose output
    conf.verb = 0

    print("=" * 60)
    print("  AI-NIDS Live Packet Capture Agent")
    print("=" * 60)
    print(f"  Interface : {iface}")
    print(f"  BPF filter: {args.filter}")
    print(f"  Idle timeout : {capture_service.IDLE_TIMEOUT_S}s")
    print(f"  Max flow pkts: {capture_service.MAX_FLOW_PACKETS}")
    print()
    print("  Scoring endpoint: http://localhost:8000/api/capture/stream")
    print("  Dashboard:        http://localhost:5173  → Data → Live Capture")
    print()
    print("  Press Ctrl+C to stop.")
    print("=" * 60)

    capture_service.reset()
    capture_service.set_active(True)

    stop_event = threading.Event()
    expire_thread = threading.Thread(
        target=_expire_loop, args=(stop_event,), daemon=True
    )
    expire_thread.start()

    pkt_count = 0
    flow_count = 0
    last_report = time.time()

    def status_report() -> None:
        nonlocal pkt_count, flow_count, last_report
        now = time.time()
        if now - last_report >= 5:
            q = capture_service.flow_queue.qsize()
            active = len(capture_service._flows)
            print(
                f"  packets={pkt_count:6d}  flows_completed={flow_count:5d}"
                f"  active_flows={active:4d}  queue={q:3d}",
                flush=True,
            )
            last_report = now

    def packet_callback(pkt) -> None:
        nonlocal pkt_count, flow_count
        prev_q = capture_service.flow_queue.qsize()
        _process_packet(pkt)
        pkt_count += 1
        new_q = capture_service.flow_queue.qsize()
        if new_q > prev_q:
            flow_count += (new_q - prev_q)
        status_report()

    try:
        sniff(
            iface=iface,
            filter=args.filter,
            prn=packet_callback,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n  Stopping capture…")
    except PermissionError:
        print("\n[ERROR] Permission denied. Run this script as Administrator.")
        sys.exit(1)
    except Exception as exc:
        print(f"\n[ERROR] {exc}")
        sys.exit(1)
    finally:
        stop_event.set()
        capture_service.set_active(False)
        capture_service.expire_idle_flows()
        print(f"  Done. Captured {pkt_count} packets, completed {flow_count} flows.")


if __name__ == "__main__":
    main()
