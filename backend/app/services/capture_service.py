"""
Live packet capture service.

The sniffer runs as a daemon thread inside the FastAPI process — no external
script or administrator terminal required.  The frontend calls:

  POST /api/capture/start   → spins up the sniffer thread
  POST /api/capture/stop    → stops it
  GET  /api/capture/status  → current state
  GET  /api/capture/stream  → SSE stream of scored flows

Flow lifecycle
--------------
Packets are grouped into bidirectional flows by 5-tuple
(src_ip, src_port, dst_ip, dst_port, protocol).

A flow is considered complete when any of:
  • TCP FIN or RST seen
  • Idle for IDLE_TIMEOUT_S seconds
  • Accumulated MAX_FLOW_PACKETS packets

On completion ~35 CICIDS2017 features are computed and pushed onto
flow_queue where the SSE endpoint reads and scores them.
"""

from __future__ import annotations

import logging
import math
import queue
import statistics
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ainids.capture")

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
IDLE_TIMEOUT_S: float = 3.0
MAX_FLOW_PACKETS: int = 300
QUEUE_MAXSIZE: int = 500

# --------------------------------------------------------------------------- #
# Shared state (module-level so the API and the thread share the same objects)
# --------------------------------------------------------------------------- #
flow_queue: queue.Queue = queue.Queue(maxsize=QUEUE_MAXSIZE)
_flows: dict[tuple, "_Flow"] = {}
_lock = threading.Lock()

_sniffer_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()
_capture_active: bool = False
_capture_iface: Optional[str] = None
_capture_error: Optional[str] = None
_packet_count: int = 0
_flow_count: int = 0


def status() -> dict:
    return {
        "agent_running": _capture_active,
        "interface": _capture_iface,
        "packet_count": _packet_count,
        "flow_count": _flow_count,
        "queue_depth": flow_queue.qsize(),
        "error": _capture_error,
    }


def is_active() -> bool:
    return _capture_active


def reset_queue() -> None:
    while not flow_queue.empty():
        try:
            flow_queue.get_nowait()
        except queue.Empty:
            break


# --------------------------------------------------------------------------- #
# Auto-detect the best network interface
# --------------------------------------------------------------------------- #
def _pick_interface(preferred: Optional[str] = None) -> Optional[str]:
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
    except Exception:
        return preferred  # non-Windows or scapy unavailable — caller will handle

    if preferred:
        pl = preferred.lower()
        for iface in ifaces:
            if (iface.get("name", "").lower() == pl or
                    iface.get("description", "").lower().startswith(pl)):
                return iface.get("name")

    # Prefer Wi-Fi with a real IPv4
    for iface in ifaces:
        ips = iface.get("ips", [])
        has_ipv4 = any("." in ip and not ip.startswith("169.254") for ip in ips)
        desc = iface.get("description", "").lower()
        if has_ipv4 and any(kw in desc for kw in ("wi-fi", "wifi", "intel", "wireless", "realtek")):
            return iface.get("name")
    # Fallback: any interface with a real IPv4
    for iface in ifaces:
        ips = iface.get("ips", [])
        has_ipv4 = any("." in ip and not ip.startswith("169.254") for ip in ips)
        if has_ipv4:
            return iface.get("name")
    return ifaces[0].get("name") if ifaces else None


def list_interfaces() -> list[dict]:
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        return [
            {
                "name": iface.get("name", ""),
                "description": iface.get("description", ""),
                "ips": iface.get("ips", []),
            }
            for iface in ifaces
            if iface.get("name")  # skip unnamed entries
        ]
    except Exception:
        return []


# --------------------------------------------------------------------------- #
# Per-flow accumulator
# --------------------------------------------------------------------------- #
@dataclass
class _Pkt:
    timestamp: float
    size: int
    is_fwd: bool
    tcp_flags: int = 0
    tcp_window: int = 0
    tcp_hdr_len: int = 0
    has_payload: bool = False


@dataclass
class _Flow:
    proto: str
    dst_port: Optional[int]
    pkts: list[_Pkt] = field(default_factory=list)
    first_ts: float = 0.0
    last_ts: float = 0.0
    fwd_init_win: int = 0
    bwd_init_win: int = 0
    fin_seen: bool = False
    rst_seen: bool = False

    def add(self, pkt: _Pkt) -> None:
        if not self.pkts:
            self.first_ts = pkt.timestamp
        self.last_ts = pkt.timestamp
        self.pkts.append(pkt)

    def is_done(self) -> bool:
        if self.fin_seen or self.rst_seen:
            return True
        if len(self.pkts) >= MAX_FLOW_PACKETS:
            return True
        if self.pkts and (time.time() - self.last_ts) > IDLE_TIMEOUT_S:
            return True
        return False


# --------------------------------------------------------------------------- #
# Feature computation
# --------------------------------------------------------------------------- #
def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    try:
        return statistics.stdev(values)
    except Exception:
        return 0.0


def _build_features(flow: _Flow) -> dict:
    pkts = flow.pkts
    if not pkts:
        return {}

    fwd = [p for p in pkts if p.is_fwd]
    bwd = [p for p in pkts if not p.is_fwd]

    duration_us = (flow.last_ts - flow.first_ts) * 1_000_000
    duration_s = max(duration_us / 1_000_000, 1e-6)

    fwd_sizes = [p.size for p in fwd]
    bwd_sizes = [p.size for p in bwd]
    all_sizes = [p.size for p in pkts]
    total_bytes = sum(all_sizes)
    total_pkts = len(pkts)

    all_ts = [p.timestamp * 1_000_000 for p in pkts]
    all_iats = [all_ts[i+1] - all_ts[i] for i in range(len(all_ts)-1)] or [0.0]
    fwd_ts = [p.timestamp * 1_000_000 for p in fwd]
    fwd_iats = [fwd_ts[i+1] - fwd_ts[i] for i in range(len(fwd_ts)-1)] or [0.0]
    bwd_ts = [p.timestamp * 1_000_000 for p in bwd]
    bwd_iats = [bwd_ts[i+1] - bwd_ts[i] for i in range(len(bwd_ts)-1)] or [0.0]

    fin = sum(1 for p in pkts if p.tcp_flags & 0x01)
    syn = sum(1 for p in pkts if p.tcp_flags & 0x02)
    rst = sum(1 for p in pkts if p.tcp_flags & 0x04)
    psh = sum(1 for p in pkts if p.tcp_flags & 0x08)
    ack = sum(1 for p in pkts if p.tcp_flags & 0x10)
    urg = sum(1 for p in pkts if p.tcp_flags & 0x20)
    cwe = sum(1 for p in pkts if p.tcp_flags & 0x80)
    ece = sum(1 for p in pkts if p.tcp_flags & 0x40)

    fwd_psh = sum(1 for p in fwd if p.tcp_flags & 0x08)
    fwd_urg = sum(1 for p in fwd if p.tcp_flags & 0x20)
    fwd_hdr = sum(p.tcp_hdr_len for p in fwd if p.tcp_hdr_len)
    bwd_hdr = sum(p.tcp_hdr_len for p in bwd if p.tcp_hdr_len)
    act_data_fwd = sum(1 for p in fwd if p.has_payload)
    min_seg_fwd = min((p.tcp_hdr_len for p in fwd if p.tcp_hdr_len), default=0)
    fwd_len_total = sum(fwd_sizes)
    bwd_len_total = sum(bwd_sizes)

    features = {
        "Destination Port":             float(flow.dst_port or 0),
        "Flow Duration":                duration_us,
        "Total Fwd Packets":            float(len(fwd)),
        "Total Backward Packets":       float(len(bwd)),
        "Total Length of Fwd Packets":  float(fwd_len_total),
        "Total Length of Bwd Packets":  float(bwd_len_total),
        "Fwd Packet Length Max":        float(max(fwd_sizes, default=0)),
        "Fwd Packet Length Min":        float(min(fwd_sizes, default=0)),
        "Fwd Packet Length Mean":       float(fwd_len_total / len(fwd)) if fwd else 0.0,
        "Fwd Packet Length Std":        _std([float(x) for x in fwd_sizes]),
        "Bwd Packet Length Max":        float(max(bwd_sizes, default=0)),
        "Bwd Packet Length Min":        float(min(bwd_sizes, default=0)),
        "Bwd Packet Length Mean":       float(bwd_len_total / len(bwd)) if bwd else 0.0,
        "Bwd Packet Length Std":        _std([float(x) for x in bwd_sizes]),
        "Flow Bytes/s":                 total_bytes / duration_s,
        "Flow Packets/s":               total_pkts / duration_s,
        "Flow IAT Mean":                statistics.mean(all_iats),
        "Flow IAT Std":                 _std(all_iats),
        "Flow IAT Max":                 max(all_iats),
        "Flow IAT Min":                 min(all_iats),
        "Fwd IAT Total":                sum(fwd_iats),
        "Fwd IAT Mean":                 statistics.mean(fwd_iats),
        "Fwd IAT Std":                  _std(fwd_iats),
        "Fwd IAT Max":                  max(fwd_iats),
        "Fwd IAT Min":                  min(fwd_iats),
        "Bwd IAT Total":                sum(bwd_iats),
        "Bwd IAT Mean":                 statistics.mean(bwd_iats),
        "Bwd IAT Std":                  _std(bwd_iats),
        "Bwd IAT Max":                  max(bwd_iats),
        "Bwd IAT Min":                  min(bwd_iats),
        "Fwd PSH Flags":                float(fwd_psh),
        "Fwd URG Flags":                float(fwd_urg),
        "Fwd Header Length":            float(fwd_hdr),
        "Bwd Header Length":            float(bwd_hdr),
        "Fwd Packets/s":                len(fwd) / duration_s,
        "Bwd Packets/s":                len(bwd) / duration_s,
        "Min Packet Length":            float(min(all_sizes, default=0)),
        "Max Packet Length":            float(max(all_sizes, default=0)),
        "Packet Length Mean":           float(total_bytes / total_pkts) if total_pkts else 0.0,
        "Packet Length Std":            _std([float(x) for x in all_sizes]),
        "Packet Length Variance":       _std([float(x) for x in all_sizes]) ** 2,
        "FIN Flag Count":               float(fin),
        "SYN Flag Count":               float(syn),
        "RST Flag Count":               float(rst),
        "PSH Flag Count":               float(psh),
        "ACK Flag Count":               float(ack),
        "URG Flag Count":               float(urg),
        "CWE Flag Count":               float(cwe),
        "ECE Flag Count":               float(ece),
        "Down/Up Ratio":                (bwd_len_total / fwd_len_total) if fwd_len_total else 0.0,
        "Average Packet Size":          (total_bytes / total_pkts) if total_pkts else 0.0,
        "Avg Fwd Segment Size":         (fwd_len_total / len(fwd)) if fwd else 0.0,
        "Avg Bwd Segment Size":         (bwd_len_total / len(bwd)) if bwd else 0.0,
        "Fwd Header Length_duplicated_0": float(fwd_hdr),
        "Subflow Fwd Packets":          float(len(fwd)),
        "Subflow Fwd Bytes":            float(fwd_len_total),
        "Subflow Bwd Packets":          float(len(bwd)),
        "Subflow Bwd Bytes":            float(bwd_len_total),
        "Init_Win_bytes_forward":       float(flow.fwd_init_win),
        "Init_Win_bytes_backward":      float(flow.bwd_init_win),
        "act_data_pkt_fwd":             float(act_data_fwd),
        "min_seg_size_forward":         float(min_seg_fwd),
        "Active Mean": float("nan"), "Active Std": float("nan"),
        "Active Max":  float("nan"), "Active Min": float("nan"),
        "Idle Mean":   float("nan"), "Idle Std":   float("nan"),
        "Idle Max":    float("nan"), "Idle Min":   float("nan"),
    }
    return {k: (None if isinstance(v, float) and not math.isfinite(v) else v)
            for k, v in features.items()}


# --------------------------------------------------------------------------- #
# Packet handler (called inside the sniffer thread)
# --------------------------------------------------------------------------- #
def _process_packet(pkt) -> None:
    global _packet_count, _flow_count
    try:
        from scapy.all import IP, TCP, UDP
        if IP not in pkt:
            return

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        size = len(ip.payload)
        ts = float(pkt.time)

        tcp_flags = tcp_window = tcp_hdr_len = 0
        has_payload = False
        src_port = dst_port = 0
        proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else str(ip.proto))

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

        _packet_count += 1

        if (src_ip, src_port) < (dst_ip, dst_port):
            key = (src_ip, src_port, dst_ip, dst_port, proto)
            is_fwd = True
        else:
            key = (dst_ip, dst_port, src_ip, src_port, proto)
            is_fwd = False

        pkt_obj = _Pkt(ts, size, is_fwd, tcp_flags, tcp_window, tcp_hdr_len, has_payload)

        with _lock:
            if key not in _flows:
                _flows[key] = _Flow(proto=proto, dst_port=dst_port)
            fl = _flows[key]
            if tcp_window and is_fwd and fl.fwd_init_win == 0:
                fl.fwd_init_win = tcp_window
            if tcp_window and not is_fwd and fl.bwd_init_win == 0:
                fl.bwd_init_win = tcp_window
            if tcp_flags & 0x01:
                fl.fin_seen = True
            if tcp_flags & 0x04:
                fl.rst_seen = True
            fl.add(pkt_obj)

            if fl.is_done():
                features = _build_features(fl)
                del _flows[key]
                if features:
                    _flow_count += 1
                    try:
                        flow_queue.put_nowait({
                            "features": features,
                            "src_ip": src_ip, "dst_ip": dst_ip,
                            "src_port": src_port, "dst_port": dst_port,
                            "proto": proto,
                            "duration_us": features.get("Flow Duration", 0),
                            "packet_rate": features.get("Flow Packets/s", 0),
                        })
                    except queue.Full:
                        pass
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Idle-flow expiry (runs in a sub-thread)
# --------------------------------------------------------------------------- #
def _expire_loop(stop: threading.Event) -> None:
    while not stop.is_set():
        stop.wait(timeout=IDLE_TIMEOUT_S / 2)
        try:
            with _lock:
                to_expire = [k for k, fl in list(_flows.items()) if fl.is_done()]
                for key in to_expire:
                    fl = _flows.pop(key)
                    features = _build_features(fl)
                    if features:
                        global _flow_count
                        _flow_count += 1
                        try:
                            flow_queue.put_nowait({
                                "features": features,
                                "src_ip": key[0], "dst_ip": key[2],
                                "src_port": key[1], "dst_port": key[3],
                                "proto": key[4],
                                "duration_us": features.get("Flow Duration", 0),
                                "packet_rate": features.get("Flow Packets/s", 0),
                            })
                        except queue.Full:
                            pass
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Sniffer thread body
# --------------------------------------------------------------------------- #
def _npcap_installed() -> bool:
    """Check if Npcap DLLs are present on this Windows machine."""
    import os
    paths = [
        r"C:\Windows\System32\Npcap\wpcap.dll",
        r"C:\Windows\SysWOW64\Npcap\wpcap.dll",
        r"C:\Windows\System32\wpcap.dll",
    ]
    return any(os.path.exists(p) for p in paths)


def _sniffer_thread_body(iface: str, stop: threading.Event) -> None:
    global _capture_active, _capture_error
    try:
        import logging as _logging
        _logging.getLogger("scapy.runtime").setLevel(_logging.ERROR)
        from scapy.all import conf, sniff
        conf.verb = 0

        logger.info("capture started on interface: %s", iface)

        expire_stop = threading.Event()
        expire_thread = threading.Thread(target=_expire_loop, args=(expire_stop,), daemon=True)
        expire_thread.start()

        def should_stop(pkt):
            return stop.is_set()

        sniff(
            iface=iface,
            filter="ip",
            prn=_process_packet,
            store=False,
            stop_filter=should_stop,
        )

        expire_stop.set()
        expire_thread.join(timeout=3)

    except Exception as exc:
        err_str = str(exc)
        if "winpcap" in err_str.lower() or "layer 2" in err_str.lower() or "not available" in err_str.lower() or "libpcap" in err_str.lower():
            _capture_error = "NPCAP_MISSING"
        elif "permission" in err_str.lower() or "access" in err_str.lower():
            _capture_error = "PERMISSION_DENIED"
        else:
            _capture_error = err_str
        logger.error("capture error: %s", err_str)
    finally:
        _capture_active = False
        logger.info("capture stopped")


# --------------------------------------------------------------------------- #
# Public start / stop API
# --------------------------------------------------------------------------- #
def start_capture(iface: Optional[str] = None) -> dict:
    global _sniffer_thread, _stop_event, _capture_active, _capture_iface
    global _capture_error, _packet_count, _flow_count

    if _capture_active and _sniffer_thread and _sniffer_thread.is_alive():
        return {"started": False, "reason": "already_running", "interface": _capture_iface}

    # Check Npcap before attempting anything
    if not _npcap_installed():
        return {
            "started": False,
            "reason": "npcap_missing",
            "error": "NPCAP_MISSING",
        }

    resolved = _pick_interface(iface)
    if resolved is None:
        return {
            "started": False,
            "reason": "no_interface_found",
            "hint": "Could not find a suitable network interface.",
        }

    # Reset state
    _stop_event = threading.Event()
    _packet_count = 0
    _flow_count = 0
    _capture_error = None
    _capture_iface = resolved
    with _lock:
        _flows.clear()
    reset_queue()

    _capture_active = True
    _sniffer_thread = threading.Thread(
        target=_sniffer_thread_body,
        args=(resolved, _stop_event),
        daemon=True,
        name="nids-sniffer",
    )
    _sniffer_thread.start()

    # Give the thread 2 seconds to fail fast
    _sniffer_thread.join(timeout=2.0)
    if not _sniffer_thread.is_alive():
        _capture_active = False
        return {
            "started": False,
            "reason": "sniffer_failed",
            "error": _capture_error or "Sniffer thread exited immediately.",
        }

    logger.info("capture thread running on %s", resolved)
    return {"started": True, "interface": resolved}


def stop_capture() -> dict:
    global _capture_active
    if not _capture_active:
        return {"stopped": False, "reason": "not_running"}
    _stop_event.set()
    _capture_active = False
    return {"stopped": True}
