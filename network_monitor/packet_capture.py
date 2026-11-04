"""
network_monitor/packet_capture.py
---------------------------------
Optional live network packet capture service using Scapy.
- Discovers system network interfaces
- Captures permitted IP/TCP/UDP/ICMP metadata safely in a background worker thread
- Aggregates flows using ConnectionFlow
- Evaluates flows through the ML anomaly detection pipeline
- Persists session and connection telemetry into SQLite
- Gracefully handles permission issues or absent Npcap/WinPcap drivers
"""

from __future__ import annotations

import logging
import os
import platform
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any

from database.db import DB_PATH
from ml.traffic_analyzer import (
    determine_severity_and_classification,
    generate_explanation,
    map_attack_category,
)
from network_monitor.traffic_processor import ConnectionFlow, determine_direction

logger = logging.getLogger(__name__)

SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP, UDP, ICMP, get_if_list, sniff
    SCAPY_AVAILABLE = True
except Exception as e:
    logger.warning("Scapy not fully functional or pcap missing: %s", e)


def get_available_interfaces() -> list[dict[str, str]]:
    """Return friendly list of network interfaces for administrator selection."""
    if not SCAPY_AVAILABLE:
        return [{"id": "lo", "name": "Loopback (No pcap available)", "status": "unavailable"}]

    try:
        raw_list = get_if_list()
        res = []
        for i, iface in enumerate(raw_list):
            friendly = f"Interface {i+1} ({iface[:36]}...)" if len(iface) > 36 else f"Interface {i+1} ({iface})"
            res.append({"id": iface, "name": friendly, "status": "available"})
        return res
    except Exception as exc:
        logger.error("Could not list interfaces: %s", exc)
        return [{"id": "default", "name": "Default Interface", "status": "unknown"}]


def get_local_ip_addresses() -> set[str]:
    """Retrieve local IP addresses of the host."""
    local_ips = {"127.0.0.1", "localhost", "::1"}
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            local_ips.add(ip)
    except Exception:
        pass
    return local_ips


class LiveCaptureService:
    """Manages an active network sniffing and analysis session."""

    _instance = None

    def __init__(self):
        self.is_running = False
        self.session_id: str | None = None
        self.interface: str | None = None
        self.worker_thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.active_flows: dict[tuple, ConnectionFlow] = {}
        self.flows_lock = threading.Lock()
        self.local_ips = get_local_ip_addresses()
        self.total_packets_captured = 0
        self.total_anomalies_detected = 0
        self.predictor = None
        self.db_path = DB_PATH
        self.error_message: str | None = None

    @classmethod
    def get_instance(cls) -> "LiveCaptureService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def set_predictor(self, predictor_dict):
        self.predictor = predictor_dict

    def start_capture(self, interface: str | None = None) -> tuple[bool, str]:
        """Start background packet sniffing on the selected interface."""
        if self.is_running:
            return False, "Capture session is already running."

        if not SCAPY_AVAILABLE:
            return False, "Scapy or WinPcap/Npcap driver is not available on this system."

        self.error_message = None
        self.session_id = f"LIVE_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        self.interface = interface
        self.stop_event.clear()
        self.active_flows.clear()
        self.total_packets_captured = 0
        self.total_anomalies_detected = 0

        # Record session in DB
        self._record_session_start()

        # Launch worker
        self.is_running = True
        self.worker_thread = threading.Thread(target=self._sniff_worker, daemon=True)
        self.worker_thread.start()

        logger.info("Live capture started on interface '%s' (Session ID: %s)", interface, self.session_id)
        return True, f"Capture started successfully on session {self.session_id}."

    def stop_capture(self) -> tuple[bool, str]:
        """Stop active capture session and flush remaining flows."""
        if not self.is_running:
            return False, "No active capture session to stop."

        self.stop_event.set()
        self.is_running = False
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=3.0)

        # Flush any remaining flows to database
        self._flush_active_flows()
        self._record_session_end()

        logger.info("Live capture stopped for session %s.", self.session_id)
        return True, f"Capture stopped. Analyzed {self.total_packets_captured} packets."

    def get_status(self) -> dict[str, Any]:
        """Return real-time metrics of the capture session."""
        with self.flows_lock:
            active_count = len(self.active_flows)
        return {
            "is_running": self.is_running,
            "session_id": self.session_id,
            "interface": self.interface,
            "total_packets": self.total_packets_captured,
            "active_flows": active_count,
            "total_anomalies": self.total_anomalies_detected,
            "error_message": self.error_message,
        }

    def _sniff_worker(self):
        """Worker loop sniffing packets using Scapy."""
        try:
            sniff_kwargs: dict[str, Any] = {
                "prn": self._packet_callback,
                "stop_filter": lambda p: self.stop_event.is_set(),
                "store": False,
            }
            if self.interface:
                sniff_kwargs["iface"] = self.interface

            sniff(**sniff_kwargs)
        except Exception as exc:
            logger.error("Sniffer crashed: %s", exc)
            self.error_message = str(exc)
            self.is_running = False

    def _packet_callback(self, packet):
        """Callback for each captured packet."""
        if self.stop_event.is_set():
            return

        if not packet.haslayer(IP):
            return

        self.total_packets_captured += 1
        ip_layer = packet[IP]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        pkt_len = int(len(packet))

        protocol = "tcp"
        src_port = None
        dst_port = None
        tcp_flags = ""

        if packet.haslayer(TCP):
            protocol = "tcp"
            tcp_layer = packet[TCP]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            tcp_flags = str(tcp_layer.flags)
        elif packet.haslayer(UDP):
            protocol = "udp"
            udp_layer = packet[UDP]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
        elif packet.haslayer(ICMP):
            protocol = "icmp"

        flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (protocol,)
        is_forward = (src_ip, src_port) == flow_key[0]

        with self.flows_lock:
            if flow_key not in self.active_flows:
                flow = ConnectionFlow(flow_key, src_ip, dst_ip, src_port, dst_port, protocol)
                self.active_flows[flow_key] = flow
            else:
                flow = self.active_flows[flow_key]

            flow.add_packet(pkt_len, tcp_flags, is_forward=is_forward)

            # Evaluate flow periodically or after burst
            if flow.packet_count >= 5 or (time.time() - flow.start_time > 10.0):
                self._evaluate_and_save_flow(flow)
                del self.active_flows[flow_key]

    def _evaluate_and_save_flow(self, flow: ConnectionFlow):
        """Evaluate flow through Random Forest and persist result."""
        features = flow.build_compatible_features()
        direction = determine_direction(flow.src_ip, flow.dst_ip, self.local_ips)

        pred_val = 0
        prob_val = 0.0
        if self.predictor:
            try:
                preds = self.predictor["batch"]([features])
                if preds:
                    pred_val = int(preds[0].get("prediction", 0))
                    prob_val = float(preds[0].get("probability", 0.0))
            except Exception as e:
                logger.warning("Model inference error on live flow: %s", e)

        classification, severity = determine_severity_and_classification(pred_val, prob_val)
        attack_type = map_attack_category(None, classification in ("Attack", "Suspicious"), features)

        if classification == "Attack":
            self.total_anomalies_detected += 1

        self._save_flow_to_db(flow, direction, classification, prob_val, severity, attack_type)

    def _flush_active_flows(self):
        with self.flows_lock:
            for flow in list(self.active_flows.values()):
                self._evaluate_and_save_flow(flow)
            self.active_flows.clear()

    def _record_session_start(self):
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                """
                INSERT INTO monitoring_sessions (session_id, interface_name, start_time, status)
                VALUES (?, ?, ?, 'running')
                """,
                (self.session_id, self.interface or "Default", datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.error("Could not record session start: %s", exc)

    def _record_session_end(self):
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                """
                UPDATE monitoring_sessions
                SET end_time = ?, status = 'completed', packet_count = ?, anomaly_count = ?
                WHERE session_id = ?
                """,
                (datetime.now(timezone.utc).isoformat(), self.total_packets_captured, self.total_anomalies_detected, self.session_id),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.error("Could not record session end: %s", exc)

    def _save_flow_to_db(self, flow: ConnectionFlow, direction: str, classification: str, prob: float, severity: str, attack_type: str):
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                """
                INSERT INTO captured_flows (
                    session_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                    protocol, service, direction, packet_count, bytes_count,
                    flag, prediction, probability, severity, attack_category
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.session_id,
                    datetime.now(timezone.utc).isoformat(),
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    flow.protocol,
                    flow.service,
                    direction,
                    flow.packet_count,
                    flow.bytes_out + flow.bytes_in,
                    flow.get_summary_flag(),
                    classification,
                    prob,
                    severity,
                    attack_type,
                ),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.error("Could not save flow to DB: %s", exc)
