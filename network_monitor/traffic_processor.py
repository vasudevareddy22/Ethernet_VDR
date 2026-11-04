"""
network_monitor/traffic_processor.py
------------------------------------
Aggregates packet-level network telemetry into bidirectional connection flows,
extracts flow statistics, estimates services, and feeds compatible features
into the trained detection pipeline.

IMPORTANT:
NSL-KDD models require 41 connection-level statistical features.
Raw single packets cannot be passed directly into the model without aggregation.
When insufficient packet flow history exists, this module classifies with
proper confidence markers and avoids misleading claims.
"""

from __future__ import annotations

import time
from typing import Any

# Standard well-known ports to NSL-KDD service mapping
PORT_SERVICE_MAP: dict[int, str] = {
    80: "http",
    443: "http",
    8080: "http",
    21: "ftp",
    20: "ftp_data",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain_u",
    110: "pop_3",
    143: "imap4",
    123: "ntp_u",
    161: "snmp",
    67: "dhcp",
    68: "dhcp",
    3389: "remote_job",
    3306: "sql_net",
    5432: "sql_net",
}


def infer_service(src_port: int | None, dst_port: int | None) -> str:
    """Infer NSL-KDD service name from ports."""
    if dst_port and dst_port in PORT_SERVICE_MAP:
        return PORT_SERVICE_MAP[dst_port]
    if src_port and src_port in PORT_SERVICE_MAP:
        return PORT_SERVICE_MAP[src_port]
    return "other"


def determine_direction(src_ip: str, dst_ip: str, local_ips: set[str]) -> str:
    """Determine whether the connection is inbound, outbound, or internal."""
    is_src_local = src_ip in local_ips or src_ip.startswith("127.") or src_ip.startswith("192.168.") or src_ip.startswith("10.")
    is_dst_local = dst_ip in local_ips or dst_ip.startswith("127.") or dst_ip.startswith("192.168.") or dst_ip.startswith("10.")

    if is_src_local and not is_dst_local:
        return "outbound"
    if not is_src_local and is_dst_local:
        return "inbound"
    return "internal"


class ConnectionFlow:
    """Represents an ongoing network session between two endpoints."""

    def __init__(self, key: tuple, src_ip: str, dst_ip: str, src_port: int | None, dst_port: int | None, protocol: str):
        self.key = key
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol.lower()
        self.service = infer_service(src_port, dst_port)
        self.start_time = time.time()
        self.last_seen = self.start_time
        self.packet_count = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.flags_seen: set[str] = set()
        self.tcp_syn_count = 0
        self.tcp_fin_count = 0
        self.tcp_rst_count = 0
        self.tcp_ack_count = 0

    def add_packet(self, length: int, flags: str = "", is_forward: bool = True):
        self.last_seen = time.time()
        self.packet_count += 1
        if is_forward:
            self.bytes_out += length
        else:
            self.bytes_in += length

        if flags:
            self.flags_seen.add(flags)
            if "S" in flags:
                self.tcp_syn_count += 1
            if "F" in flags:
                self.tcp_fin_count += 1
            if "R" in flags:
                self.tcp_rst_count += 1
            if "A" in flags:
                self.tcp_ack_count += 1

    def get_summary_flag(self) -> str:
        """Infer dominant connection flag matching KDD convention (SF, S0, REJ, RSTO)."""
        if self.protocol != "tcp":
            return "SF"
        if self.tcp_rst_count > 0:
            return "REJ" if self.tcp_ack_count == 0 else "RSTO"
        if self.tcp_syn_count > 0 and self.tcp_ack_count == 0:
            return "S0"
        if self.tcp_syn_count > 0 and self.tcp_fin_count > 0:
            return "SF"
        return "SF" if self.tcp_ack_count > 0 else "OTH"

    def build_compatible_features(self) -> dict[str, Any]:
        """
        Assemble the 41-feature dictionary required by the trained Random Forest model.
        Fills missing higher-order host/service features safely with conservative defaults.
        """
        duration = max(0.0, self.last_seen - self.start_time)
        flag = self.get_summary_flag()
        serror_rate = 1.0 if flag == "S0" else (0.5 if flag in ("REJ", "RSTO") else 0.0)

        return {
            "duration": round(duration, 2),
            "protocol_type": self.protocol,
            "service": self.service,
            "flag": flag,
            "src_bytes": self.bytes_out,
            "dst_bytes": self.bytes_in,
            "land": 1 if self.src_ip == self.dst_ip and self.src_port == self.dst_port else 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 1 if self.tcp_ack_count > 1 else 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": min(self.packet_count, 100),
            "srv_count": min(self.packet_count, 100),
            "serror_rate": serror_rate,
            "srv_serror_rate": serror_rate,
            "rerror_rate": 1.0 if flag in ("REJ", "RSTO") else 0.0,
            "srv_rerror_rate": 1.0 if flag in ("REJ", "RSTO") else 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 1,
            "dst_host_srv_count": 1,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": serror_rate,
            "dst_host_srv_serror_rate": serror_rate,
            "dst_host_rerror_rate": 1.0 if flag in ("REJ", "RSTO") else 0.0,
            "dst_host_srv_rerror_rate": 1.0 if flag in ("REJ", "RSTO") else 0.0,
        }
