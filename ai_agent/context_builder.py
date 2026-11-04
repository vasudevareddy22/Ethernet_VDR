"""
ai_agent/context_builder.py
---------------------------
Gathers factual network telemetry, live flows, historical analyses,
open alerts, and model statistics from the SQLite database to supply
grounded context for the AI SOC Analyst.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from database.db import DB_PATH


class ContextBuilder:
    """Builds structured system context directly from SQLite tables."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_system_context(self, analysis_id: int | None = None) -> dict[str, Any]:
        """
        Assemble live stats, latest CSV analysis, alerts, and model metrics.
        Never fabricates information.
        """
        conn = self._get_connection()
        try:
            # 1. Latest or targeted Analysis
            analysis_data = None
            records_sample = []
            if analysis_id:
                row = conn.execute("SELECT * FROM traffic_analyses WHERE id = ?", (analysis_id,)).fetchone()
            else:
                row = conn.execute("SELECT * FROM traffic_analyses ORDER BY id DESC LIMIT 1").fetchone()

            if row:
                analysis_data = dict(row)
                target_id = analysis_data["id"]
                rec_rows = conn.execute(
                    """
                    SELECT row_index, src_ip, dst_ip, src_port, dst_port, protocol,
                           service, flag, prediction, probability, severity, attack_type, explanation
                    FROM analysis_records
                    WHERE analysis_id = ?
                    ORDER BY row_index ASC LIMIT 20
                    """,
                    (target_id,),
                ).fetchall()
                records_sample = [dict(r) for r in rec_rows]

            # 2. Live Monitoring Summary
            live_session = conn.execute("SELECT * FROM monitoring_sessions ORDER BY id DESC LIMIT 1").fetchone()
            live_flows = conn.execute(
                """
                SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, service,
                       direction, packet_count, bytes_count, flag, prediction, severity, attack_category
                FROM captured_flows ORDER BY id DESC LIMIT 15
                """
            ).fetchall()

            # 3. Open Critical/High Alerts
            alert_rows = conn.execute(
                """
                SELECT id, timestamp, severity, title, description, status
                FROM alerts WHERE status = 'open'
                ORDER BY id DESC LIMIT 10
                """
            ).fetchall()

            # 4. Aggregations (Top Malicious Source IPs across records and flows)
            top_threat_ips = conn.execute(
                """
                SELECT src_ip, COUNT(*) as hit_count, MAX(severity) as max_severity
                FROM analysis_records
                WHERE src_ip IS NOT NULL AND prediction IN ('Attack', 'Suspicious')
                GROUP BY src_ip ORDER BY hit_count DESC LIMIT 5
                """
            ).fetchall()

            return {
                "active_analysis": analysis_data,
                "analysis_sample_records": records_sample,
                "live_session": dict(live_session) if live_session else None,
                "live_flows": [dict(f) for f in live_flows],
                "open_alerts": [dict(a) for a in alert_rows],
                "top_threat_ips": [dict(t) for t in top_threat_ips],
            }
        finally:
            conn.close()

    def format_context_for_prompt(self, context_dict: dict[str, Any]) -> str:
        """Render the structured context into a concise markdown text block for LLM prompts."""
        lines = []
        lines.append("### CURRENT NETWORK AI TELEMETRY CONTEXT:")

        # Analysis Section
        ana = context_dict.get("active_analysis")
        if ana:
            lines.append(f"- Active CSV Run: #{ana['id']} '{ana['filename']}' ({ana['timestamp']})")
            lines.append(f"  * Total Rows: {ana['total_rows']}, Safe: {ana['normal_count']}, Attacks: {ana['attack_count']}, Suspicious: {ana['suspicious_count']}")
            if ana.get("has_ground_truth") and ana.get("metrics_json"):
                try:
                    m = json.loads(ana["metrics_json"])
                    lines.append(f"  * Ground-Truth Metrics: Accuracy {m.get('accuracy')}%, Precision {m.get('precision')}%, Recall {m.get('recall')}%, F1 {m.get('f1_score')}%")
                except Exception:
                    pass
        else:
            lines.append("- Active CSV Run: None uploaded yet.")

        # Live session
        live = context_dict.get("live_session")
        if live:
            lines.append(f"- Live Packet Capture: Session {live['session_id']} on {live['interface_name']} (Status: {live['status']})")
            lines.append(f"  * Packets Captured: {live['packet_count']}, Anomalies Detected: {live['anomaly_count']}")
        else:
            lines.append("- Live Packet Capture: Inactive / No session running.")

        # Alerts
        alerts = context_dict.get("open_alerts", [])
        lines.append(f"- Open High-Priority Alerts: {len(alerts)}")
        for a in alerts[:5]:
            lines.append(f"  * [{a['severity'].upper()}] #{a['id']}: {a['title']} ({a['timestamp']})")

        # Top Suspicious IPs
        ips = context_dict.get("top_threat_ips", [])
        if ips:
            lines.append("- Top Detected Threat Source IPs:")
            for item in ips:
                lines.append(f"  * IP {item['src_ip']}: {item['hit_count']} anomalous connection hits (Severity: {item['max_severity']})")
        else:
            lines.append("- Top Threat IPs: No specific IP addresses recorded in current dataset (e.g., standard NSL-KDD session features).")

        return "\n".join(lines)
