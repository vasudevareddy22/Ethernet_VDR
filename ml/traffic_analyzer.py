"""
ml/traffic_analyzer.py
----------------------
Traffic analysis and threat investigation engine for CSV uploads.
Provides:
- Secure CSV ingestion and parsing
- IP address detection without fabricating fake addresses
- Feature alignment and coercion for the trained ML pipeline (preventing label leakage)
- Threat classification (Safe / Suspicious / Attack)
- Dynamic severity scoring (Low / Medium / High / Critical)
- NSL-KDD attack category mapping (DoS, Probe, R2L, U2R)
- Heuristic fallback categorization
- SOC analyst reasoning & explanation generator
- Ground-truth evaluation metrics (Confusion Matrix, Precision, Recall, F1)
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from typing import Any

# NSL-KDD 4-class taxonomy mapping
ATTACK_CATEGORIES: dict[str, str] = {
    # DoS
    "apache2": "DoS",
    "back": "DoS",
    "land": "DoS",
    "neptune": "DoS",
    "mailbomb": "DoS",
    "pod": "DoS",
    "processtable": "DoS",
    "smurf": "DoS",
    "teardrop": "DoS",
    "udpstorm": "DoS",
    # Probe
    "ipsweep": "Probe",
    "mscan": "Probe",
    "nmap": "Probe",
    "portsweep": "Probe",
    "saint": "Probe",
    "satan": "Probe",
    # R2L
    "ftp_write": "R2L",
    "guess_passwd": "R2L",
    "httptunnel": "R2L",
    "imap": "R2L",
    "multihop": "R2L",
    "named": "R2L",
    "phf": "R2L",
    "sendmail": "R2L",
    "snmpgetattack": "R2L",
    "snmpguess": "R2L",
    "spy": "R2L",
    "warezclient": "R2L",
    "warezmaster": "R2L",
    "worm": "R2L",
    "xlock": "R2L",
    "xsnoop": "R2L",
    # U2R
    "buffer_overflow": "U2R",
    "loadmodule": "U2R",
    "perl": "U2R",
    "ps": "U2R",
    "rootkit": "U2R",
    "sqlattack": "U2R",
    "xterm": "U2R",
}

# The 41 standard NSL-KDD features required by the ML model
ALL_FEATURES: list[str] = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

CATEGORICAL_COLS = {"protocol_type", "service", "flag"}

# Potential column aliases for IP & Port mapping
SRC_IP_CANDIDATES = ["src_ip", "source_ip", "src", "source", "ip_src", "ip_source", "srcip", "source ip"]
DST_IP_CANDIDATES = ["dst_ip", "dest_ip", "destination_ip", "dst", "destination", "ip_dst", "ip_dest", "dstip", "dest ip"]
SRC_PORT_CANDIDATES = ["src_port", "source_port", "sport", "srcport", "source port"]
DST_PORT_CANDIDATES = ["dst_port", "dest_port", "destination_port", "dport", "dstport", "destination port"]

LABEL_CANDIDATES = ["label", "class", "attack", "target", "attack_type", "ground_truth"]
DIFFICULTY_CANDIDATES = ["difficulty_level", "difficulty", "diff_level"]


def detect_column(fieldnames: list[str], candidates: list[str]) -> str | None:
    """Find the exact column name in fieldnames matching any candidate (case-insensitive)."""
    norm_map = {f.strip().lower(): f for f in fieldnames}
    for cand in candidates:
        if cand.lower() in norm_map:
            return norm_map[cand.lower()]
    return None


def extract_ips_and_ports(row: dict[str, Any], fieldnames: list[str]) -> tuple[str | None, str | None, str | None, str | None]:
    """
    Extract IP and Port fields if present.
    NEVER fabricate fake IP addresses. Return None if not found in CSV.
    """
    src_col = detect_column(fieldnames, SRC_IP_CANDIDATES)
    dst_col = detect_column(fieldnames, DST_IP_CANDIDATES)
    sport_col = detect_column(fieldnames, SRC_PORT_CANDIDATES)
    dport_col = detect_column(fieldnames, DST_PORT_CANDIDATES)

    src_ip = str(row[src_col]).strip() if src_col and row.get(src_col) else None
    dst_ip = str(row[dst_col]).strip() if dst_col and row.get(dst_col) else None
    src_port = str(row[sport_col]).strip() if sport_col and row.get(sport_col) else None
    dst_port = str(row[dport_col]).strip() if dport_col and row.get(dport_col) else None

    return src_ip, dst_ip, src_port, dst_port


def extract_ground_truth(row: dict[str, Any], fieldnames: list[str]) -> tuple[str | None, str | None]:
    """
    Extract ground-truth label and difficulty level if present in the dataset.
    """
    lbl_col = detect_column(fieldnames, LABEL_CANDIDATES)
    diff_col = detect_column(fieldnames, DIFFICULTY_CANDIDATES)

    label = str(row[lbl_col]).strip().lower() if lbl_col and row.get(lbl_col) is not None else None
    difficulty = str(row[diff_col]).strip() if diff_col and row.get(diff_col) is not None else None

    # Clean label string (remove trailing period often found in KDD99 / NSL-KDD)
    if label and label.endswith('.'):
        label = label[:-1]

    return label, difficulty


def coerce_features_for_model(row: dict[str, Any]) -> dict[str, Any]:
    """
    Extract ONLY the 41 model features from the input row, casting to appropriate types.
    Explicitly excludes labels, difficulty levels, IPs, or ports to prevent data leakage.
    """
    features: dict[str, Any] = {}
    for feat in ALL_FEATURES:
        val = row.get(feat)
        if feat in CATEGORICAL_COLS:
            features[feat] = str(val).strip().lower() if val is not None else "unknown"
        else:
            try:
                features[feat] = float(val) if val is not None and str(val).strip() != "" else 0.0
            except (ValueError, TypeError):
                features[feat] = 0.0
    return features


def map_attack_category(ground_truth_label: str | None, pred_attack: bool, features: dict[str, Any]) -> str:
    """
    Categorize threat into DoS, Probe, R2L, U2R, or Normal Traffic.
    Uses ground-truth attack name if available; otherwise uses heuristic analysis.
    """
    if ground_truth_label:
        clean = ground_truth_label.lower().strip()
        if clean in ("normal", "safe", "0", "benign"):
            if not pred_attack:
                return "Normal Traffic"
        elif clean in ATTACK_CATEGORIES:
            return ATTACK_CATEGORIES[clean]
        else:
            # Check partial match in dictionary
            for attack_name, cat in ATTACK_CATEGORIES.items():
                if attack_name in clean:
                    return cat

    if not pred_attack:
        return "Normal Traffic"

    # Heuristic categorization based on NSL-KDD network indicators
    serror = float(features.get("serror_rate", 0))
    flag = str(features.get("flag", "")).upper()
    service = str(features.get("service", "")).lower()
    diff_srv = float(features.get("diff_srv_rate", 0))
    failed_logins = float(features.get("num_failed_logins", 0))
    root_shell = float(features.get("root_shell", 0))
    num_compromised = float(features.get("num_compromised", 0))

    if serror > 0.4 or flag in ("S0", "S1", "S2", "S3", "REJ", "RSTO", "RSTR"):
        return "DoS (SYN Flood / Service Disruption)"
    if diff_srv > 0.4 or service in ("private", "eco_i", "ecr_i", "auth"):
        return "Probe (Port Sweep / Reconnaissance)"
    if failed_logins > 0 or service in ("ftp", "telnet", "smtp", "pop_3", "imap4"):
        return "R2L (Unauthorized Remote Access)"
    if root_shell > 0 or num_compromised > 0:
        return "U2R (Privilege Escalation)"

    return "Anomalous Network Activity"


def determine_severity_and_classification(pred: int, prob: float, if_score: float | None = None) -> tuple[str, str]:
    """
    Determine classification (Safe, Suspicious, Attack) and severity (Low, Medium, High, Critical).
    """
    # Classification
    if prob >= 0.65 or pred == 1:
        classification = "Attack"
    elif prob >= 0.40 or (if_score is not None and if_score < -0.05):
        classification = "Suspicious"
    else:
        classification = "Safe"

    # Severity
    if prob >= 0.90:
        severity = "Critical"
    elif prob >= 0.70:
        severity = "High"
    elif prob >= 0.45 or classification == "Suspicious":
        severity = "Medium"
    else:
        severity = "Low"

    return classification, severity


def generate_explanation(features: dict[str, Any], classification: str, severity: str, attack_type: str, prob: float) -> str:
    """
    Generate clear, human-readable SOC analyst reasoning.
    """
    flag = str(features.get("flag", "")).upper()
    service = str(features.get("service", ""))
    protocol = str(features.get("protocol_type", "")).upper()
    serror = float(features.get("serror_rate", 0))
    src_bytes = int(features.get("src_bytes", 0))
    dst_bytes = int(features.get("dst_bytes", 0))
    failed_logins = int(features.get("num_failed_logins", 0))
    count = int(features.get("count", 0))

    if classification == "Safe":
        if flag == "SF":
            return f"Normal {protocol} session on service '{service}' with clean 3-way handshake completion (flag SF) and standard payload ({src_bytes}B in / {dst_bytes}B out)."
        return f"Routine {protocol}/{service} connection matching baseline enterprise traffic behavior (Risk score: {prob:.1%})."

    # Suspicious or Attack
    reasons = []
    if serror > 0.3:
        reasons.append(f"high SYN connection error rate ({serror:.0%}) with flag '{flag}'")
    if flag in ("S0", "REJ", "RSTO", "RSTR"):
        reasons.append(f"abnormal TCP connection termination status ({flag})")
    if count > 100:
        reasons.append(f"unusual burst traffic frequency ({count} connections to same host)")
    if failed_logins > 0:
        reasons.append(f"{failed_logins} failed authentication attempt(s) detected")
    if src_bytes > 50000 or (src_bytes == 0 and dst_bytes == 0 and count > 50):
        reasons.append(f"suspicious byte volume pattern ({src_bytes}B sent, {dst_bytes}B received)")

    if not reasons:
        reasons.append(f"anomalous statistical pattern across connection vectors (Confidence: {prob:.1%})")

    detail = "; ".join(reasons)
    return f"{severity} severity threat ({attack_type}): {detail}."


def compute_metrics(ground_truth_labels: list[str | None], predictions: list[int]) -> dict[str, Any] | None:
    """
    Compute real evaluation metrics (TP, TN, FP, FN, Accuracy, Precision, Recall, F1, FPR).
    Returns None if ground-truth labels are absent.
    """
    valid_pairs = []
    for gt, pred in zip(ground_truth_labels, predictions):
        if gt is not None and gt.strip() != "":
            is_gt_attack = gt.lower().strip() not in ("normal", "safe", "0", "benign")
            is_pred_attack = (pred == 1)
            valid_pairs.append((is_gt_attack, is_pred_attack))

    if not valid_pairs:
        return None

    tp = sum(1 for gt, p in valid_pairs if gt and p)
    tn = sum(1 for gt, p in valid_pairs if not gt and not p)
    fp = sum(1 for gt, p in valid_pairs if not gt and p)
    fn = sum(1 for gt, p in valid_pairs if gt and not p)

    total = len(valid_pairs)
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "confusion_matrix": {
            "TP": tp,
            "TN": tn,
            "FP": fp,
            "FN": fn,
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
        },
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "fpr": round(fpr * 100, 2),
        "evaluated_records": total,
    }
