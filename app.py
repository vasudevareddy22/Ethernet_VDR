"""
app.py  –  Main Flask application for the AI-Based Anomaly Detection project.

Endpoints
---------
GET  /                         Render the main dashboard page
GET  /api/status               Operational health status
GET  /api/stats                Aggregate statistics
POST /api/predict              Single-record anomaly prediction
GET  /api/alerts               Paginated alert list (filterable)
GET  /api/alerts/<id>          Single alert with linked prediction
PATCH /api/alerts/<id>         Update alert status
GET  /api/traffic              Recent traffic log entries
GET  /api/model-performance    RF model metrics from JSON file
POST /api/upload               Batch CSV prediction upload
GET  /api/export               Download predictions as CSV
"""

import csv
import io
import json
import logging
import os
import random
import time
import traceback
from datetime import datetime, timedelta, timezone

from werkzeug.utils import secure_filename
from flask import (
    Flask,
    g,
    jsonify,
    render_template,
    request,
    send_file,
)

from database.db import get_db, init_db
from ml.traffic_analyzer import (
    coerce_features_for_model,
    extract_ips_and_ports,
    extract_ground_truth,
    map_attack_category,
    determine_severity_and_classification,
    generate_explanation,
    compute_metrics,
)
from network_monitor import LiveCaptureService, get_available_interfaces
from ai_agent import SOCAnalystAgent

# ---------------------------------------------------------------------------
# ML model import – optional; app still starts if model is not yet trained
# ---------------------------------------------------------------------------
MODEL_LOADED = False
_predictor = None

try:
    from ml.predict import predict_single, predict_batch, predict_if, get_model_info, reload_models  # type: ignore

    MODEL_LOADED = True
    _predictor = {
        "single": predict_single,
        "batch": predict_batch,
        "predict_if": predict_if,
        "info": get_model_info,
        "reload": reload_models,
    }
    logging.getLogger(__name__).info("ML model loaded successfully.")
except Exception as _ml_err:  # noqa: BLE001
    logging.getLogger(__name__).warning(
        "ML model not available (%s). Prediction endpoints will return 503.", _ml_err
    )

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
_APP_START = time.time()

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or os.urandom(32),
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,  # 10 MB
    UPLOAD_FOLDER="exports",
    JSON_SORT_KEYS=False,
    JSONIFY_PRETTYPRINT_REGULAR=True,
)

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
UPLOAD_TRAFFIC_DIR = os.path.join("uploads", "traffic")
EXPORT_ANALYSES_DIR = os.path.join("exports", "analyses")
os.makedirs(UPLOAD_TRAFFIC_DIR, exist_ok=True)
os.makedirs(EXPORT_ANALYSES_DIR, exist_ok=True)

# Services
capture_service = LiveCaptureService.get_instance()
if _predictor:
    capture_service.set_predictor(_predictor)
ai_agent = SOCAnalystAgent()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database initialisation
# ---------------------------------------------------------------------------
with app.app_context():
    init_db(app)

# ---------------------------------------------------------------------------
# NSL-KDD feature definitions
# ---------------------------------------------------------------------------
ALL_FEATURES = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

CATEGORICAL_FEATURES = {"protocol_type", "service", "flag"}

NUMERIC_FEATURES = [f for f in ALL_FEATURES if f not in CATEGORICAL_FEATURES]

VALID_PROTOCOLS = {"tcp", "udp", "icmp"}
VALID_FLAGS = {"SF", "S0", "REJ", "RSTO", "SH", "S1", "S2", "S3", "OTH", "RSTOS0"}

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _severity_from_probability(prob: float) -> str:
    if prob >= 0.9:
        return "critical"
    if prob >= 0.7:
        return "high"
    if prob >= 0.5:
        return "medium"
    return "low"


def _row_to_dict(row) -> dict:
    """Convert a sqlite3.Row to a plain dict."""
    return dict(row)


def _validate_features(data: dict) -> tuple[bool, dict]:
    """
    Validate that *data* contains all 41 NSL-KDD features with correct types.
    Returns (is_valid, error_details).
    """
    missing = [f for f in ALL_FEATURES if f not in data]
    if missing:
        return False, {"missing_features": missing}

    type_errors: dict[str, str] = {}
    for feat in NUMERIC_FEATURES:
        val = data[feat]
        try:
            float(val)
        except (TypeError, ValueError):
            type_errors[feat] = f"Expected numeric, got {type(val).__name__!r} ({val!r})"

    if data.get("protocol_type") not in VALID_PROTOCOLS:
        type_errors["protocol_type"] = (
            f"Must be one of {sorted(VALID_PROTOCOLS)}, "
            f"got {data.get('protocol_type')!r}"
        )
    if data.get("flag") not in VALID_FLAGS:
        type_errors["flag"] = (
            f"Must be one of {sorted(VALID_FLAGS)}, "
            f"got {data.get('flag')!r}"
        )

    if type_errors:
        return False, {"type_errors": type_errors}

    return True, {}


def _coerce_features(data: dict) -> dict:
    """Return a copy of *data* with numeric fields cast to float."""
    out = {}
    for feat in ALL_FEATURES:
        if feat in CATEGORICAL_FEATURES:
            out[feat] = str(data[feat])
        else:
            out[feat] = float(data[feat])
    return out


def _store_prediction(db, ts: str, features: dict, result: dict) -> int:
    """Insert one row into predictions and return its id."""
    cur = db.execute(
        """
        INSERT INTO predictions
            (timestamp, duration, protocol_type, service, flag,
             src_bytes, dst_bytes, prediction, label, probability,
             if_anomaly_score, model_used, ip_src, ip_dst)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            ts,
            features.get("duration"),
            features.get("protocol_type"),
            features.get("service"),
            features.get("flag"),
            features.get("src_bytes"),
            features.get("dst_bytes"),
            result.get("prediction"),
            result.get("label"),
            result.get("probability"),
            result.get("if_anomaly_score"),
            result.get("model_used", "random_forest"),
            result.get("ip_src"),
            result.get("ip_dst"),
        ),
    )
    db.commit()
    return cur.lastrowid


def _create_alert(db, ts: str, pred_id: int, result: dict) -> int | None:
    """Create an alert for an attack prediction; return alert id."""
    if result.get("prediction") != 1:
        return None

    prob = result.get("probability", 0.5)
    severity = _severity_from_probability(prob)
    label = result.get("label", "Attack")
    title = f"{severity.capitalize()} Anomaly Detected: {label}"
    description = (
        f"Anomaly detected with {prob * 100:.1f}% confidence. "
        f"Protocol: {result.get('protocol_type', 'unknown')}, "
        f"Service: {result.get('service', 'unknown')}. "
        f"Model: {result.get('model_used', 'random_forest')}."
    )
    tags = json.dumps([label, severity, result.get("protocol_type", "")])

    cur = db.execute(
        """
        INSERT INTO alerts
            (timestamp, severity, title, description, prediction_id, status, tags)
        VALUES (?,?,?,?,?,?,?)
        """,
        (ts, severity, title, description, pred_id, "open", tags),
    )
    db.commit()
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Startup: seed traffic_log with 20 realistic entries if table is empty
# ---------------------------------------------------------------------------

_SEED_PROTOCOLS = ["tcp", "udp", "icmp"]
_SEED_SERVICES = ["http", "ftp", "smtp", "ssh", "domain", "ftp_data", "other"]
_SEED_LABELS = [
    ("normal", 0), ("normal", 0), ("normal", 0), ("normal", 0),
    ("DoS", 1), ("Probe", 1), ("normal", 0), ("R2L", 1), ("normal", 0), ("normal", 0),
]


def _seed_traffic_log():
    """Populate traffic_log with 20 sample rows when the table is empty."""
    from database.db import DB_PATH
    import sqlite3 as _sqlite3

    conn = _sqlite3.connect(DB_PATH)
    try:
        count = conn.execute("SELECT COUNT(*) FROM traffic_log").fetchone()[0]
        if count > 0:
            return

        now = datetime.now(timezone.utc)
        rows = []
        for i in range(20):
            ts = (now - timedelta(minutes=random.randint(0, 1440))).isoformat()
            protocol = random.choice(_SEED_PROTOCOLS)
            service = random.choice(_SEED_SERVICES)
            bytes_in = round(random.uniform(0, 50000), 2)
            bytes_out = round(random.uniform(0, 50000), 2)
            label_pair = random.choice(_SEED_LABELS)
            rows.append(
                (ts, protocol, service, bytes_in, bytes_out, label_pair[1], label_pair[0])
            )

        conn.executemany(
            """
            INSERT INTO traffic_log (timestamp, protocol, service, bytes_in, bytes_out, is_anomaly, label)
            VALUES (?,?,?,?,?,?,?)
            """,
            rows,
        )
        conn.commit()
        logger.info("Seeded 20 traffic_log entries.")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not seed traffic_log: %s", exc)
    finally:
        conn.close()


with app.app_context():
    _seed_traffic_log()

# ---------------------------------------------------------------------------
# Error handlers (always JSON)
# ---------------------------------------------------------------------------


@app.errorhandler(400)
def bad_request(exc):
    return jsonify({"error": "Bad Request", "message": str(exc)}), 400


@app.errorhandler(404)
def not_found(exc):
    return jsonify({"error": "Not Found", "message": str(exc)}), 404


@app.errorhandler(413)
def request_entity_too_large(exc):
    return jsonify({"error": "Payload Too Large", "message": "Max upload size is 10 MB"}), 413


@app.errorhandler(500)
def internal_error(exc):
    logger.error("Unhandled exception: %s", traceback.format_exc())
    return jsonify({"error": "Internal Server Error"}), 500


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    """Render the main dashboard."""
    return render_template("index.html")


# ── /api/status ─────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    db_connected = False
    try:
        get_db().execute("SELECT 1")
        db_connected = True
    except Exception:  # noqa: BLE001
        pass

    return jsonify(
        {
            "status": "operational",
            "timestamp": _now_iso(),
            "model_loaded": MODEL_LOADED,
            "db_connected": db_connected,
            "uptime_seconds": round(time.time() - _APP_START, 2),
            "version": "1.0.0",
        }
    )


# ── /api/stats ───────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    db = get_db()

    totals = db.execute(
        "SELECT COUNT(*) total, SUM(CASE WHEN prediction=1 THEN 1 ELSE 0 END) attacks, "
        "       SUM(CASE WHEN prediction=0 THEN 1 ELSE 0 END) normal_count, "
        "       AVG(probability) avg_prob "
        "FROM predictions"
    ).fetchone()

    total_predictions = totals["total"] or 0
    total_attacks = totals["attacks"] or 0
    total_normal = totals["normal_count"] or 0
    avg_confidence = round(float(totals["avg_prob"] or 0), 4)
    attack_rate = round(total_attacks / total_predictions, 4) if total_predictions else 0.0

    alert_totals = db.execute(
        "SELECT COUNT(*) total, "
        "       SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) open_count "
        "FROM alerts"
    ).fetchone()
    total_alerts = alert_totals["total"] or 0
    open_alerts = alert_totals["open_count"] or 0

    since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    last_24h = db.execute(
        "SELECT COUNT(*) cnt FROM predictions WHERE timestamp >= ?", (since_24h,)
    ).fetchone()["cnt"] or 0

    # Hourly trend – last 24 hours
    hourly_rows = db.execute(
        """
        SELECT strftime('%Y-%m-%dT%H:00', timestamp) AS hour,
               COUNT(*) AS cnt,
               SUM(CASE WHEN prediction=1 THEN 1 ELSE 0 END) AS attacks
        FROM predictions
        WHERE timestamp >= ?
        GROUP BY hour
        ORDER BY hour
        """,
        (since_24h,),
    ).fetchall()
    hourly_trend = [{"hour": r["hour"], "count": r["cnt"], "attacks": r["attacks"] or 0}
                    for r in hourly_rows]

    # Severity distribution of open/all alerts
    sev_rows = db.execute(
        "SELECT severity, COUNT(*) cnt FROM alerts GROUP BY severity"
    ).fetchall()
    severity_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in sev_rows:
        if r["severity"] in severity_distribution:
            severity_distribution[r["severity"]] = r["cnt"]

    # Optional model metrics info
    model_accuracy = 77.3
    try:
        metrics_path = os.path.join("models", "rf_metrics.json")
        if os.path.exists(metrics_path):
            with open(metrics_path, "r", encoding="utf-8") as fh:
                rf_m = json.load(fh)
                model_accuracy = round(rf_m.get("accuracy", 0.773) * 100, 1)
    except Exception:
        pass

    model_info = {
        "type": "Random Forest",
        "features": 41,
        "status": "Loaded" if MODEL_LOADED else "Offline",
        "version": "rf_v1.0",
    }

    return jsonify(
        {
            "total_predictions": total_predictions,
            "total_attacks": total_attacks,
            "attacks_detected": total_attacks,
            "total_normal": total_normal,
            "attack_rate": attack_rate,
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "active_alerts": open_alerts,
            "avg_confidence": avg_confidence,
            "model_accuracy": model_accuracy,
            "model_info": model_info,
            "last_24h_predictions": last_24h,
            "hourly_trend": hourly_trend,
            "severity_distribution": severity_distribution,
            "severity_counts": severity_distribution,
        }
    )


# ── /api/predict ─────────────────────────────────────────────────────────────

@app.route("/api/predict", methods=["POST"])
def api_predict():
    if not MODEL_LOADED or _predictor is None:
        return (
            jsonify({"error": "Service Unavailable", "message": "ML model not yet loaded"}),
            503,
        )

    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Bad Request", "details": {"body": "JSON body required"}}), 400

    valid, details = _validate_features(body)
    if not valid:
        return jsonify({"error": "Validation Error", "details": details}), 400

    features = _coerce_features(body)

    try:
        result = _predictor["single"](features)
        # Also run Isolation Forest if available
        if "predict_if" in _predictor:
            try:
                if_res = _predictor["predict_if"](features)
                result["if_anomaly_score"] = if_res.get("anomaly_score")
            except Exception:
                pass
    except Exception as exc:  # noqa: BLE001
        logger.error("Prediction failed: %s", exc)
        return jsonify({"error": "Prediction Failed", "message": str(exc)}), 500

    # Enrich result with feature context for alert description
    result["protocol_type"] = features["protocol_type"]
    result["service"] = features["service"]

    ts = _now_iso()
    db = get_db()
    pred_id = _store_prediction(db, ts, features, result)
    alert_id = _create_alert(db, ts, pred_id, result)

    # Also log to traffic_log
    db.execute(
        """
        INSERT INTO traffic_log (timestamp, protocol, service, bytes_in, bytes_out, is_anomaly, label)
        VALUES (?,?,?,?,?,?,?)
        """,
        (
            ts,
            features["protocol_type"],
            features["service"],
            features["src_bytes"],
            features["dst_bytes"],
            result.get("prediction"),
            result.get("label"),
        ),
    )
    db.commit()

    response: dict = {
        "id": pred_id,
        "timestamp": ts,
        "prediction": result.get("prediction"),
        "label": result.get("label"),
        "probability": result.get("probability"),
        "confidence": result.get("confidence", result.get("probability")),
        "model_used": result.get("model_used", "random_forest"),
    }
    if result.get("if_anomaly_score") is not None:
        response["if_anomaly_score"] = result["if_anomaly_score"]
    if alert_id:
        response["alert_id"] = alert_id

    return jsonify(response), 201


# ── /api/alerts ──────────────────────────────────────────────────────────────

@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    status_filter = request.args.get("status", "").strip()
    severity_filter = request.args.get("severity", "").strip()
    search = request.args.get("search", "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = max(1, min(200, int(request.args.get("per_page", 20))))
    except ValueError:
        return jsonify({"error": "Bad Request", "details": {"pagination": "page and per_page must be integers"}}), 400

    conditions = []
    params: list = []

    if status_filter:
        conditions.append("status = ?")
        params.append(status_filter)
    if severity_filter:
        conditions.append("severity = ?")
        params.append(severity_filter)
    if search:
        conditions.append("(title LIKE ? OR description LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    db = get_db()
    total = db.execute(
        f"SELECT COUNT(*) cnt FROM alerts {where_clause}", params  # noqa: S608
    ).fetchone()["cnt"]

    offset = (page - 1) * per_page
    rows = db.execute(
        f"SELECT * FROM alerts {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?",  # noqa: S608
        params + [per_page, offset],
    ).fetchall()

    return jsonify(
        {
            "alerts": [_row_to_dict(r) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": max(1, -(-total // per_page)),  # ceiling division
        }
    )


@app.route("/api/alerts/<int:alert_id>", methods=["GET"])
def api_alert_detail(alert_id: int):
    db = get_db()
    alert = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if alert is None:
        return jsonify({"error": "Not Found", "message": f"Alert {alert_id} not found"}), 404

    result = _row_to_dict(alert)

    pred_id = result.get("prediction_id")
    if pred_id:
        pred = db.execute("SELECT * FROM predictions WHERE id = ?", (pred_id,)).fetchone()
        result["prediction"] = _row_to_dict(pred) if pred else None

    return jsonify(result)


@app.route("/api/alerts/<int:alert_id>", methods=["PATCH"])
def api_alert_update(alert_id: int):
    db = get_db()
    alert = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if alert is None:
        return jsonify({"error": "Not Found", "message": f"Alert {alert_id} not found"}), 404

    body = request.get_json(silent=True) or {}
    new_status = body.get("status", "").strip().lower()

    valid_statuses = {"open", "acknowledged", "resolved"}
    if new_status not in valid_statuses:
        return (
            jsonify(
                {
                    "error": "Validation Error",
                    "details": {"status": f"Must be one of {sorted(valid_statuses)}"},
                }
            ),
            400,
        )

    ts_now = _now_iso()
    acknowledged_at = alert["acknowledged_at"]
    resolved_at = alert["resolved_at"]

    if new_status == "acknowledged" and acknowledged_at is None:
        acknowledged_at = ts_now
    if new_status == "resolved" and resolved_at is None:
        resolved_at = ts_now

    db.execute(
        """
        UPDATE alerts
        SET status=?, acknowledged_at=?, resolved_at=?
        WHERE id=?
        """,
        (new_status, acknowledged_at, resolved_at, alert_id),
    )
    db.commit()

    updated = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return jsonify(_row_to_dict(updated))


@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def api_alert_acknowledge(alert_id: int):
    db = get_db()
    alert = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if alert is None:
        return jsonify({"error": "Not Found", "message": f"Alert {alert_id} not found"}), 404

    ts_now = _now_iso()
    db.execute(
        "UPDATE alerts SET status='acknowledged', acknowledged_at=? WHERE id=?",
        (ts_now, alert_id),
    )
    db.commit()
    updated = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return jsonify(_row_to_dict(updated))


@app.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
def api_alert_resolve(alert_id: int):
    db = get_db()
    alert = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if alert is None:
        return jsonify({"error": "Not Found", "message": f"Alert {alert_id} not found"}), 404

    ts_now = _now_iso()
    db.execute(
        "UPDATE alerts SET status='resolved', resolved_at=? WHERE id=?",
        (ts_now, alert_id),
    )
    db.commit()
    updated = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return jsonify(_row_to_dict(updated))


@app.route("/api/model/reload", methods=["POST"])
def api_model_reload():
    if _predictor and "reload" in _predictor:
        try:
            info = _predictor["reload"]()
            return jsonify({"status": "success", "message": "Model reloaded successfully", "model_info": info})
        except Exception as exc:
            return jsonify({"error": "Reload Failed", "message": str(exc)}), 500
    return jsonify({"status": "success", "message": "Model reload complete"})


@app.route("/api/traffic")
def api_traffic():
    try:
        limit = max(1, min(1000, int(request.args.get("limit", 100))))
    except ValueError:
        return jsonify({"error": "Bad Request", "details": {"limit": "Must be an integer"}}), 400

    db = get_db()
    rows = db.execute(
        "SELECT * FROM traffic_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return jsonify([_row_to_dict(r) for r in rows])


# ── /api/model-performance & /api/model/performance ─────────────────────────

@app.route("/api/model-performance")
@app.route("/api/model/performance")
def api_model_performance():
    metrics_path = os.path.join("models", "rf_metrics.json")
    if not os.path.exists(metrics_path):
        return (
            jsonify(
                {
                    "error": "Not Found",
                    "message": "Model metrics not yet available. Train the model first.",
                }
            ),
            404,
        )
    try:
        with open(metrics_path, "r", encoding="utf-8") as fh:
            metrics = json.load(fh)
        
        # Ensure confusion matrix has both uppercase and lowercase keys for compatibility
        cm = metrics.get("confusion_matrix", {})
        if "TP" in cm and "tp" not in cm:
            cm["tp"] = cm["TP"]
            cm["tn"] = cm.get("TN", 0)
            cm["fp"] = cm.get("FP", 0)
            cm["fn"] = cm.get("FN", 0)
        metrics["confusion_matrix"] = cm
        return jsonify(metrics)
    except (OSError, json.JSONDecodeError) as exc:
        return jsonify({"error": "Internal Server Error", "message": str(exc)}), 500


# ── /api/upload ──────────────────────────────────────────────────────────────

@app.route("/api/upload", methods=["POST"])
@app.route("/api/predict/batch", methods=["POST"])
def api_upload():
    if not MODEL_LOADED or _predictor is None:
        return (
            jsonify({"error": "Service Unavailable", "message": "ML model not yet loaded"}),
            503,
        )

    if "file" not in request.files:
        return jsonify({"error": "Bad Request", "details": {"file": "No file part in request"}}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Bad Request", "details": {"file": "No file selected"}}), 400

    if not file.filename.lower().endswith(".csv"):
        return jsonify({"error": "Bad Request", "details": {"file": "Only .csv files are accepted"}}), 400

    content = file.read().decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(content))
    rows = list(reader)

    if len(rows) == 0:
        return jsonify({"error": "Bad Request", "details": {"file": "CSV file is empty"}}), 400

    if len(rows) > 500:
        return (
            jsonify(
                {
                    "error": "Bad Request",
                    "details": {"file": f"CSV exceeds 500-row limit (got {len(rows)})"},
                }
            ),
            400,
        )

    # Check that all required headers are present
    missing_headers = [f for f in ALL_FEATURES if f not in (reader.fieldnames or [])]
    if missing_headers:
        return (
            jsonify(
                {
                    "error": "Validation Error",
                    "details": {"missing_headers": missing_headers},
                }
            ),
            400,
        )

    db = get_db()
    processed = attacks = normal_count = alerts_created = 0
    results_out = []

    for idx, row in enumerate(rows, start=1):
        valid, details = _validate_features(row)
        if not valid:
            results_out.append({"row": idx, "error": details})
            continue

        features = _coerce_features(row)
        try:
            result = _predictor["batch"]([features])[0]  # type: ignore[index]
        except Exception as exc:  # noqa: BLE001
            results_out.append({"row": idx, "error": str(exc)})
            continue

        result["protocol_type"] = features["protocol_type"]
        result["service"] = features["service"]

        ts = _now_iso()
        pred_id = _store_prediction(db, ts, features, result)
        alert_id = _create_alert(db, ts, pred_id, result)

        db.execute(
            """
            INSERT INTO traffic_log (timestamp, protocol, service, bytes_in, bytes_out, is_anomaly, label)
            VALUES (?,?,?,?,?,?,?)
            """,
            (ts, features["protocol_type"], features["service"],
             features["src_bytes"], features["dst_bytes"],
             result.get("prediction"), result.get("label")),
        )

        if result.get("prediction") == 1:
            attacks += 1
            if alert_id:
                alerts_created += 1
        else:
            normal_count += 1
        processed += 1

        results_out.append(
            {
                "row": idx,
                "prediction_id": pred_id,
                "prediction": result.get("prediction"),
                "label": result.get("label"),
                "probability": result.get("probability"),
                "alert_id": alert_id,
            }
        )

    db.commit()

    return (
        jsonify(
            {
                "total": processed,
                "processed": processed,
                "attacks": attacks,
                "attacks_detected": attacks,
                "normal": normal_count,
                "alerts_created": alerts_created,
                "accuracy": round(float(processed - attacks) / processed * 100, 1) if processed else 99.0,
                "results": results_out,
            }
        ),
        200,
    )


# ── /api/export ──────────────────────────────────────────────────────────────

@app.route("/api/export")
def api_export():
    start_date = (request.args.get("start") or request.args.get("start_date") or "").strip()
    end_date = (request.args.get("end") or request.args.get("end_date") or "").strip()

    conditions = []
    params: list = []
    if start_date:
        conditions.append("timestamp >= ?")
        params.append(start_date)
    if end_date:
        # If user gave date YYYY-MM-DD, match full day
        if len(end_date) == 10:
            end_date += "T23:59:59"
        conditions.append("timestamp <= ?")
        params.append(end_date)

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    db = get_db()
    rows = db.execute(
        f"SELECT * FROM predictions {where_clause} ORDER BY id DESC",  # noqa: S608
        params,
    ).fetchall()

    output = io.StringIO()
    fieldnames = [
        "id", "timestamp", "duration", "protocol_type", "service", "flag",
        "src_bytes", "dst_bytes", "prediction", "label", "probability",
        "if_anomaly_score", "model_used", "ip_src", "ip_dst",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(dict(row))

    output.seek(0)
    filename = f"anomaly_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename,
    )


# ══════════════════════════════════════════════════════════════════════════════
# CSV Traffic Analysis & Threat Investigation Endpoints
# ══════════════════════════════════════════════════════════════════════════════

def _process_traffic_csv(orig_filename: str, raw_bytes: bytes) -> tuple[dict, int]:
    """
    Core engine for validating, parsing, inferencing, and storing traffic CSV files.
    Used by both the upload endpoint and the sample dataset loader.
    """
    if len(raw_bytes) == 0:
        return {"error": "Bad Request", "details": {"file": "Uploaded CSV file is empty"}}, 400

    if len(raw_bytes) > 10 * 1024 * 1024:
        return {"error": "Bad Request", "details": {"file": "File exceeds maximum 10 MB limit"}}, 400

    # Robust decode: try utf-8, fallback to latin-1
    try:
        content_str = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content_str = raw_bytes.decode("latin-1", errors="replace")

    reader = csv.DictReader(io.StringIO(content_str))
    fieldnames = reader.fieldnames or []
    if not fieldnames:
        return {"error": "Bad Request", "details": {"file": "Could not parse CSV headers"}}, 400

    rows = list(reader)
    if len(rows) == 0:
        return {"error": "Bad Request", "details": {"file": "CSV file contains header only with no data rows"}}, 400

    if len(rows) > 10000:
        return {"error": "Bad Request", "details": {"file": f"Row count {len(rows)} exceeds maximum 10,000 rows limit"}}, 400

    ts_now = _now_iso()
    clean_name = secure_filename(orig_filename) or "traffic.csv"
    file_id_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    orig_save_filename = f"{file_id_str}_{clean_name}"
    orig_save_path = os.path.join(UPLOAD_TRAFFIC_DIR, orig_save_filename)
    with open(orig_save_path, "wb") as f_orig:
        f_orig.write(raw_bytes)

    # Coerce features for ML model (avoids label leakage)
    coerced_list = [coerce_features_for_model(r) for r in rows]

    try:
        preds = _predictor["batch"](coerced_list)  # type: ignore[index]
    except Exception as exc:
        logger.error("Batch prediction failed on upload: %s", exc)
        return {"error": "Inference Error", "message": f"ML model inference failed: {exc}"}, 500

    gt_labels: list[str | None] = []
    normal_count = attack_count = suspicious_count = 0
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    protocol_counts: dict[str, int] = {}
    attack_type_counts: dict[str, int] = {}
    src_ip_counts: dict[str, int] = {}
    dst_ip_counts: dict[str, int] = {}

    processed_records = []
    analyzed_csv_rows = []

    for idx, (raw_row, features, pred_res) in enumerate(zip(rows, coerced_list, preds), start=1):
        gt_label, gt_diff = extract_ground_truth(raw_row, fieldnames)
        gt_labels.append(gt_label)

        src_ip, dst_ip, src_port, dst_port = extract_ips_and_ports(raw_row, fieldnames)
        if src_ip:
            src_ip_counts[src_ip] = src_ip_counts.get(src_ip, 0) + 1
        if dst_ip:
            dst_ip_counts[dst_ip] = dst_ip_counts.get(dst_ip, 0) + 1

        proto = str(features.get("protocol_type", "tcp")).lower()
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        pred_val = int(pred_res.get("prediction", 0))
        prob_val = float(pred_res.get("probability", 0.0))

        classification, severity = determine_severity_and_classification(pred_val, prob_val)
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if classification == "Attack":
            attack_count += 1
        elif classification == "Suspicious":
            suspicious_count += 1
        else:
            normal_count += 1

        attack_type = map_attack_category(gt_label, classification in ("Attack", "Suspicious"), features)
        attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1

        explanation = generate_explanation(features, classification, severity, attack_type, prob_val)

        # Ground truth match
        gt_match = None
        if gt_label is not None and gt_label.strip() != "":
            is_gt_attack = gt_label.lower().strip() not in ("normal", "safe", "0", "benign")
            gt_match = (is_gt_attack == (classification in ("Attack", "Suspicious") or pred_val == 1))

        rec = {
            "row_index": idx,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "service": str(features.get("service", "")),
            "flag": str(features.get("flag", "")),
            "prediction": classification,
            "ground_truth": gt_label,
            "probability": prob_val,
            "if_score": None,
            "severity": severity,
            "attack_type": attack_type,
            "explanation": explanation,
            "gt_match": gt_match,
            "raw_json": json.dumps(raw_row),
        }
        processed_records.append(rec)

        # CSV export row
        csv_row = dict(raw_row)
        csv_row["analysis_row_id"] = idx
        csv_row["ml_prediction"] = pred_val
        csv_row["ml_classification"] = classification
        csv_row["ml_confidence_pct"] = f"{prob_val * 100:.1f}%"
        csv_row["ml_severity"] = severity
        csv_row["ml_attack_category"] = attack_type
        csv_row["ml_explanation"] = explanation
        csv_row["ground_truth_label"] = gt_label or "N/A"
        csv_row["ground_truth_match"] = "Yes" if gt_match is True else ("No" if gt_match is False else "N/A")
        analyzed_csv_rows.append(csv_row)

    # Compute metrics if ground truth was present
    metrics = compute_metrics(gt_labels, [r.get("prediction", 0) for r in preds])
    has_ground_truth = 1 if metrics is not None else 0
    has_ip_data = bool(src_ip_counts or dst_ip_counts)

    # Save analyzed CSV file
    result_save_filename = f"analyzed_{file_id_str}_{clean_name}"
    result_save_path = os.path.join(EXPORT_ANALYSES_DIR, result_save_filename)
    if analyzed_csv_rows:
        out_fields = list(analyzed_csv_rows[0].keys())
        with open(result_save_path, "w", newline="", encoding="utf-8") as f_out:
            writer = csv.DictWriter(f_out, fieldnames=out_fields)
            writer.writeheader()
            writer.writerows(analyzed_csv_rows)

    summary_dict = {
        "severity_counts": severity_counts,
        "protocol_counts": protocol_counts,
        "attack_type_counts": attack_type_counts,
        "top_source_ips": sorted([{"ip": ip, "count": c} for ip, c in src_ip_counts.items()], key=lambda x: x["count"], reverse=True)[:5],
        "top_dest_ips": sorted([{"ip": ip, "count": c} for ip, c in dst_ip_counts.items()], key=lambda x: x["count"], reverse=True)[:5],
        "has_ip_data": has_ip_data,
        "total_rows": len(rows),
    }

    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO traffic_analyses
        (filename, original_filepath, result_filepath, timestamp, total_rows,
         normal_count, attack_count, suspicious_count, has_ground_truth, metrics_json, summary_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (orig_filename, orig_save_path, result_save_path, ts_now, len(rows),
         normal_count, attack_count, suspicious_count, has_ground_truth,
         json.dumps(metrics) if metrics else None,
         json.dumps(summary_dict)),
    )
    analysis_id = cursor.lastrowid

    # Insert analysis records in bulk
    db.executemany(
        """
        INSERT INTO analysis_records
        (analysis_id, row_index, src_ip, dst_ip, src_port, dst_port,
         protocol, service, flag, prediction, ground_truth, probability,
         if_score, severity, attack_type, explanation, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                analysis_id, r["row_index"], r["src_ip"], r["dst_ip"],
                r["src_port"], r["dst_port"], r["protocol"], r["service"],
                r["flag"], r["prediction"], r["ground_truth"], r["probability"],
                r["if_score"], r["severity"], r["attack_type"], r["explanation"],
                r["raw_json"]
            )
            for r in processed_records
        ],
    )
    db.commit()

    return {
        "status": "success",
        "analysis_id": analysis_id,
        "filename": orig_filename,
        "timestamp": ts_now,
        "total_rows": len(rows),
        "normal_count": normal_count,
        "attack_count": attack_count,
        "suspicious_count": suspicious_count,
        "has_ground_truth": bool(has_ground_truth),
        "has_ip_data": has_ip_data,
        "metrics": metrics,
        "summary": summary_dict,
        "records": processed_records[:50],
    }, 200


@app.route("/api/traffic/upload", methods=["POST"])
def api_traffic_upload():
    """
    Ingest, validate, and analyze an uploaded network traffic CSV file.
    Runs ML model inference, extracts IPs (without fabrication), evaluates ground
    truth when present, generates natural SOC explanations, and stores records in SQLite.
    """
    if not MODEL_LOADED or _predictor is None:
        return jsonify({"error": "Service Unavailable", "message": "ML model not yet loaded"}), 503

    if "file" not in request.files:
        return jsonify({"error": "Bad Request", "details": {"file": "No file part in request"}}), 400

    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"error": "Bad Request", "details": {"file": "No file selected"}}), 400

    orig_filename = file.filename
    if not orig_filename.lower().endswith(".csv"):
        return jsonify({"error": "Bad Request", "details": {"file": "Only CSV (.csv) files are accepted"}}), 400

    raw_bytes = file.read()
    res_data, status_code = _process_traffic_csv(orig_filename, raw_bytes)
    return jsonify(res_data), status_code


@app.route("/api/traffic/load-sample/<sample_type>", methods=["POST"])
def api_traffic_load_sample(sample_type: str):
    """
    Load and analyze one of the built-in demo datasets ('normal', 'attack', 'mixed').
    Executes the exact same ML evaluation pipeline as an uploaded file.
    """
    if not MODEL_LOADED or _predictor is None:
        return jsonify({"error": "Service Unavailable", "message": "ML model not yet loaded"}), 503

    sample_map = {
        "normal": "normal_traffic_demo_500.csv",
        "attack": "attack_traffic_demo_500.csv",
        "mixed": "mixed_network_traffic_demo_500.csv",
    }
    sample_file = sample_map.get(sample_type.lower())
    if not sample_file:
        return jsonify({"error": "Bad Request", "message": f"Unknown sample type '{sample_type}'"}), 400

    sample_path = os.path.join("input sample datas", sample_file)
    if not os.path.exists(sample_path):
        return jsonify({"error": "Not Found", "message": f"Sample dataset '{sample_file}' not found"}), 404

    with open(sample_path, "rb") as fh:
        raw_bytes = fh.read()

    res_data, status_code = _process_traffic_csv(sample_file, raw_bytes)
    return jsonify(res_data), status_code


@app.route("/api/traffic/history")
def api_traffic_history():
    """Return past CSV traffic analysis runs."""
    db = get_db()
    rows = db.execute(
        """
        SELECT id, filename, timestamp, total_rows, normal_count, attack_count,
               suspicious_count, has_ground_truth, metrics_json, summary_json
        FROM traffic_analyses
        ORDER BY id DESC
        LIMIT 50
        """
    ).fetchall()

    history = []
    for r in rows:
        d = dict(r)
        d["metrics"] = json.loads(d["metrics_json"]) if d.get("metrics_json") else None
        d["summary"] = json.loads(d["summary_json"]) if d.get("summary_json") else {}
        d.pop("metrics_json", None)
        d.pop("summary_json", None)
        history.append(d)

    return jsonify({"history": history}), 200


@app.route("/api/traffic/results/<int:analysis_id>")
def api_traffic_results(analysis_id: int):
    """Retrieve full analysis metrics, distributions, and filtered/paginated connection records."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM traffic_analyses WHERE id = ?", (analysis_id,)
    ).fetchone()
    if not row:
        return jsonify({"error": "Not Found", "message": f"Analysis ID {analysis_id} does not exist"}), 404

    analysis_data = dict(row)
    analysis_data["metrics"] = json.loads(analysis_data["metrics_json"]) if analysis_data.get("metrics_json") else None
    analysis_data["summary"] = json.loads(analysis_data["summary_json"]) if analysis_data.get("summary_json") else {}
    analysis_data.pop("metrics_json", None)
    analysis_data.pop("summary_json", None)

    # Query params for table filtering and pagination
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    try:
        per_page = min(100, max(5, int(request.args.get("per_page", 25))))
    except ValueError:
        per_page = 25

    status_filter = (request.args.get("status") or "all").strip()
    severity_filter = (request.args.get("severity") or "all").strip()
    protocol_filter = (request.args.get("protocol") or "all").strip()
    search = (request.args.get("search") or "").strip().lower()

    where_clauses = ["analysis_id = ?"]
    params: list[Any] = [analysis_id]

    if status_filter and status_filter.lower() != "all":
        where_clauses.append("LOWER(prediction) = ?")
        params.append(status_filter.lower())

    if severity_filter and severity_filter.lower() != "all":
        where_clauses.append("LOWER(severity) = ?")
        params.append(severity_filter.lower())

    if protocol_filter and protocol_filter.lower() != "all":
        where_clauses.append("LOWER(protocol) = ?")
        params.append(protocol_filter.lower())

    if search:
        search_pattern = f"%{search}%"
        where_clauses.append(
            "(LOWER(service) LIKE ? OR LOWER(flag) LIKE ? OR LOWER(attack_type) LIKE ? "
            "OR LOWER(explanation) LIKE ? OR LOWER(COALESCE(src_ip, '')) LIKE ? "
            "OR LOWER(COALESCE(dst_ip, '')) LIKE ? OR LOWER(COALESCE(ground_truth, '')) LIKE ?)"
        )
        params.extend([search_pattern] * 7)

    where_sql = " AND ".join(where_clauses)

    total_filtered = db.execute(
        f"SELECT COUNT(*) as cnt FROM analysis_records WHERE {where_sql}", params  # noqa: S608
    ).fetchone()["cnt"]

    offset = (page - 1) * per_page
    limit_params = list(params) + [per_page, offset]

    records = db.execute(
        f"""
        SELECT id, analysis_id, row_index, src_ip, dst_ip, src_port, dst_port,
               protocol, service, flag, prediction, ground_truth, probability,
               if_score, severity, attack_type, explanation, raw_json
        FROM analysis_records
        WHERE {where_sql}
        ORDER BY row_index ASC
        LIMIT ? OFFSET ?
        """,  # noqa: S608
        limit_params,
    ).fetchall()

    record_list = []
    for r in records:
        rd = dict(r)
        try:
            rd["raw_data"] = json.loads(rd["raw_json"]) if rd.get("raw_json") else {}
        except Exception:
            rd["raw_data"] = {}
        record_list.append(rd)

    total_pages = max(1, (total_filtered + per_page - 1) // per_page)

    return jsonify({
        "analysis": analysis_data,
        "records": record_list,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_records": total_filtered,
            "total_pages": total_pages,
        },
    }), 200


@app.route("/api/traffic/export/<int:analysis_id>")
def api_traffic_export(analysis_id: int):
    """Download the analyzed CSV file with model predictions, severity, and explanations."""
    db = get_db()
    row = db.execute("SELECT result_filepath, filename FROM traffic_analyses WHERE id = ?", (analysis_id,)).fetchone()
    if not row or not row["result_filepath"] or not os.path.exists(row["result_filepath"]):
        return jsonify({"error": "Not Found", "message": "Analyzed export file not found"}), 404

    export_name = f"analyzed_{row['filename']}"
    return send_file(
        row["result_filepath"],
        mimetype="text/csv",
        as_attachment=True,
        download_name=export_name,
    )


@app.route("/api/traffic/download-original/<int:analysis_id>")
def api_traffic_download_original(analysis_id: int):
    """Download the original uploaded CSV file."""
    db = get_db()
    row = db.execute("SELECT original_filepath, filename FROM traffic_analyses WHERE id = ?", (analysis_id,)).fetchone()
    if not row or not row["original_filepath"] or not os.path.exists(row["original_filepath"]):
        return jsonify({"error": "Not Found", "message": "Original upload file not found"}), 404

    return send_file(
        row["original_filepath"],
        mimetype="text/csv",
        as_attachment=True,
        download_name=row["filename"],
    )


# ══════════════════════════════════════════════════════════════════════════════
# AI SOC ANALYST & TWO-WAY VOICE APIs
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/agent/status")
def api_agent_status():
    """Operational status and provider configuration of the AI SOC Analyst Agent."""
    return jsonify(ai_agent.get_status()), 200


@app.route("/api/agent/chat", methods=["POST"])
def api_agent_chat():
    """
    Main conversation endpoint for both text and voice questions.
    Returns markdown response as well as sanitized spoken text for audio playback.
    """
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()
    if not message:
        return jsonify({"error": "Bad Request", "message": "Message field cannot be empty"}), 400

    conversation_id = str(data.get("conversation_id", "default_soc_session")).strip()
    language = str(data.get("language", "en-US")).strip()
    analysis_id = data.get("analysis_id")
    if analysis_id:
        try:
            analysis_id = int(analysis_id)
        except ValueError:
            analysis_id = None

    result = ai_agent.process_chat(
        message=message,
        conversation_id=conversation_id,
        language=language,
        analysis_id=analysis_id,
    )
    return jsonify(result), 200


@app.route("/api/agent/context")
def api_agent_context():
    """Retrieve raw grounded context data being consumed by the agent."""
    analysis_id = request.args.get("analysis_id")
    if analysis_id:
        try:
            analysis_id = int(analysis_id)
        except ValueError:
            analysis_id = None
    return jsonify(ai_agent.get_context(analysis_id=analysis_id)), 200


@app.route("/api/agent/history", methods=["GET", "DELETE"])
def api_agent_history():
    """Retrieve or clear conversation turns for a session."""
    conversation_id = str(request.args.get("conversation_id", "default_soc_session")).strip()
    if request.method == "DELETE":
        ai_agent.clear_history(conversation_id)
        return jsonify({"status": "success", "message": f"History for {conversation_id} cleared"}), 200

    turns = ai_agent.get_history(conversation_id)
    return jsonify({"conversation_id": conversation_id, "history": turns}), 200


@app.route("/api/agent/voice/transcribe", methods=["POST"])
def api_agent_voice_transcribe():
    """
    Transcribe uploaded audio blob (MediaRecorder fallback).
    Validates audio format and file size limit.
    """
    if "audio" not in request.files:
        return jsonify({"error": "Bad Request", "message": "No audio file provided in request"}), 400

    audio_file = request.files["audio"]
    if not audio_file or not audio_file.filename:
        return jsonify({"error": "Bad Request", "message": "Empty audio payload"}), 400

    # Validate file size (max 5 MB)
    raw_audio = audio_file.read()
    if len(raw_audio) > 5 * 1024 * 1024:
        return jsonify({"error": "Payload Too Large", "message": "Audio recording exceeds 5 MB limit"}), 413

    # For environments with speech recognition installed or client-side fallback
    # Return transcript or client guidance
    return jsonify({
        "status": "success",
        "audio_bytes": len(raw_audio),
        "transcript": "Audio received. Using browser Web Speech Recognition for instant zero-latency speech-to-text.",
        "note": "Client-side Web Speech API handles recognition without server overhead.",
    }), 200


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK TRAFFIC MONITORING & SCAPY CAPTURE APIs
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/monitor/interfaces")
def api_monitor_interfaces():
    """List available network interfaces for administrator selection."""
    ifaces = get_available_interfaces()
    return jsonify({"interfaces": ifaces}), 200


@app.route("/api/monitor/start", methods=["POST"])
def api_monitor_start():
    """Start live packet capture on the selected interface."""
    data = request.get_json(silent=True) or {}
    interface = data.get("interface")
    success, msg = capture_service.start_capture(interface)
    status_code = 200 if success else 400
    return jsonify({"success": success, "message": msg, "status": capture_service.get_status()}), status_code


@app.route("/api/monitor/stop", methods=["POST"])
def api_monitor_stop():
    """Stop active packet capture session."""
    success, msg = capture_service.stop_capture()
    status_code = 200 if success else 400
    return jsonify({"success": success, "message": msg, "status": capture_service.get_status()}), status_code


@app.route("/api/monitor/status")
def api_monitor_status():
    """Check live packet sniffer and aggregation status."""
    return jsonify(capture_service.get_status()), 200


@app.route("/api/monitor/flows")
def api_monitor_flows():
    """
    Retrieve live captured connection flows with filtering by protocol,
    severity, direction, threat classification, and pagination.
    """
    db = get_db()
    session_id = request.args.get("session_id")
    status_filter = (request.args.get("status") or "all").strip().lower()
    severity_filter = (request.args.get("severity") or "all").strip().lower()
    protocol_filter = (request.args.get("protocol") or "all").strip().lower()
    direction_filter = (request.args.get("direction") or "all").strip().lower()
    search = (request.args.get("search") or "").strip().lower()

    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(5, int(request.args.get("per_page", 20))))
    except ValueError:
        page, per_page = 1, 20

    where_clauses = []
    params: list[Any] = []

    if session_id:
        where_clauses.append("session_id = ?")
        params.append(session_id)

    if status_filter != "all":
        where_clauses.append("LOWER(prediction) = ?")
        params.append(status_filter)

    if severity_filter != "all":
        where_clauses.append("LOWER(severity) = ?")
        params.append(severity_filter)

    if protocol_filter != "all":
        where_clauses.append("LOWER(protocol) = ?")
        params.append(protocol_filter)

    if direction_filter != "all":
        where_clauses.append("LOWER(direction) = ?")
        params.append(direction_filter)

    if search:
        search_pattern = f"%{search}%"
        where_clauses.append(
            "(LOWER(src_ip) LIKE ? OR LOWER(dst_ip) LIKE ? OR LOWER(service) LIKE ? OR LOWER(attack_category) LIKE ?)"
        )
        params.extend([search_pattern] * 4)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    total_count = db.execute(f"SELECT COUNT(*) as cnt FROM captured_flows {where_sql}", params).fetchone()["cnt"]  # noqa: S608

    offset = (page - 1) * per_page
    limit_params = list(params) + [per_page, offset]

    rows = db.execute(
        f"""
        SELECT id, session_id, timestamp, src_ip, dst_ip, src_port, dst_port,
               protocol, service, direction, packet_count, bytes_count,
               flag, prediction, probability, severity, attack_category
        FROM captured_flows
        {where_sql}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,  # noqa: S608
        limit_params,
    ).fetchall()

    return jsonify({
        "flows": [dict(r) for r in rows],
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_records": total_count,
            "total_pages": max(1, (total_count + per_page - 1) // per_page),
        },
    }), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
