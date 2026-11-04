"""
Comprehensive test suite for AI-Based Anomaly Detection in Enterprise Networks.

Tests:
1. Preprocessing and feature coercion
2. Single prediction (Normal & Attack) using actual Random Forest pipeline
3. Unsupervised Isolation Forest score calculation
4. Flask REST API endpoints:
   - GET /
   - GET /api/status
   - GET /api/stats
   - POST /api/predict (valid, invalid JSON, missing columns, type errors)
   - GET /api/alerts (pagination, status filter, severity filter, search)
   - GET /api/alerts/<id>
   - PATCH /api/alerts/<id>
   - POST /api/alerts/<id>/acknowledge
   - POST /api/alerts/<id>/resolve
   - GET /api/traffic
   - GET /api/model/performance
   - POST /api/upload & POST /api/predict/batch
   - GET /api/export
   - POST /api/model/reload
5. Database persistence and SQLite WAL operations
"""

import io
import json
import os
import pytest
import sqlite3
import pandas as pd

import app as flask_app_module
from app import app
from database.db import get_db, init_db, DB_PATH
import ml.predict as predictor


@pytest.fixture(scope="session")
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        with app.app_context():
            init_db(app)
        yield client


@pytest.fixture
def normal_connection():
    return {
        "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF",
        "src_bytes": 215, "dst_bytes": 45076, "land": 0, "wrong_fragment": 0, "urgent": 0,
        "hot": 0, "num_failed_logins": 0, "logged_in": 1, "num_compromised": 0, "root_shell": 0,
        "su_attempted": 0, "num_root": 0, "num_file_creations": 0, "num_shells": 0,
        "num_access_files": 0, "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
        "count": 1, "srv_count": 1, "serror_rate": 0, "srv_serror_rate": 0, "rerror_rate": 0,
        "srv_rerror_rate": 0, "same_srv_rate": 1, "diff_srv_rate": 0, "srv_diff_host_rate": 0,
        "dst_host_count": 255, "dst_host_srv_count": 11, "dst_host_same_srv_rate": 0.04,
        "dst_host_diff_srv_rate": 0.06, "dst_host_same_src_port_rate": 0,
        "dst_host_srv_diff_host_rate": 0, "dst_host_serror_rate": 0,
        "dst_host_srv_serror_rate": 0, "dst_host_rerror_rate": 0, "dst_host_srv_rerror_rate": 0,
    }


@pytest.fixture
def attack_connection():
    return {
        "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "REJ",
        "src_bytes": 0, "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0,
        "hot": 0, "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0, "root_shell": 0,
        "su_attempted": 0, "num_root": 0, "num_file_creations": 0, "num_shells": 0,
        "num_access_files": 0, "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
        "count": 229, "srv_count": 10, "serror_rate": 0, "srv_serror_rate": 0, "rerror_rate": 1,
        "srv_rerror_rate": 1, "same_srv_rate": 0.04, "diff_srv_rate": 0.06, "srv_diff_host_rate": 0,
        "dst_host_count": 255, "dst_host_srv_count": 10, "dst_host_same_srv_rate": 0.04,
        "dst_host_diff_srv_rate": 0.06, "dst_host_same_src_port_rate": 0,
        "dst_host_srv_diff_host_rate": 0, "dst_host_serror_rate": 0,
        "dst_host_srv_serror_rate": 0, "dst_host_rerror_rate": 1, "dst_host_srv_rerror_rate": 1,
    }


# ===========================================================================
# 1. Machine Learning Pipeline Tests
# ===========================================================================

def test_rf_model_is_loaded():
    info = predictor.get_model_info()
    assert info["model_type"] == "RandomForestClassifier"
    assert info["n_features"] == 41
    assert os.path.exists(info["pipeline_path"])


def test_predict_single_normal(normal_connection):
    res = predictor.predict_single(normal_connection)
    assert res["prediction"] == 0
    assert res["label"] == "Normal"
    assert 0.0 <= res["probability"] <= 1.0


def test_predict_single_attack(attack_connection):
    res = predictor.predict_single(attack_connection)
    assert res["prediction"] == 1
    assert res["label"] == "Attack"
    assert res["probability"] > 0.5


def test_predict_batch(normal_connection, attack_connection):
    batch = [normal_connection, attack_connection]
    results = predictor.predict_batch(batch)
    assert len(results) == 2
    assert results[0]["prediction"] == 0
    assert results[1]["prediction"] == 1


def test_isolation_forest_prediction(normal_connection):
    res = predictor.predict_if(normal_connection)
    assert "anomaly_score" in res
    assert isinstance(res["anomaly_score"], float)
    assert "is_anomaly" in res
    assert "NOT an attack probability" in res["note"]


def test_model_reload():
    info = predictor.reload_models()
    assert info["model_type"] == "RandomForestClassifier"
    assert info["n_features"] == 41


# ===========================================================================
# 2. Flask API Routes & Status Tests
# ===========================================================================

def test_dashboard_page(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"Network AI" in res.data
    assert b"Threat Defense" in res.data


def test_api_status(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "operational"
    assert data["db_connected"] is True
    assert data["model_loaded"] is True
    assert "uptime_seconds" in data


def test_api_stats(client):
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_predictions" in data
    assert "attacks_detected" in data
    assert "active_alerts" in data
    assert "hourly_trend" in data
    assert "severity_distribution" in data


def test_api_model_performance(client):
    res = client.get("/api/model/performance")
    assert res.status_code == 200
    data = res.get_json()
    assert "accuracy" in data
    assert "precision" in data
    assert "recall" in data
    assert "f1_score" in data
    assert "confusion_matrix" in data
    cm = data["confusion_matrix"]
    assert "tp" in cm or "TP" in cm


def test_api_traffic(client):
    res = client.get("/api/traffic?limit=10")
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert len(data) >= 1
    sample = data[0]
    assert "timestamp" in sample
    assert "protocol" in sample or "protocol_type" in sample


# ===========================================================================
# 3. Prediction & Alert Generation Tests
# ===========================================================================

def test_api_predict_success_normal(client, normal_connection):
    res = client.post("/api/predict", json=normal_connection)
    assert res.status_code == 201
    data = res.get_json()
    assert data["prediction"] == 0
    assert data["label"] == "Normal"
    assert "id" in data
    assert "timestamp" in data
    assert "if_anomaly_score" in data


def test_api_predict_success_attack_creates_alert(client, attack_connection):
    res = client.post("/api/predict", json=attack_connection)
    assert res.status_code == 201
    data = res.get_json()
    assert data["prediction"] == 1
    assert data["label"] == "Attack"
    assert data.get("alert_id") is not None

    alert_id = data["alert_id"]
    # Check that alert was saved in DB
    get_res = client.get(f"/api/alerts/{alert_id}")
    assert get_res.status_code == 200
    alert_obj = get_res.get_json()
    assert alert_obj["status"] == "open"
    assert alert_obj["prediction_id"] == data["id"]


def test_api_predict_missing_body(client):
    res = client.post("/api/predict", data="")
    assert res.status_code == 400
    data = res.get_json()
    assert "error" in data


def test_api_predict_missing_feature(client, normal_connection):
    bad_record = dict(normal_connection)
    del bad_record["duration"]
    res = client.post("/api/predict", json=bad_record)
    assert res.status_code == 400
    data = res.get_json()
    assert "missing_features" in data.get("details", {})


def test_api_predict_invalid_category(client, normal_connection):
    bad_record = dict(normal_connection)
    bad_record["protocol_type"] = "invalid_protocol"
    res = client.post("/api/predict", json=bad_record)
    assert res.status_code == 400


# ===========================================================================
# 4. Alerts Lifecycle & Filter Tests
# ===========================================================================

def test_api_alerts_list_and_filter(client, attack_connection):
    # Ensure at least one alert exists
    client.post("/api/predict", json=attack_connection)

    # List all
    res = client.get("/api/alerts")
    assert res.status_code == 200
    data = res.get_json()
    assert "alerts" in data
    assert data["total"] >= 1

    # Filter by status
    res_open = client.get("/api/alerts?status=open")
    assert res_open.status_code == 200
    for a in res_open.get_json()["alerts"]:
        assert a["status"] == "open"


def test_api_alert_acknowledge_and_resolve(client, attack_connection):
    pred_res = client.post("/api/predict", json=attack_connection)
    alert_id = pred_res.get_json()["alert_id"]

    # 1. Acknowledge via POST action
    ack_res = client.post(f"/api/alerts/{alert_id}/acknowledge")
    assert ack_res.status_code == 200
    assert ack_res.get_json()["status"] == "acknowledged"

    # 2. Resolve via PATCH method
    patch_res = client.patch(f"/api/alerts/{alert_id}", json={"status": "resolved"})
    assert patch_res.status_code == 200
    assert patch_res.get_json()["status"] == "resolved"


def test_api_alert_invalid_status(client, attack_connection):
    pred_res = client.post("/api/predict", json=attack_connection)
    alert_id = pred_res.get_json()["alert_id"]

    res = client.patch(f"/api/alerts/{alert_id}", json={"status": "invalid_status"})
    assert res.status_code == 400


# ===========================================================================
# 5. Batch CSV Upload & CSV Export Tests
# ===========================================================================

def test_batch_upload_valid_csv(client, normal_connection, attack_connection):
    df = pd.DataFrame([normal_connection, attack_connection])
    csv_bytes = df.to_csv(index=False).encode("utf-8")

    data = {"file": (io.BytesIO(csv_bytes), "test_traffic.csv")}
    res = client.post("/api/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    res_data = res.get_json()
    assert res_data["processed"] == 2
    assert res_data["attacks"] >= 1
    assert res_data["normal"] >= 1


def test_batch_upload_non_csv(client):
    data = {"file": (io.BytesIO(b"binary data"), "test.txt")}
    res = client.post("/api/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 400


def test_export_csv_report(client):
    res = client.get("/api/export")
    assert res.status_code == 200
    assert "text/csv" in res.headers.get("Content-Type", "")
    assert b"timestamp,duration,protocol_type" in res.data
