"""
tests/test_csv_investigation.py
-------------------------------
Comprehensive unit and integration tests for the CSV Traffic Analysis and Threat Investigation module.
Covers:
1. Ingestion of standard NSL-KDD demo CSVs (Normal, Attack, Mixed)
2. Accurate ground-truth metric calculation without feature leakage
3. Safe IP address handling (absence correctly recognized without fabricating fake addresses)
4. Detection of IP address and port fields when explicitly provided in CSVs
5. Error handling: non-CSV, empty file, missing upload
6. History retrieval, record search, filtering, and pagination
7. Original file download and analyzed CSV export
"""

import io
import json
import os
import pytest

from app import app
from database.db import init_db


@pytest.fixture(scope="module")
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        with app.app_context():
            init_db(app)
        yield client


def test_traffic_upload_missing_file(client):
    """POST /api/traffic/upload without file returns 400."""
    res = client.post("/api/traffic/upload", data={})
    assert res.status_code == 400
    data = res.get_json()
    assert "No file part" in data["details"]["file"]


def test_traffic_upload_invalid_extension(client):
    """POST /api/traffic/upload with non-csv file returns 400."""
    data = {"file": (io.BytesIO(b"not,a,csv"), "test.txt")}
    res = client.post("/api/traffic/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "Only CSV" in res.get_json()["details"]["file"]


def test_traffic_upload_empty_csv(client):
    """POST /api/traffic/upload with 0 bytes returns 400."""
    data = {"file": (io.BytesIO(b""), "empty.csv")}
    res = client.post("/api/traffic/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "empty" in res.get_json()["details"]["file"]


def test_traffic_upload_header_only_csv(client):
    """POST /api/traffic/upload with header but no rows returns 400."""
    content = b"duration,protocol_type,service,flag,src_bytes,dst_bytes\n"
    data = {"file": (io.BytesIO(content), "header_only.csv")}
    res = client.post("/api/traffic/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "no data rows" in res.get_json()["details"]["file"]


def test_traffic_load_sample_normal(client):
    """Test loading built-in normal demo dataset via /api/traffic/load-sample/normal."""
    res = client.post("/api/traffic/load-sample/normal")
    assert res.status_code == 200
    data = res.get_json()

    assert data["status"] == "success"
    assert data["total_rows"] == 500
    assert data["normal_count"] > 400  # Vast majority normal
    assert data["has_ground_truth"] is True
    assert data["has_ip_data"] is False  # Honest check: NSL-KDD schema has no IPs
    assert "metrics" in data
    assert data["metrics"]["accuracy"] > 80.0

    # Ensure no fake IP was fabricated
    for rec in data["records"]:
        assert rec["src_ip"] is None
        assert rec["dst_ip"] is None


def test_traffic_load_sample_attack(client):
    """Test loading built-in attack demo dataset via /api/traffic/load-sample/attack."""
    res = client.post("/api/traffic/load-sample/attack")
    assert res.status_code == 200
    data = res.get_json()

    assert data["status"] == "success"
    assert data["total_rows"] == 500
    assert data["attack_count"] > 150
    assert data["has_ground_truth"] is True
    assert "DoS" in str(data["summary"]["attack_type_counts"]) or "Probe" in str(data["summary"]["attack_type_counts"])


def test_traffic_load_sample_mixed(client):
    """Test loading built-in mixed demo dataset via /api/traffic/load-sample/mixed."""
    res = client.post("/api/traffic/load-sample/mixed")
    assert res.status_code == 200
    data = res.get_json()

    assert data["status"] == "success"
    assert data["total_rows"] == 500
    assert data["normal_count"] > 0
    assert data["attack_count"] > 0


def test_traffic_upload_with_explicit_ips(client):
    """Test that CSVs with IP columns correctly preserve and extract IP telemetry."""
    csv_content = """src_ip,dst_ip,src_port,dst_port,duration,protocol_type,service,flag,src_bytes,dst_bytes,land,wrong_fragment,urgent,hot,num_failed_logins,logged_in,num_compromised,root_shell,su_attempted,num_root,num_file_creations,num_shells,num_access_files,num_outbound_cmds,is_host_login,is_guest_login,count,srv_count,serror_rate,srv_serror_rate,rerror_rate,srv_rerror_rate,same_srv_rate,diff_srv_rate,srv_diff_host_rate,dst_host_count,dst_host_srv_count,dst_host_same_srv_rate,dst_host_diff_srv_rate,dst_host_same_src_port_rate,dst_host_srv_diff_host_rate,dst_host_serror_rate,dst_host_srv_serror_rate,dst_host_rerror_rate,dst_host_srv_rerror_rate
192.168.1.105,10.0.0.1,54321,80,0,tcp,http,SF,215,45076,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,1,0,0,255,11,0.04,0.06,0,0,0,0,0,0
192.168.1.200,10.0.0.5,41234,443,0,tcp,private,REJ,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,229,10,0,0,1,1,0.04,0.06,0,255,10,0.04,0.06,0,0,0,0,1,1
"""
    data = {"file": (io.BytesIO(csv_content.encode("utf-8")), "custom_enterprise_ips.csv")}
    res = client.post("/api/traffic/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    res_data = res.get_json()

    assert res_data["total_rows"] == 2
    assert res_data["has_ip_data"] is True
    assert res_data["summary"]["top_source_ips"][0]["ip"] in ("192.168.1.105", "192.168.1.200")

    records = res_data["records"]
    assert records[0]["src_ip"] == "192.168.1.105"
    assert records[0]["dst_ip"] == "10.0.0.1"
    assert records[0]["src_port"] == "54321"
    assert records[0]["dst_port"] == "80"


def test_traffic_history(client):
    """GET /api/traffic/history returns the list of analyses."""
    res = client.get("/api/traffic/history")
    assert res.status_code == 200
    history = res.get_json().get("history", [])
    assert len(history) >= 1
    first = history[0]
    assert "id" in first
    assert "filename" in first
    assert "total_rows" in first


def test_traffic_results_and_filtering(client):
    """GET /api/traffic/results/<id> returns paginated and filterable results."""
    # Get latest analysis ID
    hist_res = client.get("/api/traffic/history")
    latest_id = hist_res.get_json()["history"][0]["id"]

    # Basic fetch
    res = client.get(f"/api/traffic/results/{latest_id}?page=1&per_page=10")
    assert res.status_code == 200
    data = res.get_json()
    assert "analysis" in data
    assert "records" in data
    assert len(data["records"]) <= 10
    assert data["pagination"]["per_page"] == 10

    # Test filtering by protocol
    res_tcp = client.get(f"/api/traffic/results/{latest_id}?protocol=tcp")
    assert res_tcp.status_code == 200
    records = res_tcp.get_json()["records"]
    for r in records:
        assert r["protocol"].lower() == "tcp"


def test_traffic_downloads(client):
    """Test downloading the original file and analyzed export CSV."""
    hist_res = client.get("/api/traffic/history")
    latest_id = hist_res.get_json()["history"][0]["id"]

    # Download original
    orig_res = client.get(f"/api/traffic/download-original/{latest_id}")
    assert orig_res.status_code == 200
    assert "text/csv" in orig_res.content_type

    # Download analyzed CSV
    analyzed_res = client.get(f"/api/traffic/export/{latest_id}")
    assert analyzed_res.status_code == 200
    assert "text/csv" in analyzed_res.content_type
    content = analyzed_res.data.decode("utf-8")
    assert "ml_prediction" in content
    assert "ml_severity" in content
    assert "ml_explanation" in content
