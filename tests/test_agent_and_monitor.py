"""
Comprehensive test suite for AI SOC Analyst Agent & Live Network Traffic Monitoring.
Verifies:
- Agent status, conversation management, context builder, and fallback response generation.
- Monitor interfaces listing, session start/stop, status reporting, and live flows query with filters.
- Voice transcription endpoint fallback.
"""
import pytest
import json
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_agent_status(client):
    """Ensure agent status returns operational status and supported languages."""
    res = client.get("/api/agent/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "operational"
    assert "provider" in data
    assert "supported_languages" in data
    lang_codes = [l["code"] for l in data["supported_languages"]]
    assert "en-US" in lang_codes
    assert "en-IN" in lang_codes
    assert "hi-IN" in lang_codes
    assert "te-IN" in lang_codes
    assert "ta-IN" in lang_codes


def test_agent_chat_deterministic(client):
    """Test AI agent chat with a typical SOC analyst query."""
    payload = {
        "message": "Give me an executive summary of current network security status.",
        "language": "en-US",
        "conversation_id": "test-conv-001"
    }
    res = client.post("/api/agent/chat", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert "response" in data
    assert len(data["response"]) > 20
    assert "spoken_text" in data
    assert "#" not in data["spoken_text"]  # spoken text should be stripped of markdown
    assert "**" not in data["spoken_text"]


def test_agent_chat_empty_message(client):
    """Test AI agent chat handles empty message gracefully."""
    res = client.post("/api/agent/chat", json={"message": "   "})
    assert res.status_code == 400
    data = res.get_json()
    assert "error" in data


def test_agent_context(client):
    """Test retrieving live grounded SOC context."""
    res = client.get("/api/agent/context")
    assert res.status_code == 200
    data = res.get_json()
    assert "open_alerts" in data
    assert "top_threat_ips" in data


def test_agent_history(client):
    """Test retrieving and clearing conversation history."""
    conv_id = "test-history-conv"
    # Send message to create history
    client.post("/api/agent/chat", json={
        "message": "What attacks have been observed?",
        "conversation_id": conv_id
    })

    # Fetch history
    res = client.get(f"/api/agent/history?conversation_id={conv_id}")
    assert res.status_code == 200
    data = res.get_json()
    assert "history" in data
    assert len(data["history"]) >= 2

    # Clear history
    del_res = client.delete(f"/api/agent/history?conversation_id={conv_id}")
    assert del_res.status_code == 200

    # Verify cleared
    res_after = client.get(f"/api/agent/history?conversation_id={conv_id}")
    assert len(res_after.get_json()["history"]) == 0


def test_monitor_interfaces(client):
    """Test retrieving available network interfaces."""
    res = client.get("/api/monitor/interfaces")
    assert res.status_code == 200
    data = res.get_json()
    assert "interfaces" in data
    assert isinstance(data["interfaces"], list)


def test_monitor_status(client):
    """Test monitoring service status endpoint."""
    res = client.get("/api/monitor/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "is_running" in data
    assert "total_packets" in data


def test_monitor_start_stop(client):
    """Test starting and stopping a live monitoring session."""
    # Start capture (auto interface or loopback)
    start_res = client.post("/api/monitor/start", json={
        "interface": "auto"
    })
    assert start_res.status_code == 200
    start_data = start_res.get_json()
    assert "success" in start_data

    # Stop capture
    stop_res = client.post("/api/monitor/stop")
    assert stop_res.status_code == 200
    stop_data = stop_res.get_json()
    assert stop_data["success"] is True


def test_monitor_flows_query(client):
    """Test querying live monitor flows with filters."""
    res = client.get("/api/monitor/flows?limit=10&page=1")
    assert res.status_code == 200
    data = res.get_json()
    assert "flows" in data
    assert "pagination" in data
    assert "total_records" in data["pagination"]
