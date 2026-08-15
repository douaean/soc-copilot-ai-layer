from app.correlation.correlation import correlate_alert
from app.review.threat_intel import search_tavily


def test_correlate_alert_detects_false_positive():
    alert = {
        "timestamp": "2026-07-28T18:00:00Z",
        "rule": {"level": 1, "description": "Agent heartbeat status update", "id": "2001"},
        "agent": {"id": "agent-01", "name": "host-01", "ip": "10.0.0.5"},
        "full_log": "Agent heartbeat status update from host-01",
    }
    result = correlate_alert(alert)
    assert result["correlation"]["false_positive"] is True
    assert result["correlation"]["correlation_score"] <= 20


def test_threat_intel_search_returns_summary():
    result = search_tavily("ssh brute force invalid user")
    assert "summary" in result
    assert "confidence" in result
    assert result["source"] == "tavily.com"
