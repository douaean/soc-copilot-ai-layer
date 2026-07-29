from typing import Any


def is_false_positive(alert: dict[str, Any]) -> bool:
    """Estimate whether an alert is most likely a false positive."""
    text = alert.get("full_log", "").lower()
    benign_indicators = [
        "heartbeat",
        "status update",
        "system check",
        "scheduled scan",
        "configuration check",
        "agent started",
        "agent stop",
        "agent started",
        "verified",
    ]
    if any(indicator in text for indicator in benign_indicators):
        return True

    rule_level = alert.get("rule", {}).get("level", 0)
    if rule_level <= 2:
        return True

    if "failed password" in text and "invalid user" in text:
        return False

    if "authentication failure" in text and rule_level < 3:
        return True

    return False


def correlate_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Correlate an alert and produce a simple score used by the investigation flow."""
    false_positive = is_false_positive(alert)
    rule_level = alert.get("rule", {}).get("level", 0)
    correlation_score = max(0, min(100, rule_level * 10))
    if false_positive:
        correlation_score = min(correlation_score, 20)

    return {
        "correlation": {
            "false_positive": false_positive,
            "correlation_score": correlation_score,
        }
    }
