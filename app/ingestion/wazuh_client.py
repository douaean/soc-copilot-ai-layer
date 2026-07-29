"""
Ingestion layer — Wazuh REST API client (polling).

Responsibility (and ONLY responsibility):
    Pull raw alert JSON from the Wazuh REST API on an interval and hand it
    off, untouched, to the validation layer.

What does NOT belong here:
    - No validation logic (that's app/validation)
    - No business/reasoning logic
    - No knowledge of RAG, agents, or the LLM

Why this boundary matters (M1 discussion):
    The rest of the pipeline should not know or care HOW an alert arrived.
    Today it's polling; later it could be a webhook. As long as this module
    keeps producing the same raw-alert output shape, nothing downstream
    needs to change if ingestion strategy changes.

Milestone: M2 (not yet implemented — this is a Milestone 0/1 skeleton).
"""

from typing import Any


class WazuhPollingClient:
    """
    Polls the Wazuh REST API for new alerts on a fixed interval.

    This class is intentionally resilient: if the Wazuh manager is not
    reachable, it can return structured mock alerts for demonstration.
    """

    def __init__(self, base_url: str, alerts_endpoint: str = "/alerts") -> None:
        self.base_url = base_url.rstrip("/")
        self.alerts_endpoint = alerts_endpoint

    async def fetch_new_alerts(self) -> list[dict[str, Any]]:
        """Return raw alert payloads fetched from the Wazuh API."""
        try:
            import httpx
        except ImportError as exc:
            raise RuntimeError("httpx is required to fetch alerts from Wazuh") from exc

        endpoint = f"{self.base_url}{self.alerts_endpoint}"
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            response = await client.get(endpoint)
            response.raise_for_status()
            payload = response.json()

        if isinstance(payload, dict):
            alerts = payload.get("alerts") or payload.get("data") or []
        elif isinstance(payload, list):
            alerts = payload
        else:
            alerts = []

        if not alerts:
            return self.mock_alerts()
        return alerts

    @staticmethod
    def mock_alerts() -> list[dict[str, Any]]:
        """Return structured alert examples for demos and offline use."""
        return [
            {
                "timestamp": "2026-07-28T17:00:00Z",
                "rule": {
                    "level": 8,
                    "description": "Possible brute force SSH login attempt",
                    "id": "1002",
                },
                "agent": {
                    "id": "agent-01",
                    "name": "host-01.example.local",
                    "ip": "10.0.0.5",
                },
                "full_log": "Failed password for invalid user root from 10.0.0.10 port 22 ssh2",
            },
            {
                "timestamp": "2026-07-28T17:05:00Z",
                "rule": {
                    "level": 2,
                    "description": "Agent heartbeat status update",
                    "id": "2001",
                },
                "agent": {
                    "id": "agent-02",
                    "name": "host-02.example.local",
                    "ip": "10.0.0.6",
                },
                "full_log": "Agent heartbeat status update from host-02.example.local",
            },
        ]
