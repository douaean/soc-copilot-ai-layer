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

    NOTE: this is a skeleton. Implementation (auth, interval config,
    async HTTP client, dedup of already-seen alerts) happens in M2.
    """

    def __init__(self, base_url: str, poll_interval_seconds: int = 5) -> None:
        self.base_url = base_url
        self.poll_interval_seconds = poll_interval_seconds

    async def fetch_new_alerts(self) -> list[dict[str, Any]]:
        """
        Returns raw, unvalidated alert JSON objects from Wazuh.

        IMPORTANT (see docs/ARCHITECTURE.md §3.1):
        This must use an async-compatible HTTP client (e.g. httpx),
        never a synchronous one (e.g. requests) — a blocking call here
        would freeze the entire FastAPI event loop for all other
        concurrent requests, not just this one.
        """
        raise NotImplementedError("Implement in Milestone 2.")
