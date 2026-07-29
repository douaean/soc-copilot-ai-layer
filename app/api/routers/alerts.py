from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.core.config import settings
from app.core.orchestrator import process_raw_alerts
from app.ingestion.wazuh_client import WazuhPollingClient

router = APIRouter()


@router.post("/ingest", response_model=list[dict[str, Any]])
async def ingest_alerts(
    raw_alerts: list[dict[str, Any]] | None = None,
    mock: bool = Query(False, description="Use built-in mock alerts instead of querying Wazuh."),
) -> list[dict[str, Any]]:
    """Ingest alerts from Wazuh or a mock sample payload and run the investigation pipeline."""
    if raw_alerts is not None:
        alerts = raw_alerts
    elif mock:
        alerts = WazuhPollingClient.mock_alerts()
    else:
        client = WazuhPollingClient(
            base_url=settings.wazuh_api_base_url,
            alerts_endpoint=settings.wazuh_alerts_endpoint,
        )
        try:
            alerts = await client.fetch_new_alerts()
        except Exception:
            alerts = WazuhPollingClient.mock_alerts()

    return await process_raw_alerts(alerts)


@router.get("/sample", response_model=list[dict[str, Any]])
def get_sample_alerts() -> list[dict[str, Any]]:
    """Return a sample set of structured alerts for demonstration and validation."""
    return WazuhPollingClient.mock_alerts()
