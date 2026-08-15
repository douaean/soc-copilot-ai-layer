from typing import Any

from fastapi import APIRouter, HTTPException, status
from app.core.orchestrator import investigate_alert
from app.validation.models import WazuhAlertModel

router = APIRouter()


@router.post("", response_model=dict[str, Any], status_code=status.HTTP_200_OK)
async def run_investigation(alert: WazuhAlertModel) -> dict[str, Any]:
    """Accept a validated Wazuh alert and run the investigation workflow."""
    try:
        return await investigate_alert(alert)
    except NotImplementedError as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation failed: {exc}",
        )
