"""
Orchestration layer — wires validation, retrieval, RAG, agents, and reporting.

Responsibility:
    Combine the modules beneath app/ into a single investigation workflow.

The orchestrator should stay thin: it delegates work to each layer and
transforms the final investigation state into an analyst-facing response.
"""

from typing import Any

from pydantic import ValidationError

from app.core.config import settings
from app.agents.graph import build_investigation_graph
from app.rag.pipeline import build_grounded_prompt
from app.reporting.report_builder import build_analyst_report
from app.retrieval.chroma_client import ChromaRetriever
from app.validation.models import WazuhAlertModel


async def investigate_alert(alert: WazuhAlertModel) -> dict[str, Any]:
    """Run the investigation workflow for a single validated alert."""
    retriever = ChromaRetriever(
        collection_name=settings.chroma_collection_name,
        persist_directory=settings.chroma_persist_directory,
    )

    retrieved_docs = retriever.query(alert.full_log)
    grounded_prompt = build_grounded_prompt(alert.full_log, retrieved_docs)
    graph = build_investigation_graph()
    initial_state = {
        "alert": alert.model_dump(),
        "retrieved_docs": retrieved_docs,
        "grounded_prompt": grounded_prompt,
        "correlation": None,
        "threat_intel": None,
        "status": None,
        "final_score": None,
    }

    investigation_result = graph.invoke(initial_state)
    report = build_analyst_report(investigation_result)

    return {
        "alert": initial_state["alert"],
        "retrieved_docs": retrieved_docs,
        "investigation_result": investigation_result,
        "report": report,
    }


async def process_raw_alerts(raw_alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate raw alert payloads and run the investigation pipeline on each one."""
    results: list[dict[str, Any]] = []
    for raw in raw_alerts:
        try:
            alert = WazuhAlertModel.model_validate(raw)
        except ValidationError as exc:
            results.append(
                {
                    "raw_alert": raw,
                    "status": "validation_failed",
                    "error": str(exc),
                }
            )
            continue

        investigation = await investigate_alert(alert)
        results.append(investigation)

    return results
