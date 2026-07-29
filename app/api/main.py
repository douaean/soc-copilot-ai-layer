"""
FastAPI entry point — thin orchestrator only.

Responsibility (and ONLY responsibility):
    Wire up routes, dependency injection, and delegate immediately to the
    other layers (ingestion, validation, rag, agents, reporting). This
    file should stay small — business logic does NOT belong here.

Why FastAPI (see docs/ARCHITECTURE.md §3.1):
    Native async I/O for concurrent alert bursts (NFR3), built-in
    Pydantic validation at the boundary (NFR2).
"""

from fastapi import FastAPI

from app.api.routers import alerts_router, investigation_router

app = FastAPI(
    title="AI-Native SOC Copilot — AI Layer",
    description="Ingests Wazuh alerts, retrieves context, reasons via "
    "multi-agent RAG, and produces analyst reports.",
    version="0.1.0",
)

app.include_router(
    alerts_router,
    prefix="/alerts",
    tags=["alerts"],
)
app.include_router(
    investigation_router,
    prefix="/investigation",
    tags=["investigation"],
)


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Basic liveness check — confirms the API process is up."""
    return {"status": "ok"}
