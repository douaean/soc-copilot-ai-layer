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

app = FastAPI(
    title="AI-Native SOC Copilot — AI Layer",
    description="Ingests Wazuh alerts, retrieves context, reasons via "
    "multi-agent RAG, and produces analyst reports.",
    version="0.1.0",
)


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Basic liveness check — confirms the API process is up."""
    return {"status": "ok"}


# TODO (M2 onward): mount routers for /alerts (ingestion trigger/status),
# /investigations (agent results), /reports (analyst reports) once those
# modules are implemented. Keep routers in separate files under app/api/
# and include them here with app.include_router(...) — do not grow this
# file into a monolith.
