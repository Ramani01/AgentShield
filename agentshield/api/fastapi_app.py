"""
AgentShield REST API Server (FastAPI).
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel

try:
    from fastapi import FastAPI, HTTPException
except ImportError:
    FastAPI = None

from agentshield.core.config import ShieldConfig
from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.exceptions import AgentShieldError

class InspectionRequest(BaseModel):
    prompt: str
    tenant_id: Optional[str] = "default"

class InspectionResponse(BaseModel):
    status: str
    sanitized_prompt: str
    metadata: Dict[str, Any]

def create_app(config: Optional[ShieldConfig] = None):
    """Creates FastAPI application instance for AgentShield service."""
    if FastAPI is None:
        raise ImportError("FastAPI is required for running AgentShield REST API server.")

    app = FastAPI(
        title="AgentShield API",
        version="0.1.0",
        description="Security, Safety, and Governance Service for AI Agents"
    )

    pipeline = SecurityPipeline(config=config or ShieldConfig())

    @app.get("/health")
    def health_check():
        return {"status": "HEALTHY", "version": "0.1.0"}

    @app.post("/v1/shield/inspect", response_model=InspectionResponse)
    def inspect_prompt(request: InspectionRequest):
        try:
            clean_prompt, meta = pipeline.inspect_input(request.prompt, tenant_id=request.tenant_id)
            return InspectionResponse(
                status="APPROVED",
                sanitized_prompt=clean_prompt,
                metadata=meta
            )
        except AgentShieldError as e:
            raise HTTPException(
                status_code=400,
                detail={"error": str(e), "details": getattr(e, "details", {})}
            )

    @app.get("/v1/shield/telemetry")
    def get_telemetry():
        return pipeline.telemetry.get_summary()

    return app
