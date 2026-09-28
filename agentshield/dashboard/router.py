"""
Dashboard REST API Router for AgentShield Security Observability.

Provides 10 read-only endpoints for dashboard visualization.
Enforces strict READ-ONLY access (no mutation endpoints), tenant isolation, and sanitized error responses.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

try:
    from fastapi import APIRouter, HTTPException, Query, Path
except ImportError:
    APIRouter = None
    HTTPException = Exception
    Query = lambda **k: None
    Path = lambda **k: None

from agentshield.dashboard.provider import DashboardDataProvider

def create_dashboard_router(provider: Optional[DashboardDataProvider] = None):
    """Factory function returning FastAPI APIRouter for dashboard endpoints."""
    if APIRouter is None:
        raise ImportError("FastAPI is required for running AgentShield Dashboard API.")

    router = APIRouter(prefix="/api/dashboard", tags=["Security Dashboard"])
    data_provider = provider or DashboardDataProvider()

    @router.get("/overview")
    def get_overview(tenant_id: str = Query("default", description="Tenant isolation ID")):
        try:
            return data_provider.get_current_security_status(tenant_id=tenant_id)
        except Exception as e:
            raise HTTPException(status_code=500, detail={"error": "Internal dashboard provider error", "code": "PROVIDER_ERROR"})

    @router.get("/controls")
    def get_controls(tenant_id: str = Query("default", description="Tenant isolation ID")):
        try:
            return data_provider.get_control_results(tenant_id=tenant_id)
        except Exception as e:
            raise HTTPException(status_code=500, detail={"error": "Internal dashboard provider error", "code": "PROVIDER_ERROR"})

    @router.get("/controls/{control_id}")
    def get_control_detail(
        control_id: str = Path(..., description="Target control ID (e.g. CONTROL-01)"),
        tenant_id: str = Query("default", description="Tenant isolation ID")
    ):
        try:
            return data_provider.get_control_detail(control_id=control_id, tenant_id=tenant_id)
        except ValueError as ve:
            raise HTTPException(status_code=404, detail={"error": str(ve), "code": "CONTROL_NOT_FOUND"})
        except Exception as e:
            raise HTTPException(status_code=500, detail={"error": "Internal dashboard provider error", "code": "PROVIDER_ERROR"})

    @router.get("/findings")
    def get_findings(
        tenant_id: str = Query("default", description="Tenant isolation ID"),
        severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
        control_id: Optional[str] = Query(None, description="Filter by control ID"),
        decision: Optional[str] = Query(None, description="Filter by decision (ALLOW, DENY, REVIEW, ISOLATE)")
    ):
        try:
            return data_provider.get_findings(tenant_id=tenant_id, severity=severity, control_id=control_id, decision=decision)
        except Exception as e:
            raise HTTPException(status_code=500, detail={"error": "Internal dashboard provider error", "code": "PROVIDER_ERROR"})

    @router.get("/benchmark")
    def get_benchmark():
        try:
            return data_provider.get_benchmark_summary()
        except Exception as e:
            raise HTTPException(status_code=500, detail={"error": "Internal dashboard provider error", "code": "PROVIDER_ERROR"})

    @router.get("/benchmark/categories")
    def get_benchmark_categories():
        try:
            return data_provider.get_benchmark_categories()
        except Exception as e:
            raise HTTPException(status_code=500, detail={"error": "Internal dashboard provider error", "code": "PROVIDER_ERROR"})

    @router.get("/tools")
    def get_tools(tenant_id: str = Query("default", description="Tenant isolation ID")):
        try:
            return data_provider.get_tool_governance_events(tenant_id=tenant_id)
        except Exception as e:
            raise HTTPException(status_code=500, detail={"error": "Internal dashboard provider error", "code": "PROVIDER_ERROR"})

    @router.get("/checkpoints")
    def get_checkpoints(tenant_id: str = Query("default", description="Tenant isolation ID")):
        try:
            return data_provider.get_checkpoint_events(tenant_id=tenant_id)
        except Exception as e:
            raise HTTPException(status_code=500, detail={"error": "Internal dashboard provider error", "code": "PROVIDER_ERROR"})

    @router.get("/audit")
    def get_audit(
        tenant_id: str = Query("default", description="Tenant isolation ID"),
        limit: int = Query(100, ge=1, le=1000, description="Max events to return"),
        offset: int = Query(0, ge=0, description="Pagination offset"),
        force_verify: bool = Query(False, description="Force full re-verification of hash chain")
    ):
        try:
            return data_provider.get_audit_summary(
                tenant_id=tenant_id,
                limit=limit,
                offset=offset,
                force_reverify=force_verify
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail={"error": "Internal dashboard provider error", "code": "PROVIDER_ERROR"})


    @router.get("/evaluations")
    def get_evaluations(tenant_id: str = Query("default", description="Tenant isolation ID")):
        try:
            return data_provider.get_evaluation_history(tenant_id=tenant_id)
        except Exception as e:
            raise HTTPException(status_code=500, detail={"error": "Internal dashboard provider error", "code": "PROVIDER_ERROR"})

    return router
