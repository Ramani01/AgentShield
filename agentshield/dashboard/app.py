"""
Standalone Dashboard FastAPI Application Entry Point.

Runs local security observability dashboard on 127.0.0.1:8000.
Serves read-only REST API endpoints and static HTML/CSS/JS dashboard UI.
"""

from typing import Optional

try:
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse
except ImportError:
    FastAPI = None
    HTMLResponse = None

from agentshield.core.config import ShieldConfig
from agentshield.core.pipeline import SecurityPipeline
from agentshield.dashboard.provider import DashboardDataProvider
from agentshield.dashboard.router import create_dashboard_router
from agentshield.dashboard.ui import get_dashboard_html

def create_dashboard_app(
    pipeline: Optional[SecurityPipeline] = None,
    config: Optional[ShieldConfig] = None
) -> FastAPI:
    """Creates standalone FastAPI application instance for AgentShield Security Dashboard."""
    if FastAPI is None:
        raise ImportError("FastAPI is required for running AgentShield Security Dashboard.")

    pipe = pipeline or SecurityPipeline(config=config or ShieldConfig())
    provider = DashboardDataProvider(pipeline=pipe)
    router = create_dashboard_router(provider=provider)

    app = FastAPI(
        title="AgentShield Security Dashboard",
        version="1.0.0",
        description="Local Read-Only Security Observability Dashboard for AgentShield"
    )

    app.include_router(router)

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
    def render_dashboard():
        """Serves static read-only dashboard single-page HTML interface."""
        return HTMLResponse(content=get_dashboard_html())

    return app

# Singleton app instance for uvicorn execution
app = create_dashboard_app()
