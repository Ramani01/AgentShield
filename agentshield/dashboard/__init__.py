"""
AgentShield Security Dashboard & Observability Package.
"""

from agentshield.dashboard.provider import DashboardDataProvider
from agentshield.dashboard.router import create_dashboard_router
from agentshield.dashboard.ui import get_dashboard_html
from agentshield.dashboard.app import create_dashboard_app, app

__all__ = [
    "DashboardDataProvider",
    "create_dashboard_router",
    "get_dashboard_html",
    "create_dashboard_app",
    "app",
]
