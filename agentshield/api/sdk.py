"""
AgentShield Python SDK Client for remote service integration.
"""

from typing import Dict, Any, Optional

try:
    import requests
except ImportError:
    requests = None

class AgentShieldClient:
    """Client SDK for interacting with a remote AgentShield server instance."""

    def __init__(self, endpoint_url: str = "http://localhost:8000"):
        self.endpoint_url = endpoint_url.rstrip("/")

    def inspect_prompt(self, prompt: str, tenant_id: str = "default") -> Dict[str, Any]:
        """Sends prompt to remote AgentShield service for security inspection."""
        if requests is None:
            raise ImportError("requests package is required for AgentShieldClient SDK.")

        url = f"{self.endpoint_url}/v1/shield/inspect"
        response = requests.post(url, json={"prompt": prompt, "tenant_id": tenant_id})
        
        if response.status_code != 200:
            raise RuntimeError(f"AgentShield API error ({response.status_code}): {response.text}")

        return response.json()
