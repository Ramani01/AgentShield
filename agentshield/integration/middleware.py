"""
FastAPI / ASGI Security Middleware for AgentShield.
"""

import json
from typing import Callable, Any, Dict, Optional, List
from agentshield.integration.models import (
    ShieldDecision,
    ShieldIdentity,
    ShieldRequest,
    ShieldResponse
)
from agentshield.integration.adapter import AgentShieldAdapter
from agentshield.context.models import TrustLevel


class AgentShieldMiddleware:
    """
    ASGI Middleware integrating AgentShield security controls into FastAPI/Starlette
    HTTP applications.
    """

    def __init__(
        self,
        app: Any,
        adapter: Optional[AgentShieldAdapter] = None,
        tenant_header: str = "x-tenant-id",
        user_header: str = "x-user-id",
        role_header: str = "x-user-role",
        enforce_identity: bool = True,
        exclude_paths: Optional[List[str]] = None
    ):
        self.app = app
        self.adapter = adapter or AgentShieldAdapter()
        self.tenant_header = tenant_header.lower()
        self.user_header = user_header.lower()
        self.role_header = role_header.lower()
        self.enforce_identity = enforce_identity
        self.exclude_paths = exclude_paths or [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/health",
            "/api/dashboard"
        ]

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        # Check path exclusions
        if any(path.startswith(ex) for ex in self.exclude_paths):
            await self.app(scope, receive, send)
            return

        # Extract headers into dict
        headers = dict(scope.get("headers", []))
        headers_decoded = {k.decode("latin1").lower(): v.decode("latin1") for k, v in headers.items()}

        tenant_id = headers_decoded.get(self.tenant_header)
        user_id = headers_decoded.get(self.user_header, "anonymous")
        roles_raw = headers_decoded.get(self.role_header, "")
        roles = [r.strip() for r in roles_raw.split(",") if r.strip()]

        # Fail-closed check if identity or tenant header is missing when enforcement is enabled
        if self.enforce_identity or self.adapter.config.strict_policy_mode:
            if not tenant_id:
                response_body = json.dumps({
                    "decision": ShieldDecision.DENY.value,
                    "allowed": False,
                    "reason": f"Fail-closed: Missing required security header '{self.tenant_header}'",
                    "violations": ["MISSING_SECURITY_HEADER"]
                }).encode("utf-8")

                await send({
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(response_body)).encode("utf-8"))
                    ]
                })
                await send({
                    "type": "http.response.body",
                    "body": response_body
                })
                return

        identity = ShieldIdentity(
            user_id=user_id,
            tenant_id=tenant_id or "default",
            roles=roles,
            trust_level=TrustLevel.TRUSTED if "admin" in roles else TrustLevel.UNTRUSTED
        )

        # Store security identity in scope state for FastAPI context access
        if "state" not in scope:
            scope["state"] = {}
        scope["state"]["security_identity"] = identity

        # If HTTP method is POST or PUT, inspect body if possible
        method = scope.get("method", "GET").upper()
        if method in ("POST", "PUT"):
            body_bytes = b""
            more_body = True

            async def custom_receive():
                nonlocal body_bytes, more_body
                message = await receive()
                if message["type"] == "http.request":
                    body_bytes += message.get("body", b"")
                    more_body = message.get("more_body", False)
                return message

            # Consume request body once
            message = await receive()
            if message["type"] == "http.request":
                body_bytes += message.get("body", b"")
                more_body = message.get("more_body", False)

                if body_bytes:
                    try:
                        payload = json.loads(body_bytes.decode("utf-8"))
                        prompt = payload.get("prompt") or payload.get("content")
                        if prompt and isinstance(prompt, str):
                            req = ShieldRequest(
                                prompt=prompt,
                                identity=identity,
                                context_items=payload.get("context_items", [])
                            )
                            sh_res = self.adapter.process_request(req)
                            if not sh_res.allowed:
                                err_body = json.dumps(sh_res.model_dump()).encode("utf-8")
                                await send({
                                    "type": "http.response.start",
                                    "status": 400,
                                    "headers": [
                                        (b"content-type", b"application/json"),
                                        (b"content-length", str(len(err_body)).encode("utf-8"))
                                    ]
                                })
                                await send({
                                    "type": "http.response.body",
                                    "body": err_body
                                })
                                return
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass

            # Provide replay receive callable for downstream app
            consumed = False
            async def replay_receive():
                nonlocal consumed
                if not consumed:
                    consumed = True
                    return {
                        "type": "http.request",
                        "body": body_bytes,
                        "more_body": False
                    }
                return await receive()

            # Intercept output response to filter secrets/PII
            async def send_with_output_inspection(message: Dict[str, Any]) -> None:
                if message["type"] == "http.response.body" and message.get("body"):
                    try:
                        raw_str = message["body"].decode("utf-8")
                        clean_str = self.adapter.pipeline.inspect_output(raw_str, tenant_id=identity.tenant_id)
                        message["body"] = clean_str.encode("utf-8")
                    except Exception:
                        pass
                await send(message)

            await self.app(scope, replay_receive, send_with_output_inspection)
            return

        # Response interceptor for non-POST requests
        async def send_with_output_inspection(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.body" and message.get("body"):
                try:
                    raw_str = message["body"].decode("utf-8")
                    clean_str = self.adapter.pipeline.inspect_output(raw_str, tenant_id=identity.tenant_id)
                    message["body"] = clean_str.encode("utf-8")
                except Exception:
                    pass
            await send(message)

        await self.app(scope, receive, send_with_output_inspection)
