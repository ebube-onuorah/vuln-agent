"""
API Key authentication middleware.

Usage:
    Set API_KEY env var to require authentication on all endpoints.
    If API_KEY is not set, all requests pass (dev/open mode).

Clients send:
    Authorization: Bearer <key>
    — or —
    X-API-Key: <key>
"""

import os
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

_REQUIRED_KEY: str = os.getenv("API_KEY", "")

security = HTTPBearer(auto_error=False)


def _extract_key(request: Request) -> str | None:
    """Extract API key from Authorization header or X-API-Key header."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return request.headers.get("X-API-Key", "").strip() or None


async def require_api_key(request: Request) -> None:
    """
    FastAPI dependency. Validates API key when API_KEY env var is configured.
    No-op in open/dev mode (API_KEY not set).
    """
    if not _REQUIRED_KEY:
        return  # Auth disabled — dev/open mode

    key = _extract_key(request)
    if not key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Send 'Authorization: Bearer <key>' or 'X-API-Key: <key>'.",
        )
    if key != _REQUIRED_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key.")
