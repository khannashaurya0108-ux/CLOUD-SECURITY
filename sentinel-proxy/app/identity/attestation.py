"""
SentinelAgent Proxy - Identity Attestation Gateway
Inspects incoming request headers for cryptographically signed `X-Sentinel-Agent-Token`.
Enforces signature verification, process integrity hash, and a strict <= 30s token lifespan.
"""

import time
from typing import Optional, Dict, Any
from dataclasses import dataclass

try:
    from fastapi import Request, HTTPException, status
except ImportError:
    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: Any):
            self.status_code = status_code
            self.detail = detail
            super().__init__(str(detail))
    class status:
        HTTP_403_FORBIDDEN = 403
        HTTP_400_BAD_REQUEST = 400
        HTTP_200_OK = 200
    Request = Any

try:
    import jwt
    HAS_PYJWT = True
except ImportError:
    HAS_PYJWT = False

try:
    from app.identity.spiffe import (
        DEFAULT_SECRET_KEY,
        ALGORITHM,
        DEFAULT_AUDIENCE,
        DEFAULT_ISSUER,
        MAX_TOKEN_LIFESPAN_SECONDS,
        decode_workload_identity_token,
    )
except ImportError:
    from identity.spiffe import (
        DEFAULT_SECRET_KEY,
        ALGORITHM,
        DEFAULT_AUDIENCE,
        DEFAULT_ISSUER,
        MAX_TOKEN_LIFESPAN_SECONDS,
        decode_workload_identity_token,
    )


@dataclass
class AgentIdentity:
    """Attested agent identity object passed down through the proxy pipeline."""
    agent_id: str
    spiffe_id: str
    process_hash: str
    creation_timestamp: int
    expires_at: int
    jti: str
    capabilities: list
    raw_token: str


class AttestationError(HTTPException):
    """Specific HTTP 403 Forbidden exception for failed identity attestation."""
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "ATTESTATION_FAILED",
                "message": detail,
                "header_required": "X-Sentinel-Agent-Token",
                "spec": "SPIFFE/WIMSE WIT (max 30s TTL)",
            },
        )


def extract_and_validate_token(
    token_str: str,
    secret_key: str = DEFAULT_SECRET_KEY,
) -> AgentIdentity:
    """
    Decodes and cryptographically attests the Workload Identity Token (WIT).
    Enforces:
    1. Signature validity (HMAC-SHA256 with known trust domain)
    2. JWT integrity & algorithm enforcement
    3. Maximum lifespan <= 30 seconds
    4. Current time <= exp
    5. Presence of required claims: agent_id, process_hash, creation_timestamp
    """
    if not token_str:
        raise AttestationError("Empty or missing 'X-Sentinel-Agent-Token' header.")

    # Remove optional 'Bearer ' prefix if present
    if token_str.startswith("Bearer "):
        token_str = token_str[len("Bearer "):].strip()

    try:
        # Decode and verify signature
        payload = decode_workload_identity_token(token_str, secret_key=secret_key, verify_exp=True)
    except Exception as err:
        msg = str(err)
        if "expired" in msg.lower():
            raise AttestationError("Token signature has expired. Maximum allowed lifespan is 30 seconds.")
        elif "signature" in msg.lower() or "invalid" in msg.lower():
            raise AttestationError("Cryptographic signature validation failed. Untrusted key or tampered payload.")
        else:
            raise AttestationError(f"Malformed or corrupt JWT: {msg}")

    # Extract required zero-trust claims
    agent_id = payload.get("agent_id")
    process_hash = payload.get("process_hash")
    creation_timestamp = payload.get("creation_timestamp") or payload.get("iat")
    expires_at = payload.get("exp", 0)

    if not agent_id:
        raise AttestationError("Missing required 'agent_id' claim in WIT payload.")
    if not process_hash:
        raise AttestationError("Missing required 'process_hash' claim in WIT payload.")
    if not creation_timestamp:
        raise AttestationError("Missing required 'creation_timestamp' claim in WIT payload.")

    now = time.time()
    token_age = now - creation_timestamp

    # Strict Zero-Trust lifespan audit: token must not be older than MAX_TOKEN_LIFESPAN_SECONDS
    if token_age > MAX_TOKEN_LIFESPAN_SECONDS:
        raise AttestationError(
            f"Token age ({token_age:.2f}s) exceeds maximum allowed lifespan ({MAX_TOKEN_LIFESPAN_SECONDS}s)."
        )

    # Future timestamp check (drift tolerance: 5 seconds)
    if creation_timestamp > now + 5:
        raise AttestationError("Token creation timestamp is in the future. Clock skew detected.")

    return AgentIdentity(
        agent_id=agent_id,
        spiffe_id=payload.get("sub", f"spiffe://sentinel.internal/sa/{agent_id}"),
        process_hash=process_hash,
        creation_timestamp=int(creation_timestamp),
        expires_at=int(expires_at),
        jti=payload.get("jti", ""),
        capabilities=payload.get("capabilities", []),
        raw_token=token_str,
    )


async def attest_agent_request(request: Request) -> AgentIdentity:
    """
    FastAPI dependency / middleware helper to inspect and attest incoming requests.
    Inspects header `X-Sentinel-Agent-Token`.
    """
    token = request.headers.get("X-Sentinel-Agent-Token")
    if not token:
        # Check fallback authorization header if present
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Sentinel-WIT ") or auth_hdr.startswith("Bearer "):
            token = auth_hdr.split(" ", 1)[1]

    if not token:
        raise AttestationError(
            "Access denied: Missing mandatory 'X-Sentinel-Agent-Token' header. "
            "Non-Human Identity (NHI) unauthenticated."
        )

    return extract_and_validate_token(token)
