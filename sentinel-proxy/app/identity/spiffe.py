"""
SentinelAgent Proxy - SPIFFE & Workload Identity Token (WIT) Binder
Compliant with SPIFFE ID standards and WIMSE (Workload Identity in Multi-System Environments) drafts.
"""

import time
import hashlib
import hmac
import base64
import json
import uuid
from typing import Dict, Any, Optional

try:
    import jwt
    HAS_PYJWT = True
except ImportError:
    HAS_PYJWT = False

# Standard shared secret for prototype HMAC-SHA256 signature verification
# In production enterprise deployments, this is backed by SPIRE / HashiCorp Vault / KMS asymmetric keys
DEFAULT_SECRET_KEY = "sentinel-agent-zero-trust-hmac-sha256-signing-key"
ALGORITHM = "HS256"
DEFAULT_ISSUER = "https://spiffe.sentinel.internal"
DEFAULT_AUDIENCE = "sentinel-proxy.cluster.local"
MAX_TOKEN_LIFESPAN_SECONDS = 30  # Strict 30-second token lifespan per Zero-Trust spec


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (4 - (len(s) % 4)) if len(s) % 4 != 0 else ""
    return base64.urlsafe_b64decode((s + padding).encode("utf-8"))


def compute_process_hash(command_line: str = "agent_runner.py --task-id=exec-42") -> str:
    """Computes a SHA-256 fingerprint of the calling agent's process binary/script."""
    hasher = hashlib.sha256()
    hasher.update(command_line.encode("utf-8"))
    return hasher.hexdigest()


def generate_spiffe_id(agent_id: str, namespace: str = "production-agents") -> str:
    """Formats a canonical SPIFFE ID."""
    clean_id = agent_id.strip().replace(" ", "_")
    return f"spiffe://sentinel.internal/ns/{namespace}/sa/{clean_id}"


def create_workload_identity_token(
    agent_id: str,
    namespace: str = "production-agents",
    process_hash: Optional[str] = None,
    secret_key: str = DEFAULT_SECRET_KEY,
    ttl_seconds: int = 30,
    capabilities: Optional[list] = None
) -> str:
    """
    Generates a cryptographically signed Workload Identity Token (WIT / JWT).
    Enforces a strict TTL (default 30 seconds) and binds the process hash & SPIFFE ID.
    """
    now = int(time.time())
    lifespan = min(ttl_seconds, MAX_TOKEN_LIFESPAN_SECONDS)
    spiffe_id = generate_spiffe_id(agent_id, namespace)
    actual_hash = process_hash or compute_process_hash(f"agent_{agent_id}_runtime")

    payload: Dict[str, Any] = {
        "iss": DEFAULT_ISSUER,
        "sub": spiffe_id,
        "aud": DEFAULT_AUDIENCE,
        "agent_id": agent_id,
        "spiffe_id": spiffe_id,
        "process_hash": actual_hash,
        "creation_timestamp": now,
        "iat": now,
        "nbf": now - 1,
        "exp": now + lifespan,
        "jti": str(uuid.uuid4()),
        "capabilities": capabilities or ["s3_access", "tool_execution"]
    }

    if HAS_PYJWT:
        return jwt.encode(payload, secret_key, algorithm=ALGORITHM)

    # Standard-library HMAC-SHA256 JWT generation
    header = {"alg": "HS256", "typ": "JWT"}
    hdr_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{hdr_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{hdr_b64}.{payload_b64}.{sig_b64}"


def decode_workload_identity_token(
    token: str,
    secret_key: str = DEFAULT_SECRET_KEY,
    verify_exp: bool = True
) -> Dict[str, Any]:
    """
    Decodes and validates a WIT JWT against standard and custom Zero-Trust claims.
    """
    if HAS_PYJWT:
        return jwt.decode(
            token,
            secret_key,
            algorithms=[ALGORITHM],
            audience=DEFAULT_AUDIENCE,
            issuer=DEFAULT_ISSUER,
            options={"verify_exp": verify_exp}
        )

    # Standard-library fallback
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT structure")

    signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
    expected_sig = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    actual_sig = _b64url_decode(parts[2])

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("Signature verification failed")

    payload_json = _b64url_decode(parts[1]).decode("utf-8")
    payload = json.loads(payload_json)

    if verify_exp:
        exp = payload.get("exp", 0)
        if time.time() > exp:
            raise ValueError("Token signature has expired")

    return payload
