"""
SentinelAgent Proxy - Main Application Entrypoint
Zero-Trust Runtime Security Proxy for Autonomous AI Agents and Non-Human Identities (NHI).
FastAPI application with HTTP/gRPC interception, WebSocket telemetry, and JIT IAM synthesis.
"""

import time
import json
from typing import Dict, Any, Optional
from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

try:
    from app.proxy.interceptor import interceptor
    from app.identity.spiffe import create_workload_identity_token, DEFAULT_SECRET_KEY
    from app.telemetry.logger import telemetry_hub
    from app.policy.synthesizer import synthesize_iam_policy
except ImportError:
    from proxy.interceptor import interceptor
    from identity.spiffe import create_workload_identity_token, DEFAULT_SECRET_KEY
    from telemetry.logger import telemetry_hub
    from policy.synthesizer import synthesize_iam_policy

app = FastAPI(
    title="SentinelAgent Proxy",
    description="Zero-Trust Runtime Security Proxy for Autonomous AI Agents & Non-Human Identities",
    version="1.0.0"
)

# Cross-Origin Resource Sharing for the React Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[
        "X-Sentinel-Status",
        "X-Sentinel-Audit-Id",
        "X-Sentinel-Latency-Ms",
        "X-Sentinel-Policy-Sha256",
        "X-Sentinel-Agent-Id",
        "X-Sentinel-SPIFFE-ID"
    ]
)


class MintTokenRequest(BaseModel):
    agent_id: str = "agent-fin-analyst-01"
    namespace: str = "finance-workloads"
    ttl_seconds: int = Field(default=30, ge=1, le=300)
    process_hash: Optional[str] = None


class ToolCallRequest(BaseModel):
    action: str
    bucket: Optional[str] = None
    key: Optional[str] = None
    table: Optional[str] = None
    queue: Optional[str] = None
    extra_params: Optional[Dict[str, Any]] = None


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "SentinelAgent Proxy",
        "version": "1.0.0",
        "mode": "Zero-Trust Enforcement",
        "sla_target": "< 15ms overhead",
        "time": time.time()
    }


@app.post("/proxy/v1/tool")
async def proxy_tool_call(request: Request):
    """
    Primary tool-call reverse proxy gateway.
    Catches HTTP requests from AI Agents executing cloud actions or MCP tools.
    Enforces WIT token attestation, payload sanitization, and JIT IAM policy synthesis.
    """
    token_header = request.headers.get("X-Sentinel-Agent-Token") or request.headers.get("Authorization")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed JSON in tool call request body."
        )

    target_endpoint = request.headers.get("X-Sentinel-Target", "https://s3.amazonaws.com")
    res_body, status_code, res_headers = await interceptor.process_tool_request(
        request_body=body,
        token_header=token_header,
        target_endpoint=target_endpoint
    )

    return JSONResponse(content=res_body, status_code=status_code, headers=res_headers)


@app.post("/proxy/aws/{service}")
async def proxy_aws_service(service: str, request: Request):
    """
    AWS Endpoints reverse proxy (e.g. s3.amazonaws.com, dynamodb.us-east-1.amazonaws.com).
    Intercepts REST/JSON calls to AWS services, synthesizes ephemeral role, and forwards.
    """
    token_header = request.headers.get("X-Sentinel-Agent-Token")
    try:
        body = await request.json()
    except Exception:
        body = {"action": f"{service}_generic_request"}

    res_body, status_code, res_headers = await interceptor.process_tool_request(
        request_body=body,
        token_header=token_header,
        target_endpoint=f"https://{service}.amazonaws.com"
    )

    return JSONResponse(content=res_body, status_code=status_code, headers=res_headers)


@app.post("/api/token/mint")
async def mint_agent_token(req: MintTokenRequest):
    """
    Generates a cryptographically signed Workload Identity Token (WIT) for an agent.
    Enforces standard 30-second TTL.
    """
    token = create_workload_identity_token(
        agent_id=req.agent_id,
        namespace=req.namespace,
        process_hash=req.process_hash,
        ttl_seconds=req.ttl_seconds
    )
    return {
        "agent_id": req.agent_id,
        "token": token,
        "ttl_seconds": min(req.ttl_seconds, 30),
        "header_format": f"X-Sentinel-Agent-Token: {token}",
        "expires_in_seconds": min(req.ttl_seconds, 30)
    }


@app.get("/api/telemetry/metrics")
async def get_telemetry_metrics():
    """Returns aggregated proxy latency and security metrics."""
    return telemetry_hub.get_summary_metrics()


@app.get("/api/telemetry/events")
async def get_telemetry_events(limit: int = 50):
    """Returns recent telemetry events from memory ring buffer."""
    return telemetry_hub.get_recent_events(limit=limit)


@app.post("/api/policy/preview")
async def preview_policy(tool_call: Dict[str, Any]):
    """Previews the dynamically synthesized AWS IAM Policy for a given tool call."""
    try:
        policy_doc, policy_json, policy_sha256 = synthesize_iam_policy(tool_call, validity_seconds=30)
        return {
            "status": "VALID",
            "policy_doc": policy_doc,
            "policy_json": policy_json,
            "policy_sha256": policy_sha256
        }
    except Exception as err:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"status": "REJECTED", "error": str(err)}
        )


@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    """
    Real-time WebSocket event stream for dashboard UI telemetry.
    Streams latency measurements, attestation events, and threat alerts live.
    """
    await telemetry_hub.connect(websocket)
    try:
        while True:
            # Keep-alive ping/pong receiver
            data = await websocket.receive_text()
            # Optional client ping handler
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "PONG", "timestamp": time.time()}))
    except WebSocketDisconnect:
        telemetry_hub.disconnect(websocket)
    except Exception:
        telemetry_hub.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
