"""
SentinelAgent Proxy - Core Asynchronous Interception Engine
Reverse proxy middleware catching tool calls, AWS service calls, and LLM requests.
Orchestrates:
1. High-precision latency clocking (< 15ms SLA target)
2. Cryptographic WIT identity attestation
3. Deep payload sanitization & prompt injection defense
4. Dynamic JIT task-scoped IAM policy synthesis
5. Temporary AWS STS credential assumption
6. Telemetry emission via WebSocket stream
"""

import time
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

try:
    from fastapi import Request, Response, HTTPException, status
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
    Response = Any

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    class httpx:
        class AsyncClient:
            def __init__(self, *args, **kwargs):
                pass
            async def aclose(self):
                pass

try:
    from app.identity.attestation import extract_and_validate_token, AttestationError, AgentIdentity
    from app.proxy.sanitizer import sanitize_and_inspect_payload, SanitizerResult
    from app.policy.synthesizer import synthesize_iam_policy, PolicySynthesisError
    from app.policy.aws_sts import assume_task_scoped_role, TemporaryCredentials
    from app.telemetry.logger import telemetry_hub, TelemetryEvent
except ImportError:
    from identity.attestation import extract_and_validate_token, AttestationError, AgentIdentity
    from proxy.sanitizer import sanitize_and_inspect_payload, SanitizerResult
    from policy.synthesizer import synthesize_iam_policy, PolicySynthesisError
    from policy.aws_sts import assume_task_scoped_role, TemporaryCredentials
    from telemetry.logger import telemetry_hub, TelemetryEvent


class SentinelInterceptor:
    """Asynchronous reverse proxy processing engine."""

    def __init__(self, upstream_client: Optional[httpx.AsyncClient] = None):
        self._http_client = upstream_client or httpx.AsyncClient(timeout=10.0)

    async def close(self):
        await self._http_client.aclose()

    async def process_tool_request(
        self,
        request_body: Dict[str, Any],
        token_header: Optional[str],
        target_endpoint: str = "https://s3.amazonaws.com"
    ) -> Tuple[Dict[str, Any], int, Dict[str, str]]:
        """
        Executes the full Zero-Trust security pipeline on an intercepted tool call.
        Returns:
            (response_body, http_status_code, response_headers)
        """
        start_ns = time.perf_counter_ns()
        event_id = f"sentinel-{uuid.uuid4().hex[:10]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        action_name = str(request_body.get("action") or request_body.get("tool") or "unknown_action")
        target_desc = str(request_body.get("bucket") or request_body.get("table") or target_endpoint)

        # -------------------------------------------------------------
        # STEP 1: Cryptographic Identity Attestation (WIT / JWT)
        # -------------------------------------------------------------
        if not token_header:
            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            event = TelemetryEvent(
                id=event_id,
                timestamp=time.time(),
                iso_time=now_iso,
                event_type="ATTESTATION_FAILED",
                agent_id="UNAUTHENTICATED_NHI",
                target=target_desc,
                action=action_name,
                status="BLOCKED",
                latency_ms=round(elapsed_ms, 3),
                risk_score=90,
                threat_details="Missing mandatory X-Sentinel-Agent-Token header. Zero-Trust access denied.",
                mitre_technique="AML.T0053",
            )
            await telemetry_hub.emit_event(event)
            return (
                {
                    "error": "ACCESS_DENIED_UNATTESTED_NHI",
                    "message": "Missing 'X-Sentinel-Agent-Token'. All agent tool calls must carry signed WIT credentials.",
                    "audit_id": event_id,
                    "proxy_overhead_ms": round(elapsed_ms, 3),
                },
                status.HTTP_403_FORBIDDEN,
                {"X-Sentinel-Status": "BLOCKED_ATTESTATION", "X-Sentinel-Audit-Id": event_id},
            )

        try:
            agent_identity: AgentIdentity = extract_and_validate_token(token_header)
        except AttestationError as err:
            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            event = TelemetryEvent(
                id=event_id,
                timestamp=time.time(),
                iso_time=now_iso,
                event_type="ATTESTATION_FAILED",
                agent_id="UNTRUSTED_AGENT",
                target=target_desc,
                action=action_name,
                status="BLOCKED",
                latency_ms=round(elapsed_ms, 3),
                risk_score=95,
                threat_details=str(err.detail.get("message") if isinstance(err.detail, dict) else err.detail),
                mitre_technique="AML.T0053",
            )
            await telemetry_hub.emit_event(event)
            return (
                {
                    "error": "ATTESTATION_VALIDATION_FAILED",
                    "detail": err.detail,
                    "audit_id": event_id,
                    "proxy_overhead_ms": round(elapsed_ms, 3),
                },
                status.HTTP_403_FORBIDDEN,
                {"X-Sentinel-Status": "BLOCKED_INVALID_TOKEN", "X-Sentinel-Audit-Id": event_id},
            )

        # -------------------------------------------------------------
        # STEP 2: Runtime Action Sanitizer & Prompt Injection Analysis
        # -------------------------------------------------------------
        sanitizer_res: SanitizerResult = sanitize_and_inspect_payload(request_body)

        if sanitizer_res.is_blocked:
            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            event = TelemetryEvent(
                id=event_id,
                timestamp=time.time(),
                iso_time=now_iso,
                event_type="SANITIZER_BLOCKED",
                agent_id=agent_identity.agent_id,
                target=target_desc,
                action=action_name,
                status="BLOCKED",
                latency_ms=round(elapsed_ms, 3),
                risk_score=sanitizer_res.risk_score,
                threat_details=sanitizer_res.threat_details,
                mitre_technique=sanitizer_res.mitre_atlas_technique,
                details={"flagged_patterns": sanitizer_res.flagged_patterns},
            )
            await telemetry_hub.emit_event(event)
            return (
                {
                    "error": "SENTINEL_SANITIZER_POLICY_VIOLATION",
                    "reason": sanitizer_res.threat_details,
                    "mitre_atlas": sanitizer_res.mitre_atlas_technique,
                    "risk_score": sanitizer_res.risk_score,
                    "audit_id": event_id,
                    "proxy_overhead_ms": round(elapsed_ms, 3),
                },
                status.HTTP_403_FORBIDDEN,
                {
                    "X-Sentinel-Status": "BLOCKED_SANITIZER",
                    "X-Sentinel-Audit-Id": event_id,
                    "X-Sentinel-Threat": sanitizer_res.threat_details[:100],
                },
            )

        effective_payload = sanitizer_res.sanitized_payload or request_body

        # -------------------------------------------------------------
        # STEP 3: Dynamic JIT IAM Policy Synthesis
        # -------------------------------------------------------------
        try:
            policy_doc, policy_json, policy_sha256 = synthesize_iam_policy(
                effective_payload,
                agent_id=agent_identity.agent_id,
                validity_seconds=30
            )
        except PolicySynthesisError as p_err:
            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            event = TelemetryEvent(
                id=event_id,
                timestamp=time.time(),
                iso_time=now_iso,
                event_type="POLICY_SYNTHESIS_FAILED",
                agent_id=agent_identity.agent_id,
                target=target_desc,
                action=action_name,
                status="BLOCKED",
                latency_ms=round(elapsed_ms, 3),
                risk_score=70,
                threat_details=f"Policy synthesis rejection: {str(p_err)}",
                mitre_technique="AML.T0053",
            )
            await telemetry_hub.emit_event(event)
            return (
                {
                    "error": "POLICY_SYNTHESIS_REJECTED",
                    "reason": str(p_err),
                    "audit_id": event_id,
                    "proxy_overhead_ms": round(elapsed_ms, 3),
                },
                status.HTTP_400_BAD_REQUEST,
                {"X-Sentinel-Status": "BLOCKED_SYNTHESIS", "X-Sentinel-Audit-Id": event_id},
            )

        # -------------------------------------------------------------
        # STEP 4: Ephemeral AWS STS Role Assumption
        # -------------------------------------------------------------
        sts_creds: TemporaryCredentials = assume_task_scoped_role(
            policy_json=policy_json,
            agent_id=agent_identity.agent_id,
            duration_seconds=30
        )

        # -------------------------------------------------------------
        # STEP 5: Authorized Downstream Execution / Simulation
        # -------------------------------------------------------------
        # In this prototype, we simulate the downstream S3 / cloud operation executing
        # with the newly acquired ephemeral credentials
        simulated_result = {
            "status": "SUCCESS_AUTHORIZED",
            "operation": action_name,
            "target": target_desc,
            "agent_identity": {
                "agent_id": agent_identity.agent_id,
                "spiffe_id": agent_identity.spiffe_id,
                "token_age_seconds": round(time.time() - agent_identity.creation_timestamp, 2)
            },
            "task_scoped_credentials": {
                "access_key_id": sts_creds.access_key_id,
                "expiration": sts_creds.expiration,
                "assumed_role_arn": sts_creds.assumed_role_arn,
                "temporal_scope": "30 seconds"
            },
            "authorized_data": {
                "object": f"{target_desc}/{request_body.get('key', 'default.dat')}",
                "content_preview": "Q3 Financial Summary: Operating Margin +24.8%, ARR $48.2M, Clean Audit Opinion.",
                "checksum_sha256": "8f4e2...d7a1"
            }
        }

        # Calculate high-resolution latency overhead
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

        # Emit completion telemetry
        event = TelemetryEvent(
            id=event_id,
            timestamp=time.time(),
            iso_time=now_iso,
            event_type="COMPLETED",
            agent_id=agent_identity.agent_id,
            target=target_desc,
            action=action_name,
            status="PASS",
            latency_ms=round(elapsed_ms, 3),
            risk_score=0,
            threat_details="Attested, Sanitized, and Ephemeral Role Assumed (< 15ms target).",
            policy_doc=policy_doc,
            policy_sha256=policy_sha256,
            sts_session_id=sts_creds.access_key_id[:12],
            details={"policy_summary": f"Grant {action_name} on {target_desc} for 30s"}
        )
        await telemetry_hub.emit_event(event)

        response_headers = {
            "X-Sentinel-Status": "AUTHORIZED_PASS",
            "X-Sentinel-Audit-Id": event_id,
            "X-Sentinel-Latency-Ms": str(round(elapsed_ms, 3)),
            "X-Sentinel-Policy-Sha256": policy_sha256,
            "X-Sentinel-Agent-Id": agent_identity.agent_id,
            "X-Sentinel-SPIFFE-ID": agent_identity.spiffe_id,
        }

        return simulated_result, status.HTTP_200_OK, response_headers


# Global instance
interceptor = SentinelInterceptor()
