"""
SentinelAgent Proxy - Telemetry Logger & Real-Time Event Stream
Manages WebSocket broadcasting, metrics aggregation, and security audit log rings.
"""

import time
import json
import asyncio
from typing import Dict, Any, List, Set, Optional
from dataclasses import dataclass, asdict

try:
    from fastapi import WebSocket
except ImportError:
    class WebSocket:
        pass


@dataclass
class TelemetryEvent:
    id: str
    timestamp: float
    iso_time: str
    event_type: str  # "INTERCEPTED", "ATTESTED", "SANITIZED", "POLICY_GENERATED", "STS_ASSUMED", "BLOCKED", "COMPLETED"
    agent_id: str
    target: str
    action: str
    status: str  # "PASS", "BLOCKED", "WARNING", "ERROR"
    latency_ms: float
    risk_score: int
    threat_details: Optional[str] = None
    mitre_technique: Optional[str] = None
    policy_doc: Optional[Dict[str, Any]] = None
    policy_sha256: Optional[str] = None
    sts_session_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TelemetryHub:
    """Singleton hub managing WebSocket connections and metrics."""
    def __init__(self, max_history: int = 150):
        self._active_websockets: Set[WebSocket] = set()
        self._event_history: List[TelemetryEvent] = []
        self._max_history = max_history
        self._latencies: List[float] = []
        self._total_requests = 0
        self._blocked_requests = 0

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self._active_websockets.add(websocket)
        # Send initial snapshot of metrics and recent events
        snapshot = {
            "type": "INITIAL_SNAPSHOT",
            "metrics": self.get_summary_metrics(),
            "recent_events": [e.to_dict() for e in self._event_history[-30:]]
        }
        await websocket.send_text(json.dumps(snapshot))

    def disconnect(self, websocket: WebSocket):
        self._active_websockets.discard(websocket)

    async def emit_event(self, event: TelemetryEvent):
        """Records an event and broadcasts it to all active WebSocket clients."""
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history.pop(0)

        self._total_requests += 1
        if event.status == "BLOCKED":
            self._blocked_requests += 1

        if event.latency_ms > 0:
            self._latencies.append(event.latency_ms)
            if len(self._latencies) > 500:
                self._latencies.pop(0)

        payload_str = json.dumps({
            "type": "TELEMETRY_EVENT",
            "event": event.to_dict(),
            "metrics": self.get_summary_metrics()
        })

        # Broadcast to all connected clients
        stale = set()
        for ws in self._active_websockets:
            try:
                await ws.send_text(payload_str)
            except Exception:
                stale.add(ws)

        for ws in stale:
            self._active_websockets.discard(ws)

    def get_summary_metrics(self) -> Dict[str, Any]:
        count = len(self._latencies)
        if count > 0:
            avg_lat = sum(self._latencies) / count
            sorted_lat = sorted(self._latencies)
            p50 = sorted_lat[int(count * 0.50)]
            p95 = sorted_lat[min(count - 1, int(count * 0.95))]
            p99 = sorted_lat[min(count - 1, int(count * 0.99))]
            max_lat = sorted_lat[-1]
            min_lat = sorted_lat[0]
        else:
            avg_lat = p50 = p95 = p99 = max_lat = min_lat = 0.0

        block_rate = (self._blocked_requests / self._total_requests * 100.0) if self._total_requests > 0 else 0.0

        return {
            "total_requests": self._total_requests,
            "blocked_requests": self._blocked_requests,
            "pass_requests": self._total_requests - self._blocked_requests,
            "block_rate_percent": round(block_rate, 2),
            "avg_latency_ms": round(avg_lat, 2),
            "p50_latency_ms": round(p50, 2),
            "p95_latency_ms": round(p95, 2),
            "p99_latency_ms": round(p99, 2),
            "min_latency_ms": round(min_lat, 2),
            "max_latency_ms": round(max_lat, 2),
            "target_sla_ms": 15.0,
            "sla_met": avg_lat <= 15.0 if count > 0 else True,
            "active_ws_clients": len(self._active_websockets)
        }

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._event_history[-limit:]]


# Global singleton instance
telemetry_hub = TelemetryHub()
