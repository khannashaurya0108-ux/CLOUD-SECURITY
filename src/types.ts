export interface TelemetryEventData {
  id: string;
  timestamp: number;
  iso_time: string;
  event_type:
    | 'INTERCEPTED'
    | 'ATTESTED'
    | 'ATTESTATION_FAILED'
    | 'SANITIZED'
    | 'SANITIZER_BLOCKED'
    | 'POLICY_GENERATED'
    | 'POLICY_SYNTHESIS_FAILED'
    | 'STS_ASSUMED'
    | 'BLOCKED'
    | 'COMPLETED'
    | string;
  agent_id: string;
  target: string;
  action: string;
  status: 'PASS' | 'BLOCKED' | 'WARNING' | 'ERROR';
  latency_ms: number;
  risk_score: number;
  threat_details?: string;
  mitre_technique?: string;
  policy_doc?: Record<string, any>;
  policy_sha256?: string;
  sts_session_id?: string;
  details?: Record<string, any>;
}

export interface SummaryMetrics {
  total_requests: number;
  blocked_requests: number;
  pass_requests: number;
  block_rate_percent: number;
  avg_latency_ms: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  min_latency_ms: number;
  max_latency_ms: number;
  target_sla_ms: number;
  sla_met: boolean;
  active_ws_clients?: number;
}

export interface SimulationPayload {
  name: string;
  agent_id: string;
  action: string;
  bucket?: string;
  key?: string;
  table?: string;
  key_id?: string;
  instruction?: string;
  has_valid_token: boolean;
  token_expired?: boolean;
  description: string;
  expected_outcome: 'PASS' | 'BLOCKED_SANITIZER' | 'BLOCKED_ATTESTATION';
}
