import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { LiveLogFeed } from './components/LiveLogFeed';
import { LatencyGauge } from './components/LatencyGauge';
import { PolicyViewer } from './components/PolicyViewer';
import { AlertModal } from './components/AlertModal';
import { Shield, ShieldCheck, Zap, Radio, Bell } from 'lucide-react';

const INITIAL_EVENTS = [
  {
    id: 'sentinel-seed-01',
    timestamp: Date.now() - 25000,
    iso_time: new Date(Date.now() - 25000).toISOString(),
    event_type: 'COMPLETED',
    agent_id: 'agent-fin-analyst-01',
    target: 'finance-reports/q3_2026.pdf',
    action: 's3_get_object',
    status: 'PASS',
    latency_ms: 4.18,
    risk_score: 0,
    threat_details: 'Attested, Sanitized, and Ephemeral Role Assumed (< 15ms target).',
    policy_sha256: 'd95dc48af9013c72b53a479d2b27bc19a7e0',
    sts_session_id: 'ASIA9B2C4F1A',
    policy_doc: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'SentinelJITTaskScopedFinAnalyst01',
          Effect: 'Allow',
          Action: ['s3:GetObject'],
          Resource: ['arn:aws:s3:::finance-reports/q3_2026.pdf'],
          Condition: {
            DateLessThan: {
              'aws:CurrentTime': new Date(Date.now() - 2000).toISOString(),
            },
          },
        },
      ],
    },
  },
  {
    id: 'sentinel-seed-02',
    timestamp: Date.now() - 12000,
    iso_time: new Date(Date.now() - 12000).toISOString(),
    event_type: 'SANITIZER_BLOCKED',
    agent_id: 'agent-rogue-injected',
    target: 'kms:*',
    action: 'kms_decrypt',
    status: 'BLOCKED',
    latency_ms: 2.84,
    risk_score: 95,
    threat_details: 'Unauthorized KMS Master Key Decryption on Wildcard (*); Prompt Injection: Instruction Override',
    mitre_technique: 'AML.T0051 / AML.T0054',
  },
];

export default function App() {
  const [events, setEvents] = useState(INITIAL_EVENTS);
  const [selectedEvent, setSelectedEvent] = useState(INITIAL_EVENTS[0]);
  const [activeThreatModalEvent, setActiveThreatModalEvent] = useState(null);
  const [isThreatModalOpen, setIsThreatModalOpen] = useState(false);
  const [isBenchmarking, setIsBenchmarking] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);

  // Connect to FastAPI WebSocket
  useEffect(() => {
    let ws = null;
    let reconnectTimeout = null;

    const connectWebSocket = () => {
      try {
        const wsUrl = `ws://${window.location.hostname}:8000/ws/telemetry`;
        ws = new WebSocket(wsUrl);

        ws.onopen = () => setWsConnected(true);
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'TELEMETRY_EVENT' && data.event) {
              setEvents((prev) => [data.event, ...prev.slice(0, 150)]);
              if (data.event.status === 'BLOCKED') {
                setActiveThreatModalEvent(data.event);
                setIsThreatModalOpen(true);
              }
            } else if (data.type === 'INITIAL_SNAPSHOT' && data.recent_events) {
              if (data.recent_events.length > 0) {
                setEvents(data.recent_events);
              }
            }
          } catch (e) {
            // Ignore parse errors
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimeout = setTimeout(connectWebSocket, 5000);
        };
      } catch (e) {
        setWsConnected(false);
      }
    };

    connectWebSocket();
    return () => {
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (ws) ws.close();
    };
  }, []);

  const metrics = useMemo(() => {
    const total = events.length;
    const blocked = events.filter((e) => e.status === 'BLOCKED').length;
    const latencies = events.map((e) => e.latency_ms).sort((a, b) => a - b);
    const sum = latencies.reduce((acc, curr) => acc + curr, 0);
    const avg = total > 0 ? sum / total : 0;
    return {
      total_requests: total,
      blocked_requests: blocked,
      avg_latency_ms: Number(avg.toFixed(2)),
      p50_latency_ms: Number((latencies[Math.floor(total * 0.5)] || 0).toFixed(2)),
      p95_latency_ms: Number((latencies[Math.min(total - 1, Math.floor(total * 0.95))] || 0).toFixed(2)),
      p99_latency_ms: Number((latencies[Math.min(total - 1, Math.floor(total * 0.99))] || 0).toFixed(2)),
      target_sla_ms: 15.0,
      sla_met: avg <= 15.0,
    };
  }, [events]);

  const recentLatencies = useMemo(() => events.slice(-30).map((e) => e.latency_ms), [events]);

  const handleRunBenchmark = (count) => {
    setIsBenchmarking(true);
    let counter = 0;
    const interval = setInterval(() => {
      counter++;
      const isAttack = Math.random() < 0.2;
      const newEv = {
        id: `bench-${Date.now()}-${counter}`,
        timestamp: Date.now(),
        iso_time: new Date().toISOString(),
        event_type: isAttack ? 'SANITIZER_BLOCKED' : 'COMPLETED',
        agent_id: `agent-bench-${counter % 4}`,
        target: isAttack ? 'kms:*' : 'finance-reports/q3_2026.pdf',
        action: isAttack ? 'kms_decrypt' : 's3_get_object',
        status: isAttack ? 'BLOCKED' : 'PASS',
        latency_ms: Number((Math.random() * 4 + 2).toFixed(2)),
        risk_score: isAttack ? 95 : 0,
        threat_details: isAttack ? 'KMS Decrypt on Wildcard' : null,
        policy_doc: isAttack ? null : {
          Version: '2012-10-17',
          Statement: [{ Effect: 'Allow', Action: ['s3:GetObject'], Resource: ['arn:aws:s3:::finance-reports/q3_2026.pdf'] }]
        }
      };

      setEvents((prev) => [newEv, ...prev.slice(0, 150)]);
      if (counter >= count) {
        clearInterval(interval);
        setIsBenchmarking(false);
      }
    }, 50);
  };

  return (
    <div className="min-h-screen bg-black text-zinc-100 flex flex-col font-sans">
      <header className="sticky top-0 z-40 bg-zinc-950/95 backdrop-blur border-b border-zinc-800/80 px-6 py-3">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-emerald-500/20 border border-emerald-500/30 text-emerald-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight text-white">SentinelAgent Proxy</h1>
              <p className="text-[11px] text-zinc-400">Zero-Trust Runtime Security Proxy for Autonomous AI Agents</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono border ${
              wsConnected ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300' : 'bg-zinc-900 border-zinc-800 text-zinc-400'
            }`}>
              <Radio className={`w-3.5 h-3.5 ${wsConnected ? 'text-emerald-400 animate-pulse' : 'text-zinc-500'}`} />
              <span>{wsConnected ? 'WS Connected' : 'Standalone Mode'}</span>
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono bg-zinc-900 border border-zinc-800 text-zinc-300">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <span>Overhead: <strong className="text-emerald-400">{metrics.avg_latency_ms} ms</strong></span>
            </div>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <div className="lg:col-span-7 h-[500px]">
            <LiveLogFeed
              events={events}
              selectedEventId={selectedEvent?.id}
              onSelectEvent={(ev) => setSelectedEvent(ev)}
              onClearLogs={() => setEvents([])}
            />
          </div>

          <div className="lg:col-span-5 flex flex-col gap-6">
            <LatencyGauge
              metrics={metrics}
              recentLatencies={recentLatencies}
              onRunBenchmark={handleRunBenchmark}
              isBenchmarking={isBenchmarking}
            />
            <div className="h-[400px]">
              <PolicyViewer selectedEvent={selectedEvent} />
            </div>
          </div>
        </div>
      </main>

      <AlertModal
        event={activeThreatModalEvent}
        isOpen={isThreatModalOpen}
        onClose={() => setIsThreatModalOpen(false)}
      />
    </div>
  );
}
