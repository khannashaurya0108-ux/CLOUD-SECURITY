import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { TelemetryEventData, SummaryMetrics, SimulationPayload } from './types';
import {
  INITIAL_EVENTS,
  executeProxySimulation,
  computeMetricsFromEvents,
} from './lib/sentinelEngine';
import { LiveLogFeed } from './components/LiveLogFeed';
import { LatencyGauge } from './components/LatencyGauge';
import { PolicyViewer } from './components/PolicyViewer';
import { AlertModal } from './components/AlertModal';
import { AgentSimulator } from './components/AgentSimulator';
import { ArchitectureViewer } from './components/ArchitectureViewer';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Activity,
  Radio,
  Bell,
  RefreshCw,
  Terminal,
  Cpu,
} from 'lucide-react';

export default function App() {
  const [events, setEvents] = useState<TelemetryEventData[]>(INITIAL_EVENTS);
  const [selectedEvent, setSelectedEvent] = useState<TelemetryEventData | undefined>(
    INITIAL_EVENTS[0]
  );
  const [activeThreatModalEvent, setActiveThreatModalEvent] = useState<TelemetryEventData | null>(null);
  const [isThreatModalOpen, setIsThreatModalOpen] = useState<boolean>(false);
  const [isBenchmarking, setIsBenchmarking] = useState<boolean>(false);
  const [isRunningScenario, setIsRunningScenario] = useState<boolean>(false);
  const [wsConnected, setWsConnected] = useState<boolean>(false);

  // Compute live summary metrics
  const metrics: SummaryMetrics = useMemo(() => computeMetricsFromEvents(events), [events]);
  const recentLatencies = useMemo(() => events.slice(-30).map((e) => e.latency_ms), [events]);

  // Attempt connection to live FastAPI WebSocket endpoint if available
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimeout: any = null;

    const connectWebSocket = () => {
      try {
        const wsUrl = `ws://${window.location.hostname}:8000/ws/telemetry`;
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          setWsConnected(true);
        };

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
          } catch {
            // Ignore malformed message
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimeout = setTimeout(connectWebSocket, 5000);
        };

        ws.onerror = () => {
          setWsConnected(false);
          ws?.close();
        };
      } catch {
        setWsConnected(false);
      }
    };

    connectWebSocket();

    return () => {
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (ws) ws.close();
    };
  }, []);

  // Dispatch simulation through Sentinel Engine
  const handleRunScenario = useCallback((scenario: SimulationPayload) => {
    setIsRunningScenario(true);

    // Simulate minor asynchronous proxy transit delay
    setTimeout(() => {
      const result = executeProxySimulation(scenario);
      setEvents((prev) => [result.event, ...prev.slice(0, 150)]);
      setSelectedEvent(result.event);
      setIsRunningScenario(false);

      if (result.event.status === 'BLOCKED') {
        setActiveThreatModalEvent(result.event);
        setIsThreatModalOpen(true);
      }
    }, 150);
  }, []);

  // Latency Benchmark Runner (e.g. 50 calls)
  const handleRunBenchmark = useCallback((count: number) => {
    setIsBenchmarking(true);
    let counter = 0;
    const interval = setInterval(() => {
      counter++;
      const isAnomalous = Math.random() < 0.15;
      const scenario: SimulationPayload = isAnomalous
        ? {
            name: `Benchmark Attack #${counter}`,
            agent_id: 'agent-benchmark-stress',
            action: 'kms_decrypt',
            key_id: '*',
            has_valid_token: true,
            description: 'Automated benchmark injection test',
            expected_outcome: 'BLOCKED_SANITIZER',
          }
        : {
            name: `Benchmark Valid Tool Call #${counter}`,
            agent_id: `agent-worker-${counter % 5}`,
            action: 's3_get_object',
            bucket: 'finance-reports',
            key: `batch_${counter}.dat`,
            has_valid_token: true,
            description: 'High-throughput tool execution test',
            expected_outcome: 'PASS',
          };

      const result = executeProxySimulation(scenario);
      setEvents((prev) => [result.event, ...prev.slice(0, 150)]);

      if (counter >= count) {
        clearInterval(interval);
        setIsBenchmarking(false);
      }
    }, 45);
  }, []);

  const handleClearLogs = useCallback(() => {
    setEvents([]);
    setSelectedEvent(undefined);
  }, []);

  const blockedCount = events.filter((e) => e.status === 'BLOCKED').length;

  return (
    <div className="min-h-screen bg-black text-zinc-100 flex flex-col font-sans selection:bg-emerald-500/30 selection:text-emerald-200">
      {/* Top Global Command Header */}
      <header className="sticky top-0 z-40 bg-zinc-950/95 backdrop-blur border-b border-zinc-800/80 px-4 sm:px-6 py-3">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
          {/* Logo & Product Name */}
          <div className="flex items-center gap-3">
            <div className="relative p-2 rounded-xl bg-gradient-to-br from-emerald-500/20 to-teal-500/10 border border-emerald-500/30 text-emerald-400 shadow-lg shadow-emerald-950/40">
              <Shield className="w-5 h-5" />
              <div className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold tracking-tight text-white">
                  SentinelAgent Proxy
                </h1>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-emerald-400 font-semibold">
                  v1.0.0
                </span>
              </div>
              <p className="text-[11px] text-zinc-400">
                Zero-Trust Runtime Security Proxy for Autonomous AI Agents &amp; NHI
              </p>
            </div>
          </div>

          {/* Operational Status Badges */}
          <div className="flex flex-wrap items-center gap-2.5">
            {/* WebSocket Stream Indicator */}
            <div
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono border transition-all ${
                wsConnected
                  ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
                  : 'bg-zinc-900 border-zinc-800 text-zinc-400'
              }`}
            >
              <Radio className={`w-3.5 h-3.5 ${wsConnected ? 'text-emerald-400 animate-pulse' : 'text-zinc-500'}`} />
              <span>{wsConnected ? 'WS Live Stream: Connected' : 'Engine: Client Reactive Stream'}</span>
            </div>

            {/* SLA Badge */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono bg-zinc-900 border border-zinc-800 text-zinc-300">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <span>Overhead:</span>
              <strong className="text-emerald-400 font-bold">{metrics.avg_latency_ms} ms</strong>
              <span className="text-[10px] text-zinc-500">(&lt; 15ms SLA)</span>
            </div>

            {/* Security Alerts Button */}
            <button
              id="view-alerts-btn"
              onClick={() => {
                const latestBlocked = events.find((e) => e.status === 'BLOCKED');
                if (latestBlocked) {
                  setActiveThreatModalEvent(latestBlocked);
                  setIsThreatModalOpen(true);
                }
              }}
              className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-200 transition-colors cursor-pointer"
            >
              <Bell className="w-3.5 h-3.5 text-rose-400" />
              <span>Threats Flagged:</span>
              <span className="font-mono font-bold text-rose-400">{blockedCount}</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Split-Screen Dashboard Layout */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 space-y-6">
        {/* Top Two-Column Grid: Left (Log Feed) vs Right (Latency Gauge & Policy Viewer) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Column: Live Activity Feed (7 cols) */}
          <div className="lg:col-span-7 flex flex-col gap-6">
            <div className="h-[460px]">
              <LiveLogFeed
                events={events}
                selectedEventId={selectedEvent?.id}
                onSelectEvent={(ev) => setSelectedEvent(ev)}
                onClearLogs={handleClearLogs}
              />
            </div>

            {/* Interactive Agent Lab below the log feed */}
            <AgentSimulator
              onRunScenario={handleRunScenario}
              isRunning={isRunningScenario}
            />
          </div>

          {/* Right Column: Latency Impact Gauge & Synthesized IAM Policy Viewer (5 cols) */}
          <div className="lg:col-span-5 flex flex-col gap-6">
            {/* Latency Impact Gauge */}
            <LatencyGauge
              metrics={metrics}
              recentLatencies={recentLatencies}
              onRunBenchmark={handleRunBenchmark}
              isBenchmarking={isBenchmarking}
            />

            {/* Synthesized IAM Policy Viewer */}
            <div className="h-[420px]">
              <PolicyViewer selectedEvent={selectedEvent} />
            </div>
          </div>
        </div>

        {/* Bottom Section: Architecture Flow & 4-Terminal Verification Protocol */}
        <ArchitectureViewer />
      </main>

      {/* Footer */}
      <footer className="bg-zinc-950 border-t border-zinc-800/80 py-4 px-6 text-xs text-zinc-500 font-mono flex flex-wrap items-center justify-between gap-4 max-w-7xl mx-auto w-full">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>SentinelAgent Proxy &bull; Zero-Trust Runtime Gateway</span>
        </div>
        <div className="flex items-center gap-4">
          <span>Standards: SPIFFE | WIMSE | AWS STS</span>
          <span>MITRE ATLAS: AML.T0051 / AML.T0054</span>
          <span>SLA Target: &lt; 15ms Overhead</span>
        </div>
      </footer>

      {/* Threat Alert Modal */}
      <AlertModal
        event={activeThreatModalEvent}
        isOpen={isThreatModalOpen}
        onClose={() => setIsThreatModalOpen(false)}
      />
    </div>
  );
}
