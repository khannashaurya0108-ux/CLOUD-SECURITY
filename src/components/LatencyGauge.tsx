import React from 'react';
import { SummaryMetrics } from '../types';
import { Activity, Gauge, Zap, TrendingDown, CheckCircle2, AlertTriangle } from 'lucide-react';

interface LatencyGaugeProps {
  metrics: SummaryMetrics;
  recentLatencies: number[];
  onRunBenchmark: (count: number) => void;
  isBenchmarking: boolean;
}

export const LatencyGauge: React.FC<LatencyGaugeProps> = ({
  metrics,
  recentLatencies,
  onRunBenchmark,
  isBenchmarking,
}) => {
  const avg = metrics.avg_latency_ms;
  const target = metrics.target_sla_ms; // 15.0ms
  const percentageOfTarget = Math.min(100, Math.round((avg / target) * 100));

  // Determine status color
  const isHealthy = avg <= target;
  const statusColor = isHealthy ? 'text-emerald-400' : 'text-rose-400';
  const barColor = isHealthy ? 'bg-emerald-500' : 'bg-rose-500';

  // SVG Gauge calculations (semi-circle arc)
  const radius = 64;
  const circumference = Math.PI * radius; // Half-circle
  const strokeDashoffset = circumference - (Math.min(percentageOfTarget, 100) / 100) * circumference;

  return (
    <div id="latency-gauge-card" className="bg-zinc-950 border border-zinc-800/80 rounded-xl p-5 shadow-2xl flex flex-col justify-between">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-zinc-800/80">
        <div className="flex items-center gap-2">
          <Gauge className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold tracking-wider uppercase text-zinc-200">
            Proxy Overhead Gauge
          </h3>
        </div>
        <div className="flex items-center gap-1.5 text-xs font-mono px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800">
          <span className="text-zinc-400">SLA Target:</span>
          <span className="text-emerald-400 font-bold">&lt; 15.0 ms</span>
        </div>
      </div>

      {/* Main Gauge & Primary Number */}
      <div className="py-4 flex flex-col sm:flex-row items-center justify-around gap-6">
        {/* Radial Semi-Gauge */}
        <div className="relative flex flex-col items-center justify-center">
          <svg className="w-36 h-24 overflow-visible" viewBox="0 0 160 90">
            {/* Background Track Arc */}
            <path
              d="M 16 80 A 64 64 0 0 1 144 80"
              fill="none"
              stroke="#27272a"
              strokeWidth="12"
              strokeLinecap="round"
            />
            {/* 15ms SLA Threshold marker tick */}
            <line x1="80" y1="8" x2="80" y2="22" stroke="#71717a" strokeWidth="2" strokeDasharray="2,2" />
            {/* Active Gauge Arc */}
            <path
              d="M 16 80 A 64 64 0 0 1 144 80"
              fill="none"
              stroke={isHealthy ? '#10b981' : '#f43f5e'}
              strokeWidth="12"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              className="transition-all duration-500 ease-out"
            />
          </svg>

          <div className="absolute bottom-1 text-center">
            <span className={`text-2xl font-mono font-bold tracking-tight ${statusColor}`}>
              {avg.toFixed(2)}
            </span>
            <span className="text-xs text-zinc-400 ml-1 font-mono">ms</span>
            <div className="text-[10px] uppercase tracking-wider text-zinc-500 font-semibold">
              Overhead
            </div>
          </div>
        </div>

        {/* Status Badge & Benchmarking Trigger */}
        <div className="flex flex-col gap-3 min-w-[190px]">
          <div
            className={`p-2.5 rounded-lg border flex items-center gap-2.5 text-xs ${
              isHealthy
                ? 'bg-emerald-950/30 border-emerald-800/40 text-emerald-200'
                : 'bg-rose-950/30 border-rose-800/40 text-rose-200'
            }`}
          >
            {isHealthy ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            )}
            <div>
              <div className="font-semibold font-sans">
                {isHealthy ? 'SLA Target Achieved' : 'Latency Exceeded SLA'}
              </div>
              <div className="text-[11px] text-zinc-400 font-mono">
                {percentageOfTarget}% of 15ms ceiling
              </div>
            </div>
          </div>

          <button
            id="run-benchmark-btn"
            disabled={isBenchmarking}
            onClick={() => onRunBenchmark(50)}
            className="flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-700/80 text-xs font-semibold tracking-wide transition-all shadow hover:shadow-zinc-800/40 disabled:opacity-50 cursor-pointer"
          >
            <Zap className={`w-3.5 h-3.5 text-amber-400 ${isBenchmarking ? 'animate-bounce' : ''}`} />
            {isBenchmarking ? 'Running 50 reqs...' : 'Run 50-Request Benchmark'}
          </button>
        </div>
      </div>

      {/* Latency Sparkline Graph */}
      <div className="bg-zinc-900/40 border border-zinc-800/60 rounded-lg p-3 my-2">
        <div className="flex justify-between items-center text-[10px] text-zinc-400 uppercase tracking-wider mb-1.5">
          <span>Recent Interception Delays</span>
          <span className="font-mono text-zinc-500">Last {recentLatencies.length} calls</span>
        </div>
        <div className="h-10 flex items-end gap-1 overflow-hidden pt-1">
          {recentLatencies.map((lat, idx) => {
            const h = Math.min(100, Math.max(12, (lat / 15) * 80));
            const isOver = lat > 15;
            return (
              <div
                key={idx}
                title={`${lat.toFixed(2)} ms`}
                style={{ height: `${h}%` }}
                className={`flex-1 min-w-[4px] rounded-t transition-all ${
                  isOver ? 'bg-rose-500' : 'bg-emerald-500/80 hover:bg-emerald-400'
                }`}
              />
            );
          })}
        </div>
      </div>

      {/* Percentiles Breakdown Grid */}
      <div className="grid grid-cols-4 gap-2 pt-2 border-t border-zinc-800/60 text-center font-mono">
        <div className="bg-zinc-900/60 p-2 rounded border border-zinc-800/60">
          <div className="text-[10px] text-zinc-500 uppercase">P50 (Median)</div>
          <div className="text-xs font-semibold text-zinc-200 mt-0.5">{metrics.p50_latency_ms} ms</div>
        </div>
        <div className="bg-zinc-900/60 p-2 rounded border border-zinc-800/60">
          <div className="text-[10px] text-zinc-500 uppercase">P95</div>
          <div className="text-xs font-semibold text-zinc-200 mt-0.5">{metrics.p95_latency_ms} ms</div>
        </div>
        <div className="bg-zinc-900/60 p-2 rounded border border-zinc-800/60">
          <div className="text-[10px] text-zinc-500 uppercase">P99</div>
          <div className="text-xs font-semibold text-zinc-200 mt-0.5">{metrics.p99_latency_ms} ms</div>
        </div>
        <div className="bg-zinc-900/60 p-2 rounded border border-zinc-800/60">
          <div className="text-[10px] text-zinc-500 uppercase">Total Calls</div>
          <div className="text-xs font-semibold text-emerald-400 mt-0.5">{metrics.total_requests}</div>
        </div>
      </div>
    </div>
  );
};
