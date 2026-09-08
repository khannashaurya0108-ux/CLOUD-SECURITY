import React, { useState } from 'react';
import { TelemetryEventData } from '../types';
import { ShieldCheck, ShieldAlert, Clock, Terminal, Filter, Search, ChevronRight } from 'lucide-react';

interface LiveLogFeedProps {
  events: TelemetryEventData[];
  selectedEventId?: string;
  onSelectEvent: (event: TelemetryEventData) => void;
  onClearLogs: () => void;
}

export const LiveLogFeed: React.FC<LiveLogFeedProps> = ({
  events,
  selectedEventId,
  onSelectEvent,
  onClearLogs,
}) => {
  const [filter, setFilter] = useState<'ALL' | 'PASS' | 'BLOCKED'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  const filteredEvents = events.filter((e) => {
    if (filter !== 'ALL' && e.status !== filter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        e.agent_id.toLowerCase().includes(term) ||
        e.action.toLowerCase().includes(term) ||
        e.target.toLowerCase().includes(term) ||
        (e.threat_details && e.threat_details.toLowerCase().includes(term))
      );
    }
    return true;
  });

  return (
    <div id="live-log-feed-container" className="flex flex-col h-full bg-zinc-950 border border-zinc-800/80 rounded-xl overflow-hidden shadow-2xl">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 bg-zinc-900/90 border-b border-zinc-800">
        <div className="flex items-center gap-2.5">
          <div className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
          </div>
          <h2 className="text-sm font-semibold tracking-wider uppercase text-zinc-200">
            Real-Time Activity Telemetry
          </h2>
          <span className="text-xs px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-400 font-mono">
            {filteredEvents.length} events
          </span>
        </div>

        <div className="flex items-center gap-2">
          {/* Filter Pills */}
          <div className="flex items-center bg-zinc-950 p-0.5 rounded-lg border border-zinc-800 text-xs">
            <button
              id="filter-all-btn"
              onClick={() => setFilter('ALL')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                filter === 'ALL' ? 'bg-zinc-800 text-zinc-100 font-medium' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              All
            </button>
            <button
              id="filter-pass-btn"
              onClick={() => setFilter('PASS')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                filter === 'PASS' ? 'bg-emerald-950/80 text-emerald-300 font-medium' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Passed
            </button>
            <button
              id="filter-blocked-btn"
              onClick={() => setFilter('BLOCKED')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                filter === 'BLOCKED' ? 'bg-rose-950/80 text-rose-300 font-medium' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Blocked
            </button>
          </div>

          <button
            id="clear-logs-btn"
            onClick={onClearLogs}
            className="text-xs px-2.5 py-1 rounded-lg border border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Search Filter Bar */}
      <div className="px-4 py-2 bg-zinc-900/40 border-b border-zinc-800/60 flex items-center gap-2">
        <Search className="w-3.5 h-3.5 text-zinc-500" />
        <input
          id="log-search-input"
          type="text"
          placeholder="Filter by Agent ID, action (s3_get_object, kms_decrypt), or target..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full bg-transparent text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none"
        />
        {searchTerm && (
          <button
            onClick={() => setSearchTerm('')}
            className="text-xs text-zinc-500 hover:text-zinc-300 px-1"
          >
            ×
          </button>
        )}
      </div>

      {/* Events Table / Feed */}
      <div className="flex-1 overflow-y-auto divide-y divide-zinc-900/90 font-mono text-xs">
        {filteredEvents.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-12 text-zinc-500 text-center">
            <Terminal className="w-8 h-8 mb-2 opacity-40" />
            <p>No telemetry events match the current filter.</p>
            <p className="text-zinc-600 text-[11px] mt-1">Execute an agent tool call from the simulator panel.</p>
          </div>
        ) : (
          filteredEvents.map((ev) => {
            const isSelected = ev.id === selectedEventId;
            const isBlocked = ev.status === 'BLOCKED';

            return (
              <div
                key={ev.id}
                id={`log-row-${ev.id}`}
                onClick={() => onSelectEvent(ev)}
                className={`p-3 transition-colors cursor-pointer flex items-start justify-between gap-3 ${
                  isSelected
                    ? 'bg-zinc-900 border-l-2 border-emerald-500'
                    : isBlocked
                    ? 'hover:bg-rose-950/20 bg-rose-950/5'
                    : 'hover:bg-zinc-900/40'
                }`}
              >
                <div className="flex items-start gap-2.5 min-w-0 flex-1">
                  <div className="mt-0.5">
                    {isBlocked ? (
                      <div className="p-1 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                        <ShieldAlert className="w-3.5 h-3.5" />
                      </div>
                    ) : (
                      <div className="p-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        <ShieldCheck className="w-3.5 h-3.5" />
                      </div>
                    )}
                  </div>

                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold tracking-wide ${
                          isBlocked
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        }`}
                      >
                        {ev.status}
                      </span>
                      <span className="font-semibold text-zinc-100 truncate">
                        {ev.action}
                      </span>
                      <span className="text-zinc-500 text-[11px] truncate max-w-[200px]">
                        → {ev.target}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-3 text-[11px] text-zinc-400">
                      <span className="text-zinc-300 font-sans font-medium">
                        Agent: <code className="text-emerald-400/90">{ev.agent_id}</code>
                      </span>
                      {ev.mitre_technique && (
                        <span className="text-rose-400/90 font-mono text-[10px] px-1 rounded bg-rose-950/40 border border-rose-900/50">
                          MITRE: {ev.mitre_technique}
                        </span>
                      )}
                      {ev.threat_details && isBlocked && (
                        <span className="text-rose-400/80 truncate max-w-sm">
                          {ev.threat_details}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex flex-col items-end shrink-0 gap-1">
                  <div className="flex items-center gap-1 text-[11px] font-mono">
                    <Clock className="w-3 h-3 text-zinc-500" />
                    <span
                      className={`font-semibold ${
                        ev.latency_ms <= 15 ? 'text-emerald-400' : 'text-amber-400'
                      }`}
                    >
                      {ev.latency_ms.toFixed(2)} ms
                    </span>
                  </div>
                  <span className="text-[10px] text-zinc-500">
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </span>
                  <ChevronRight className="w-3.5 h-3.5 text-zinc-600 mt-1" />
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
