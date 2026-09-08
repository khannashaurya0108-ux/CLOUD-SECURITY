import React from 'react';
import { ShieldAlert, X, Flame, CheckCircle } from 'lucide-react';

export const AlertModal = ({ event, isOpen, onClose }) => {
  if (!isOpen || !event) return null;

  return (
    <div
      id="threat-alert-modal-backdrop"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        id="threat-alert-modal-card"
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg bg-zinc-950 border-2 border-rose-600/80 rounded-2xl shadow-2xl overflow-hidden text-zinc-100 font-sans"
      >
        <div className="bg-rose-950/80 border-b border-rose-800/80 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-rose-500/20 border border-rose-500/40 text-rose-400">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="text-xs font-bold uppercase tracking-widest text-rose-400">
                Threat Detected & Intercepted
              </div>
              <h2 className="text-lg font-bold text-white tracking-tight">
                Sentinel Runtime Guardrail Violation
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800/60 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between p-3 rounded-xl bg-rose-950/30 border border-rose-900/40">
            <div className="flex items-center gap-2">
              <Flame className="w-5 h-5 text-rose-400" />
              <div>
                <div className="text-xs font-semibold text-rose-200">Threat Severity Score</div>
                <div className="text-[11px] text-zinc-400">Heuristic Anomaly Index</div>
              </div>
            </div>
            <div className="text-right">
              <span className="text-2xl font-mono font-black text-rose-400">
                {event.risk_score}
              </span>
              <span className="text-xs text-zinc-400 font-mono"> / 100</span>
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
              Flagged Anomaly Signature
            </div>
            <div className="p-3 bg-zinc-900 rounded-lg border border-zinc-800 text-xs font-mono text-rose-300">
              {event.threat_details || 'Malicious prompt injection or unconstrained cloud command detected.'}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-zinc-900/60 rounded-lg border border-zinc-800/60">
              <span className="text-zinc-500 text-[10px] uppercase font-mono block">Attacker / Calling Agent</span>
              <span className="font-mono text-zinc-200 font-semibold mt-0.5 block truncate">
                {event.agent_id}
              </span>
            </div>
            <div className="p-3 bg-zinc-900/60 rounded-lg border border-zinc-800/60">
              <span className="text-zinc-500 text-[10px] uppercase font-mono block">Targeted Action</span>
              <span className="font-mono text-zinc-200 font-semibold mt-0.5 block truncate">
                {event.action}
              </span>
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-zinc-900/80 border border-zinc-800 flex items-start gap-2.5 text-xs">
            <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold text-zinc-200">Mitigation: Terminated at Proxy Gateway</div>
              <p className="text-zinc-400 text-[11px] mt-0.5">
                HTTP request was aborted with 403 Forbidden before reaching AWS STS. No credentials were exposed.
              </p>
            </div>
          </div>
        </div>

        <div className="bg-zinc-900/90 border-t border-zinc-800/80 px-6 py-3 flex items-center justify-between text-xs">
          <span className="text-zinc-500 font-mono text-[11px]">Audit ID: {event.id}</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-medium transition-colors"
          >
            Acknowledge & Dismiss
          </button>
        </div>
      </div>
    </div>
  );
};
