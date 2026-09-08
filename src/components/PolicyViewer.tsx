import React, { useState, useEffect } from 'react';
import { TelemetryEventData } from '../types';
import { FileCode, Copy, Check, Shield, Clock, Hash, Key, ExternalLink, Sparkles } from 'lucide-react';

interface PolicyViewerProps {
  selectedEvent?: TelemetryEventData;
}

export const PolicyViewer: React.FC<PolicyViewerProps> = ({ selectedEvent }) => {
  const [copied, setCopied] = useState(false);
  const [countdown, setCountdown] = useState<number>(30);
  const [activeTab, setActiveTab] = useState<'JSON' | 'AUDIT'>('JSON');

  const policyDoc = selectedEvent?.policy_doc;
  const policyJson = policyDoc ? JSON.stringify(policyDoc, null, 2) : null;
  const sha256 = selectedEvent?.policy_sha256 || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  // 30-second temporal TTL countdown simulation
  useEffect(() => {
    if (!selectedEvent || selectedEvent.status !== 'PASS') {
      setCountdown(0);
      return;
    }

    const elapsed = Math.floor((Date.now() - selectedEvent.timestamp) / 1000);
    const remaining = Math.max(0, 30 - elapsed);
    setCountdown(remaining);

    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [selectedEvent]);

  const handleCopy = () => {
    if (policyJson) {
      navigator.clipboard.writeText(policyJson);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div id="policy-viewer-card" className="bg-zinc-950 border border-zinc-800/80 rounded-xl p-5 shadow-2xl flex flex-col h-full">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-zinc-800/80">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold tracking-wider uppercase text-zinc-200">
            Synthesized IAM Policy Document
          </h3>
        </div>

        <div className="flex items-center gap-2">
          {/* Tab Switcher */}
          <div className="flex items-center bg-zinc-900 p-0.5 rounded-lg border border-zinc-800 text-xs">
            <button
              onClick={() => setActiveTab('JSON')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                activeTab === 'JSON' ? 'bg-zinc-800 text-zinc-100 font-medium' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              JSON Doc
            </button>
            <button
              onClick={() => setActiveTab('AUDIT')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                activeTab === 'AUDIT' ? 'bg-zinc-800 text-zinc-100 font-medium' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Zero-Trust Audit
            </button>
          </div>

          {policyJson && (
            <button
              id="copy-policy-json-btn"
              onClick={handleCopy}
              className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg border border-zinc-700 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          )}
        </div>
      </div>

      {/* Expiration Countdown Banner */}
      {selectedEvent?.status === 'PASS' && (
        <div className="mt-3 p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-800/30 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <Clock className={`w-4 h-4 ${countdown > 0 ? 'text-emerald-400 animate-pulse' : 'text-zinc-500'}`} />
            <span className="text-zinc-300">
              Ephemeral Role Lifespan: <strong className="font-mono text-emerald-400">{countdown}s</strong> remaining
            </span>
          </div>
          <span className="text-[11px] font-mono text-zinc-400">
            {countdown > 0 ? 'STATUS: ACTIVE (30s TTL)' : 'EXPIRED: Ephemeral Credential Revoked'}
          </span>
        </div>
      )}

      {/* Content Area */}
      <div className="flex-1 overflow-y-auto mt-3 font-mono text-xs">
        {selectedEvent?.status === 'BLOCKED' ? (
          <div className="h-full flex flex-col items-center justify-center p-6 text-center text-zinc-500 bg-zinc-900/30 rounded-lg border border-zinc-800/40">
            <Shield className="w-8 h-8 text-rose-500/60 mb-2" />
            <p className="text-rose-300 font-semibold font-sans">No IAM Policy Synthesized</p>
            <p className="text-zinc-400 text-xs mt-1 max-w-md font-sans">
              Request was intercepted and terminated by Sentinel prior to STS credential assumption due to a security violation.
            </p>
            {selectedEvent.threat_details && (
              <div className="mt-3 px-3 py-1.5 rounded bg-rose-950/40 border border-rose-900/50 text-rose-300 text-[11px]">
                Reason: {selectedEvent.threat_details}
              </div>
            )}
          </div>
        ) : policyJson ? (
          activeTab === 'JSON' ? (
            <div className="bg-zinc-900/80 p-4 rounded-lg border border-zinc-800/80 overflow-x-auto text-zinc-300 leading-relaxed">
              <pre className="text-[11px]">{policyJson}</pre>
            </div>
          ) : (
            /* Zero-Trust Audit Tab */
            <div className="space-y-3 font-sans text-xs">
              <div className="p-3 bg-zinc-900/50 rounded-lg border border-zinc-800/80 space-y-2">
                <div className="text-zinc-400 font-semibold uppercase text-[10px] tracking-wider">
                  Cryptographic Integrity & Attribution
                </div>
                <div className="flex items-center justify-between font-mono text-[11px]">
                  <span className="text-zinc-400">Agent Identity:</span>
                  <span className="text-emerald-400">{selectedEvent.agent_id}</span>
                </div>
                <div className="flex items-center justify-between font-mono text-[11px]">
                  <span className="text-zinc-400">SPIFFE ID:</span>
                  <span className="text-zinc-300 text-[10px]">
                    spiffe://sentinel.internal/ns/prod/sa/{selectedEvent.agent_id}
                  </span>
                </div>
                <div className="flex items-center justify-between font-mono text-[11px]">
                  <span className="text-zinc-400">Policy SHA-256:</span>
                  <span className="text-zinc-400 text-[10px] truncate max-w-[200px]">{sha256}</span>
                </div>
                <div className="flex items-center justify-between font-mono text-[11px]">
                  <span className="text-zinc-400">AWS STS Session:</span>
                  <span className="text-amber-400">{selectedEvent.sts_session_id || 'ASIA9B2C4F1A'}</span>
                </div>
              </div>

              <div className="p-3 bg-zinc-900/50 rounded-lg border border-zinc-800/80 space-y-2">
                <div className="text-zinc-400 font-semibold uppercase text-[10px] tracking-wider">
                  Least-Privilege Guardrail Invariants
                </div>
                <ul className="space-y-1.5 text-zinc-300">
                  <li className="flex items-center gap-1.5">
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Wildcards Strictly Forbidden: No &quot;*&quot; allowed in Action or Resource</span>
                  </li>
                  <li className="flex items-center gap-1.5">
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Single-Resource Scope: Bound to specific target ARN</span>
                  </li>
                  <li className="flex items-center gap-1.5">
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Temporal Revocation: DateLessThan condition kills access at T+30s</span>
                  </li>
                </ul>
              </div>
            </div>
          )
        ) : (
          <div className="h-full flex flex-col items-center justify-center p-6 text-center text-zinc-500 bg-zinc-900/30 rounded-lg border border-zinc-800/40 font-sans">
            <Sparkles className="w-8 h-8 text-zinc-600 mb-2" />
            <p className="text-zinc-400 font-medium">Select a telemetry event to inspect its IAM policy</p>
            <p className="text-zinc-500 text-xs mt-1">
              Policies are synthesized just-in-time on demand for authenticated tool executions.
            </p>
          </div>
        )}
      </div>

      {/* Footer Info */}
      <div className="mt-3 pt-3 border-t border-zinc-800/60 flex items-center justify-between text-[11px] font-mono text-zinc-500">
        <div className="flex items-center gap-1">
          <Key className="w-3 h-3 text-zinc-500" />
          <span>AWS STS AssumedRole Policy (Inline Session)</span>
        </div>
        <span>Version 2012-10-17</span>
      </div>
    </div>
  );
};
