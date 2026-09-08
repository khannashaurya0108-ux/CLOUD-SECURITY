import React, { useState, useEffect } from 'react';
import { FileCode, Copy, Check, Clock, Key } from 'lucide-react';

export const PolicyViewer = ({ selectedEvent }) => {
  const [copied, setCopied] = useState(false);
  const [countdown, setCountdown] = useState(30);

  const policyDoc = selectedEvent?.policy_doc;
  const policyJson = policyDoc ? JSON.stringify(policyDoc, null, 2) : null;

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
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-zinc-800/80">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold tracking-wider uppercase text-zinc-200">
            Synthesized IAM Policy Document
          </h3>
        </div>

        {policyJson && (
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg border border-zinc-700 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied' : 'Copy'}
          </button>
        )}
      </div>

      {selectedEvent?.status === 'PASS' && (
        <div className="mt-3 p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-800/30 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <Clock className={`w-4 h-4 ${countdown > 0 ? 'text-emerald-400 animate-pulse' : 'text-zinc-500'}`} />
            <span className="text-zinc-300">
              Ephemeral Role Lifespan: <strong className="font-mono text-emerald-400">{countdown}s</strong> remaining
            </span>
          </div>
          <span className="text-[11px] font-mono text-zinc-400">
            {countdown > 0 ? 'STATUS: ACTIVE (30s TTL)' : 'EXPIRED: Revoked'}
          </span>
        </div>
      )}

      <div className="flex-1 overflow-y-auto mt-3 font-mono text-xs">
        {selectedEvent?.status === 'BLOCKED' ? (
          <div className="h-full flex flex-col items-center justify-center p-6 text-center text-zinc-500 bg-zinc-900/30 rounded-lg border border-zinc-800/40">
            <p className="text-rose-300 font-semibold font-sans">No IAM Policy Synthesized</p>
            <p className="text-zinc-400 text-xs mt-1 max-w-md font-sans">
              Request was intercepted and terminated prior to STS credential assumption.
            </p>
          </div>
        ) : policyJson ? (
          <div className="bg-zinc-900/80 p-4 rounded-lg border border-zinc-800/80 overflow-x-auto text-zinc-300">
            <pre className="text-[11px]">{policyJson}</pre>
          </div>
        ) : (
          <div className="h-full flex flex-col items-center justify-center p-6 text-center text-zinc-500 bg-zinc-900/30 rounded-lg border border-zinc-800/40 font-sans">
            <p className="text-zinc-400 font-medium">Select a telemetry event to inspect its IAM policy</p>
          </div>
        )}
      </div>

      <div className="mt-3 pt-3 border-t border-zinc-800/60 flex items-center justify-between text-[11px] font-mono text-zinc-500">
        <div className="flex items-center gap-1">
          <Key className="w-3 h-3 text-zinc-500" />
          <span>AWS STS AssumedRole Policy</span>
        </div>
        <span>Version 2012-10-17</span>
      </div>
    </div>
  );
};
