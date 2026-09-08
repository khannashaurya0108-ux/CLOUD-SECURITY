import React, { useState } from 'react';
import { Code, Terminal, Layers, ShieldCheck, Copy, Check } from 'lucide-react';

export const ArchitectureViewer: React.FC = () => {
  const [selectedTab, setSelectedTab] = useState<'FLOW' | 'CLI' | 'SPECS'>('FLOW');
  const [copied, setCopied] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const cliCommands = [
    {
      terminal: 'Terminal 1: FastAPI Reverse Proxy',
      cmd: 'uvicorn app.main:app --port 8000 --reload',
      desc: 'Starts the Sentinel proxy with WebSocket stream and WIT attestation on port 8000',
    },
    {
      terminal: 'Terminal 2: React Telemetry Dashboard',
      cmd: 'cd dashboard && npm run dev',
      desc: 'Launches the dark-mode real-time monitor and latency SLA gauge',
    },
    {
      terminal: 'Terminal 3: Vulnerable Agent (Unprotected)',
      cmd: 'python demo/agent_vulnerable.py',
      desc: 'Demonstrates prompt injection succeeding against raw cloud APIs without Sentinel',
    },
    {
      terminal: 'Terminal 4: Protected Agent (Sentinel Shielded)',
      cmd: 'python demo/agent_protected.py',
      desc: 'Demonstrates sub-10ms prompt injection defense and scoped JIT IAM synthesis',
    },
  ];

  return (
    <div id="architecture-viewer-card" className="bg-zinc-950 border border-zinc-800/80 rounded-xl p-5 shadow-2xl">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-zinc-800/80">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold tracking-wider uppercase text-zinc-200">
            Sentinel Architecture & Verification Protocol
          </h3>
        </div>

        {/* Tab switcher */}
        <div className="flex items-center bg-zinc-900 p-0.5 rounded-lg border border-zinc-800 text-xs">
          <button
            onClick={() => setSelectedTab('FLOW')}
            className={`px-3 py-1 rounded-md transition-colors ${
              selectedTab === 'FLOW' ? 'bg-zinc-800 text-zinc-100 font-medium' : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Zero-Trust Pipeline
          </button>
          <button
            onClick={() => setSelectedTab('CLI')}
            className={`px-3 py-1 rounded-md transition-colors ${
              selectedTab === 'CLI' ? 'bg-zinc-800 text-zinc-100 font-medium' : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            4-Terminal CLI Guide
          </button>
          <button
            onClick={() => setSelectedTab('SPECS')}
            className={`px-3 py-1 rounded-md transition-colors ${
              selectedTab === 'SPECS' ? 'bg-zinc-800 text-zinc-100 font-medium' : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Security Invariants
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="mt-4">
        {selectedTab === 'FLOW' && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
            <div className="p-3.5 rounded-lg bg-zinc-900/60 border border-zinc-800/80 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-mono text-emerald-400 font-bold text-[11px]">Phase 1</span>
                <span className="text-[10px] text-zinc-500 font-mono">&lt; 1.5ms</span>
              </div>
              <h4 className="font-semibold text-zinc-100">Identity Attestation</h4>
              <p className="text-zinc-400 text-[11px] leading-relaxed">
                Cryptographic SPIFFE / WIT signature inspection. Validates 30s token lifespan and process hash. Rejects unattested callers.
              </p>
              <div className="pt-1 text-[10px] font-mono text-zinc-500">app/identity/attestation.py</div>
            </div>

            <div className="p-3.5 rounded-lg bg-zinc-900/60 border border-zinc-800/80 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-mono text-emerald-400 font-bold text-[11px]">Phase 2</span>
                <span className="text-[10px] text-zinc-500 font-mono">&lt; 2.5ms</span>
              </div>
              <h4 className="font-semibold text-zinc-100">Action Sanitizer</h4>
              <p className="text-zinc-400 text-[11px] leading-relaxed">
                Heuristic & RegEx scanner for prompt injection (OWASP LLM01) and dangerous operations (KMS Decrypt wildcard, bulk delete).
              </p>
              <div className="pt-1 text-[10px] font-mono text-zinc-500">app/proxy/sanitizer.py</div>
            </div>

            <div className="p-3.5 rounded-lg bg-zinc-900/60 border border-zinc-800/80 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-mono text-emerald-400 font-bold text-[11px]">Phase 3</span>
                <span className="text-[10px] text-zinc-500 font-mono">&lt; 1.2ms</span>
              </div>
              <h4 className="font-semibold text-zinc-100">JIT Policy Synthesizer</h4>
              <p className="text-zinc-400 text-[11px] leading-relaxed">
                Translates JSON tool calls into task-scoped AWS IAM policies. Disallows wildcards; embeds 30s temporal expiration.
              </p>
              <div className="pt-1 text-[10px] font-mono text-zinc-500">app/policy/synthesizer.py</div>
            </div>

            <div className="p-3.5 rounded-lg bg-zinc-900/60 border border-zinc-800/80 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-mono text-emerald-400 font-bold text-[11px]">Phase 4</span>
                <span className="text-[10px] text-zinc-500 font-mono">&lt; 4.0ms</span>
              </div>
              <h4 className="font-semibold text-zinc-100">AWS STS AssumeRole</h4>
              <p className="text-zinc-400 text-[11px] leading-relaxed">
                Applies synthesized inline policy to acquire ephemeral session credentials. Total proxy latency consistently &lt; 15ms.
              </p>
              <div className="pt-1 text-[10px] font-mono text-zinc-500">app/policy/aws_sts.py</div>
            </div>
          </div>
        )}

        {selectedTab === 'CLI' && (
          <div className="space-y-2.5">
            {cliCommands.map((item, idx) => (
              <div
                key={idx}
                className="p-3 bg-zinc-900/60 border border-zinc-800 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div>
                  <span className="font-semibold text-zinc-200 block mb-0.5">{item.terminal}</span>
                  <span className="text-[11px] text-zinc-400 block mb-1">{item.desc}</span>
                  <code className="font-mono text-emerald-400 bg-zinc-950 px-2 py-1 rounded border border-zinc-800/80 inline-block">
                    {item.cmd}
                  </code>
                </div>
                <button
                  onClick={() => copyToClipboard(item.cmd, `cmd-${idx}`)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-200 font-medium text-xs transition-colors shrink-0"
                >
                  {copied === `cmd-${idx}` ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Command</span>
                    </>
                  )}
                </button>
              </div>
            ))}
          </div>
        )}

        {selectedTab === 'SPECS' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-sans">
            <div className="p-3 bg-zinc-900/40 border border-zinc-800 rounded-lg">
              <div className="font-semibold text-emerald-400 mb-1">Zero-Trust Principle #1</div>
              <div className="font-medium text-zinc-200 mb-1">Strict 30-Second Token Lifespan</div>
              <p className="text-zinc-400 text-[11px] leading-relaxed">
                Workload Identity Tokens (WIT) carry cryptographic creation timestamps. Replay attacks after 30 seconds are rejected with 403 Forbidden.
              </p>
            </div>
            <div className="p-3 bg-zinc-900/40 border border-zinc-800 rounded-lg">
              <div className="font-semibold text-emerald-400 mb-1">Zero-Trust Principle #2</div>
              <div className="font-medium text-zinc-200 mb-1">Zero-Wildcard IAM Guarantee</div>
              <p className="text-zinc-400 text-[11px] leading-relaxed">
                Synthesizer explicitly bans wildcard resources (e.g. &quot;*&quot; or &quot;arn:...:::*&quot;). Access is strictly constrained to the single identified object ARN.
              </p>
            </div>
            <div className="p-3 bg-zinc-900/40 border border-zinc-800 rounded-lg">
              <div className="font-semibold text-emerald-400 mb-1">Zero-Trust Principle #3</div>
              <div className="font-medium text-zinc-200 mb-1">Pre-Cloud Injection Defense</div>
              <p className="text-zinc-400 text-[11px] leading-relaxed">
                Action Sanitizer executes prior to AWS STS or Cloud Provider ingress. Malicious prompt injections are killed in &lt; 10ms with zero credential exposure.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
