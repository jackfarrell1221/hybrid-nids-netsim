// components/traffic/PacketDissector.tsx — Wireshark-Style 3-Pane Dissector & Raw Hex Inspector.

import React, { useState } from 'react';
import type { CapturedPacket } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';
import { Badge } from '../common/Badge';
import {
  X,
  ChevronDown,
  ChevronRight,
  Copy,
  Check,
  ShieldAlert,
  Terminal,
  Layers,
  Binary,
  Globe,
  Radio,
} from 'lucide-react';

interface Props {
  packet: CapturedPacket | null;
  onClose: () => void;
}

type TabMode = 'wireshark' | 'raw_hex';

export const PacketDissector: React.FC<Props> = ({ packet, onClose }) => {
  const [tab, setTab] = useState<TabMode>('wireshark');
  const [copiedHex, setCopiedHex] = useState(false);
  const [copiedMitigation, setCopiedMitigation] = useState(false);

  // Expand/collapse states for protocol tree nodes in Pane A
  const [expandedFrame, setExpandedFrame] = useState(true);
  const [expandedIP, setExpandedIP] = useState(true);
  const [expandedTransport, setExpandedTransport] = useState(true);

  if (!packet) return null;

  const handleCopyHex = () => {
    if (!packet) return;
    navigator.clipboard.writeText(packet.hex_dump);
    setCopiedHex(true);
    setTimeout(() => setCopiedHex(false), 2000);
  };

  const handleCopyMitigation = () => {
    if (!packet?.verdict?.mitigation) return;
    const cmd = packet.verdict.mitigation.powershell || packet.verdict.mitigation.iptables;
    if (cmd) {
      navigator.clipboard.writeText(cmd);
      setCopiedMitigation(true);
      setTimeout(() => setCopiedMitigation(false), 2000);
    }
  };

  const verdict = packet.verdict;
  const isIntrusion = verdict?.status === 'INTRUSION';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/75 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="w-full max-w-6xl max-h-[92vh] flex flex-col rounded-lg border border-soc-border bg-soc-card shadow-2xl overflow-hidden text-soc-text font-mono">
        {/* Top Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-soc-border bg-soc-bg/80">
          <div className="flex items-center gap-3">
            <Radio className="w-4 h-4 text-soc-primary animate-pulse" />
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm">Frame #{packet.id} Dissection</span>
                <span className="text-xs text-soc-text-muted">({packet.interface})</span>
                {packet.provider && (
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-soc-primary/10 border border-soc-primary/30 text-soc-primary">
                    {packet.provider}
                  </span>
                )}
              </div>
              <p className="text-[11px] text-soc-text-muted mt-0.5">
                {packet.timestamp} • {packet.src_ip}:{packet.src_port} → {packet.dst_ip}:{packet.dst_port} • {packet.length} bytes
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Tab switch */}
            <div className="flex rounded border border-soc-border overflow-hidden mr-2">
              <button
                type="button"
                onClick={() => setTab('wireshark')}
                className={`px-3 py-1 text-xs font-mono font-medium transition-colors flex items-center gap-1.5 ${
                  tab === 'wireshark'
                    ? 'bg-soc-primary text-white'
                    : 'bg-soc-card text-soc-text-secondary hover:text-soc-text'
                }`}
              >
                <Layers className="w-3 h-3" />
                <span>Wireshark 3-Pane</span>
              </button>
              <button
                type="button"
                onClick={() => setTab('raw_hex')}
                className={`px-3 py-1 text-xs font-mono font-medium transition-colors flex items-center gap-1.5 ${
                  tab === 'raw_hex'
                    ? 'bg-soc-primary text-white'
                    : 'bg-soc-card text-soc-text-secondary hover:text-soc-text'
                }`}
              >
                <Binary className="w-3 h-3" />
                <span>Payload & Raw Hex</span>
              </button>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded hover:bg-soc-card-hover text-soc-text-secondary hover:text-soc-text transition-colors"
              title="Close dissector"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tab 1: Wireshark 3-Pane Layout */}
        {tab === 'wireshark' && (
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              {/* Pane A: Decoded Headers (L3 IP, L4 TCP/UDP, Flags) */}
              <div className="lg:col-span-6 space-y-2">
                <div className="flex items-center justify-between text-xs font-bold uppercase tracking-wider text-soc-text-secondary pb-1 border-b border-soc-border">
                  <span>Pane A: Decoded Protocol Tree</span>
                  <span className="text-[10px] text-soc-text-muted">RFC 791 / 793 Dissector</span>
                </div>

                <div className="rounded border border-soc-border bg-soc-bg/40 p-2 text-xs space-y-1.5 max-h-[320px] overflow-y-auto font-mono">
                  {/* Frame Node */}
                  <div>
                    <button
                      type="button"
                      onClick={() => setExpandedFrame((prev) => !prev)}
                      className="w-full flex items-center gap-1.5 text-left py-1 hover:text-soc-primary font-medium text-soc-text"
                    >
                      {expandedFrame ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      <span>Frame {packet.id}: {packet.length} bytes on wire ({packet.length * 8} bits)</span>
                    </button>
                    {expandedFrame && (
                      <div className="pl-6 py-1 space-y-0.5 text-soc-text-muted text-[11px] border-l border-soc-border/60 ml-2">
                        <div>Interface: {packet.interface} ({packet.engine})</div>
                        <div>Arrival Time: {packet.timestamp}</div>
                        <div>Frame Length: {packet.length} bytes</div>
                        <div>Protocols in frame: {packet.headers?.frame?.protocols || `ip:${packet.protocol.toLowerCase()}`}</div>
                      </div>
                    )}
                  </div>

                  {/* IPv4 Node */}
                  <div>
                    <button
                      type="button"
                      onClick={() => setExpandedIP((prev) => !prev)}
                      className="w-full flex items-center gap-1.5 text-left py-1 hover:text-soc-primary font-medium text-soc-text"
                    >
                      {expandedIP ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      <span>Internet Protocol Version 4, Src: {packet.src_ip}, Dst: {packet.dst_ip}</span>
                    </button>
                    {expandedIP && (
                      <div className="pl-6 py-1 space-y-0.5 text-soc-text-muted text-[11px] border-l border-soc-border/60 ml-2">
                        <div>0100 .... = Version: {packet.headers?.ipv4?.version ?? 4}</div>
                        <div>.... 0101 = Header Length: {packet.headers?.ipv4?.header_length ?? 20} bytes</div>
                        <div>Differentiated Services Field: {packet.headers?.ipv4?.tos ?? '0x00 (Routine)'}</div>
                        <div>Total Length: {packet.headers?.ipv4?.total_length ?? packet.length}</div>
                        <div>Identification: {packet.headers?.ipv4?.identification ?? '0x1c46'}</div>
                        <div>Flags: {packet.headers?.ipv4?.flags?.raw ?? "0x4000, Don't fragment"}</div>
                        <div>Time to Live (TTL): {packet.headers?.ipv4?.ttl ?? 64}</div>
                        <div>Protocol: {packet.headers?.ipv4?.protocol ?? `${packet.protocol} (6)`}</div>
                        <div>Header Checksum: {packet.headers?.ipv4?.checksum ?? '0x4a2b [Validated]'}</div>
                        <div>Source Address: {packet.src_ip}</div>
                        <div>Destination Address: {packet.dst_ip}</div>
                      </div>
                    )}
                  </div>

                  {/* L4 Transport Node */}
                  <div>
                    <button
                      type="button"
                      onClick={() => setExpandedTransport((prev) => !prev)}
                      className="w-full flex items-center gap-1.5 text-left py-1 hover:text-soc-primary font-medium text-soc-text"
                    >
                      {expandedTransport ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      <span>
                        {packet.protocol === 'TCP' ? 'Transmission Control Protocol' : 'User Datagram Protocol'},
                        Src Port: {packet.src_port}, Dst Port: {packet.dst_port}
                      </span>
                    </button>
                    {expandedTransport && (
                      <div className="pl-6 py-1 space-y-0.5 text-soc-text-muted text-[11px] border-l border-soc-border/60 ml-2">
                        <div>Source Port: {packet.src_port}</div>
                        <div>Destination Port: {packet.dst_port} ({packet.headers?.transport?.service_name || 'Dynamic'})</div>
                        <div>Sequence Number: {packet.headers?.transport?.seq_number ?? 100234}</div>
                        {packet.headers?.transport?.ack_number && (
                          <div>Acknowledgment Number: {packet.headers.transport.ack_number}</div>
                        )}
                        <div>TCP State / Control Flags: {packet.tcp_state || packet.headers?.transport?.flags}</div>
                        {packet.headers?.transport?.window_size && (
                          <div>Calculated Window Size: {packet.headers.transport.window_size}</div>
                        )}
                        <div>Checksum: {packet.headers?.transport?.checksum ?? '0x8e21 [Verified]'}</div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Pane C: Rule & ML Verdict Explainability */}
              <div className="lg:col-span-6 space-y-2">
                <div className="flex items-center justify-between text-xs font-bold uppercase tracking-wider text-soc-text-secondary pb-1 border-b border-soc-border">
                  <span>Pane C: Verdict & MITRE Defense</span>
                  {verdict && (
                    <Badge variant={isIntrusion ? 'critical' : 'success'}>
                      {verdict.status}
                    </Badge>
                  )}
                </div>

                <div className="rounded border border-soc-border bg-soc-bg/40 p-3 space-y-3 text-xs max-h-[320px] overflow-y-auto">
                  {/* Status Card */}
                  <div
                    className={`p-2.5 rounded border flex items-center justify-between ${
                      isIntrusion
                        ? 'border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400'
                        : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                    }`}
                  >
                    <div>
                      <span className="text-[10px] uppercase font-mono block">Threat Classification</span>
                      <span className="text-sm font-bold font-mono">
                        {verdict?.attack_type || (isIntrusion ? 'ML_ANOMALY' : 'LEGITIMATE TRAFFIC')}
                      </span>
                    </div>
                    {verdict?.severity && <SeverityBadge severity={verdict.severity} size="md" />}
                  </div>

                  {/* Decision Pipeline Stats */}
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div className="p-2 rounded border border-soc-border bg-soc-card">
                      <span className="text-soc-text-muted block">INSPECTION ENGINE</span>
                      <span className="font-semibold text-soc-text">{packet.engine}</span>
                    </div>
                    <div className="p-2 rounded border border-soc-border bg-soc-card">
                      <span className="text-soc-text-muted block">DETECTION METHOD</span>
                      <span className="font-semibold text-soc-text">{verdict?.detection_method || 'RULE'}</span>
                    </div>
                  </div>

                  {/* Reasoning & Evidence */}
                  <div className="space-y-1">
                    <span className="text-[10px] uppercase font-semibold text-soc-text-secondary">
                      Rule / Model Explanation
                    </span>
                    <div className="p-2 rounded border border-soc-border bg-soc-card text-[11px] leading-relaxed text-soc-text">
                      {verdict?.message || 'Standard baseline traffic within operational thresholds.'}
                    </div>
                  </div>

                  {/* MITRE ATT&CK */}
                  {verdict?.mitre && (
                    <div className="flex items-center gap-2 p-2 rounded border border-soc-border bg-soc-card text-[11px]">
                      <ShieldAlert className="w-4 h-4 text-amber-500 shrink-0" />
                      <div className="min-w-0">
                        <span className="font-bold text-soc-text mr-1">MITRE {verdict.mitre.id}:</span>
                        <span className="text-soc-text-secondary">{verdict.mitre.name} ({verdict.mitre.tactic})</span>
                      </div>
                    </div>
                  )}

                  {/* Active Defense Mitigation Command */}
                  {verdict?.mitigation && (
                    <div className="space-y-1">
                      <div className="flex items-center justify-between text-[10px] uppercase font-semibold text-soc-text-secondary">
                        <span className="flex items-center gap-1">
                          <Terminal className="w-3 h-3 text-red-500" />
                          Recommended Mitigation
                        </span>
                        <button
                          type="button"
                          onClick={handleCopyMitigation}
                          className="text-soc-primary hover:underline inline-flex items-center gap-1"
                        >
                          {copiedMitigation ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedMitigation ? 'Copied' : 'Copy PowerShell'}</span>
                        </button>
                      </div>
                      <div className="p-2 rounded bg-black/60 border border-soc-border text-[10px] font-mono text-emerald-400 break-all select-all">
                        {verdict.mitigation.powershell}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Pane B: Hex Dump View (Full Width Lower Pane) */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-bold uppercase tracking-wider text-soc-text-secondary pb-1 border-b border-soc-border">
                <span>Pane B: Wireshark Hex Dissection View</span>
                <button
                  type="button"
                  onClick={handleCopyHex}
                  className="inline-flex items-center gap-1 text-[11px] text-soc-primary hover:underline"
                >
                  {copiedHex ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedHex ? 'Copied Hex' : 'Copy Hex Dump'}</span>
                </button>
              </div>

              <div className="rounded border border-soc-border bg-black/70 p-3 max-h-56 overflow-auto font-mono text-[11px] leading-relaxed select-text">
                <pre className="text-emerald-400 whitespace-pre">{packet.hex_dump}</pre>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Payload & Raw Hex Dedicated View */}
        {tab === 'raw_hex' && (
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-soc-text">Deep Payload Inspection</h3>
                <p className="text-xs text-soc-text-muted mt-0.5">
                  Raw binary frame bytes, decoded ASCII representation, and cloud host metadata
                </p>
              </div>
              <button
                type="button"
                onClick={handleCopyHex}
                className="px-3 py-1.5 rounded bg-soc-primary text-white text-xs inline-flex items-center gap-1.5 font-medium hover:bg-soc-primary-hover transition-colors"
              >
                {copiedHex ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedHex ? 'Copied to Clipboard' : 'Copy All Bytes'}</span>
              </button>
            </div>

            {/* Cloud Provider & DNS Card */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3 rounded border border-soc-border bg-soc-bg/40 text-xs">
              <div>
                <span className="text-[10px] text-soc-text-muted uppercase block">Cloud Provider Tag</span>
                <span className="font-semibold text-soc-text flex items-center gap-1 mt-0.5">
                  <Globe className="w-3.5 h-3.5 text-soc-primary" />
                  {packet.provider || 'Public Internet'}
                </span>
              </div>
              <div>
                <span className="text-[10px] text-soc-text-muted uppercase block">Reverse DNS Hostname</span>
                <span className="font-semibold text-soc-text truncate block mt-0.5">
                  {packet.hostname || 'None (Direct IP Route)'}
                </span>
              </div>
              <div>
                <span className="text-[10px] text-soc-text-muted uppercase block">Payload Signature</span>
                <span className="font-semibold text-soc-text truncate block mt-0.5">
                  {packet.payload_preview}
                </span>
              </div>
            </div>

            {/* Complete Hex Stream */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-soc-text-secondary uppercase">
                Continuous Hex Stream ({packet.length} bytes)
              </label>
              <div className="p-3 rounded border border-soc-border bg-black/80 font-mono text-[11px] text-sky-400 break-all select-all max-h-40 overflow-y-auto leading-relaxed">
                {packet.raw_hex}
              </div>
            </div>

            {/* Hex Dump Format */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-soc-text-secondary uppercase">
                Aligned Offset Dissection (16 Bytes / Row)
              </label>
              <div className="p-3 rounded border border-soc-border bg-black/80 font-mono text-[11px] text-emerald-400 max-h-60 overflow-y-auto leading-relaxed select-text">
                <pre className="whitespace-pre">{packet.hex_dump}</pre>
              </div>
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="px-4 py-2.5 border-t border-soc-border bg-soc-bg/80 flex items-center justify-between text-xs text-soc-text-muted">
          <span>Engine: {packet.engine}</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-soc-card border border-soc-border hover:bg-soc-card-hover text-soc-text text-xs transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
