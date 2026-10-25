// components/traffic/LiveNicWorkbench.tsx — Enterprise-Grade Live NIC Sniffer & Wirefeed Monitoring Workbench.

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { api } from '../../services/api';
import { useToast } from '../../context/ToastContext';
import { audioAlert } from '../../utils/audioChime';
import { LiveBandwidthChart } from './LiveBandwidthChart';
import { WireFilterBar } from './WireFilterBar';
import { PacketDissector } from './PacketDissector';
import { SeverityBadge } from '../common/SeverityBadge';
import type {
  CapturedPacket,
  SnifferStatus,
  NetworkInterface,
  TimelineMetricPoint,
} from '../../types';
import {
  Play,
  Square,
  Trash2,
  Radio,
  ShieldCheck,
  ShieldAlert,
  Server,
  ChevronRight,
} from 'lucide-react';

export const LiveNicWorkbench: React.FC = () => {
  const { addToast } = useToast();

  const [status, setStatus] = useState<SnifferStatus | null>(null);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('');
  const [packets, setPackets] = useState<CapturedPacket[]>([]);
  const [metrics, setMetrics] = useState<TimelineMetricPoint[]>([]);

  const [isStarting, setIsStarting] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [audioAlarmEnabled, setAudioAlarmEnabled] = useState(true);
  const [filterQuery, setFilterQuery] = useState('');
  const [inspectedPacket, setInspectedPacket] = useState<CapturedPacket | null>(null);

  const lastSeenPktIdRef = useRef<number>(0);
  const pollTimerRef = useRef<any>(null);

  // Load initial status & interface list
  const loadInitialData = useCallback(async () => {
    try {
      const [statusRes, ifaceRes] = await Promise.all([
        api.snifferStatus(),
        api.snifferInterfaces(),
      ]);
      setStatus(statusRes);
      setInterfaces(ifaceRes.interfaces);

      if (ifaceRes.interfaces.length > 0) {
        // Prioritize default active route
        const defaultIf = ifaceRes.interfaces.find((i) => i.is_default);
        setSelectedInterface(defaultIf ? defaultIf.name : ifaceRes.interfaces[0].name);
      }
    } catch {
      // Backend starting or temporary network blip
    }
  }, []);

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);

  // Polling loop for live packets & timeline metrics
  const pollSnifferData = useCallback(async () => {
    try {
      const [statusRes, pktsRes, metricsRes] = await Promise.all([
        api.snifferStatus(),
        api.snifferPackets(150, 0),
        api.snifferMetrics(),
      ]);

      setStatus(statusRes);
      setMetrics(metricsRes.metrics || []);

      if (!isPaused) {
        const newPackets = pktsRes.packets || [];
        setPackets(newPackets);

        // Check for new critical threats to trigger audio chime
        if (newPackets.length > 0) {
          const newest = newPackets[0];
          if (newest.id > lastSeenPktIdRef.current) {
            lastSeenPktIdRef.current = newest.id;

            // Trigger chime if critical intrusion detected
            if (audioAlarmEnabled) {
              const hasCritical = newPackets.slice(0, 5).some(
                (p) =>
                  p.verdict?.severity === 'CRITICAL' ||
                  p.verdict?.attack_type === 'DATA_EXFILTRATION' ||
                  p.verdict?.attack_type === 'DOS'
              );
              if (hasCritical) {
                audioAlert.play('critical');
              }
            }
          }
        }
      }
    } catch {
      // Ignore poll transient error
    }
  }, [isPaused, audioAlarmEnabled]);

  useEffect(() => {
    pollSnifferData();
    pollTimerRef.current = setInterval(pollSnifferData, 1200);
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [pollSnifferData]);

  // Toggle Sniffing Action — NEVER DISABLED
  const handleToggleSniffing = async () => {
    setIsStarting(true);
    try {
      if (status?.is_sniffing) {
        const res = await api.stopSniffer();
        setStatus(res);
        addToast('info', 'NIC Sniffer Stopped', 'Live packet ingestion suspended.');
      } else {
        const res = await api.startSniffer(selectedInterface);
        setStatus(res);
        addToast(
          'success',
          'NIC Capture Active',
          `Ingesting via ${res.engine_display_name} on ${res.active_interface?.name || 'NIC'}`
        );
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Sniffer control failed';
      addToast('error', 'Capture Engine Error', msg);
    } finally {
      setIsStarting(false);
    }
  };

  const handleClearBuffer = async () => {
    try {
      await api.clearSnifferPackets();
      setPackets([]);
      addToast('info', 'Buffer Cleared', 'Captured frame ring buffer purged.');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Clear failed';
      addToast('error', 'Error', msg);
    }
  };

  // Wireshark-like Filter Engine
  const filteredPackets = useMemo(() => {
    if (!filterQuery.trim()) return packets;

    const tokens = filterQuery.toLowerCase().split(/\s+/).filter(Boolean);

    return packets.filter((pkt) => {
      return tokens.every((token) => {
        if (token.startsWith('proto:')) {
          const proto = token.split(':')[1];
          return pkt.protocol.toLowerCase().includes(proto);
        }
        if (token.startsWith('port:')) {
          const port = parseInt(token.split(':')[1], 10);
          return pkt.src_port === port || pkt.dst_port === port;
        }
        if (token.startsWith('host:')) {
          const term = token.split(':')[1];
          return (
            (pkt.hostname && pkt.hostname.toLowerCase().includes(term)) ||
            (pkt.provider && pkt.provider.toLowerCase().includes(term)) ||
            pkt.dst_ip.toLowerCase().includes(term) ||
            pkt.src_ip.toLowerCase().includes(term)
          );
        }
        if (token.startsWith('verdict:')) {
          const term = token.split(':')[1];
          return pkt.verdict?.status.toLowerCase().includes(term);
        }
        if (token.startsWith('severity:')) {
          const term = token.split(':')[1];
          return pkt.verdict?.severity.toLowerCase() === term;
        }
        if (token.startsWith('rule:')) {
          const term = token.split(':')[1];
          return pkt.verdict?.attack_type?.toLowerCase().includes(term);
        }
        if (token.startsWith('state:')) {
          const term = token.split(':')[1];
          return pkt.tcp_state?.toLowerCase().includes(term);
        }

        // Generic free-text search across all fields
        return (
          pkt.src_ip.includes(token) ||
          pkt.dst_ip.includes(token) ||
          pkt.src_port.toString().includes(token) ||
          pkt.dst_port.toString().includes(token) ||
          pkt.protocol.toLowerCase().includes(token) ||
          (pkt.provider && pkt.provider.toLowerCase().includes(token)) ||
          (pkt.hostname && pkt.hostname.toLowerCase().includes(token)) ||
          (pkt.verdict?.attack_type && pkt.verdict.attack_type.toLowerCase().includes(token)) ||
          pkt.payload_preview.toLowerCase().includes(token)
        );
      });
    });
  }, [packets, filterQuery]);

  // Provider badge renderer
  const renderProviderBadge = (pkt: CapturedPacket) => {
    if (!pkt.provider && !pkt.hostname) {
      return <span className="text-[11px] text-soc-text-muted font-mono">{pkt.dst_ip}</span>;
    }

    const tag = pkt.provider_tag || '';
    let badgeColor = 'bg-slate-500/10 text-slate-400 border-slate-500/20';

    if (tag === 'google') badgeColor = 'bg-blue-500/10 text-blue-500 border-blue-500/30';
    else if (tag === 'cloudflare') badgeColor = 'bg-amber-500/10 text-amber-500 border-amber-500/30';
    else if (tag === 'aws') badgeColor = 'bg-orange-500/10 text-orange-500 border-orange-500/30';
    else if (tag === 'azure') badgeColor = 'bg-cyan-500/10 text-cyan-500 border-cyan-500/30';
    else if (tag === 'internal') badgeColor = 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30';

    return (
      <div className="flex flex-col min-w-0">
        <div className="flex items-center gap-1.5 truncate">
          <span className="font-mono text-xs text-soc-text font-medium">{pkt.dst_ip}</span>
          {pkt.provider && (
            <span className={`text-[10px] px-1.5 py-0.2 rounded border font-mono ${badgeColor}`}>
              {pkt.provider}
            </span>
          )}
        </div>
        {pkt.hostname && (
          <span className="text-[10px] text-soc-text-muted truncate font-mono">
            {pkt.hostname}
          </span>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-4">
      {/* Top Controls & Status Bar */}
      <div className="p-4 rounded-lg border border-soc-border bg-soc-card shadow-sm space-y-3">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Active Engine & Gateway Indicator */}
          <div className="flex items-center gap-3">
            <div
              className={`p-2 rounded-lg border ${
                status?.is_sniffing
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-500 animate-pulse'
                  : 'bg-soc-bg border-soc-border text-soc-text-muted'
              }`}
            >
              <Radio className="w-5 h-5" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-soc-text tracking-tight font-mono">
                  {status?.engine_display_name || 'Dual-Engine Physical NIC Sniffer'}
                </h2>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-bold ${
                    status?.is_sniffing
                      ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                      : 'bg-soc-bg text-soc-text-muted border border-soc-border'
                  }`}
                >
                  {status?.is_sniffing ? '● CAPTURING' : '○ IDLE'}
                </span>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded border font-mono ${
                    status?.is_elevated
                      ? 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/30'
                      : 'bg-slate-500/10 text-slate-500 dark:text-slate-400 border-slate-500/30'
                  }`}
                >
                  {status?.is_elevated ? 'Elevated Administrator' : 'Zero-Privilege (User Mode)'}
                </span>
              </div>
              <p className="text-xs text-soc-text-secondary mt-0.5 font-mono">
                Active Route: <span className="text-soc-text font-semibold">{status?.active_interface?.name || 'Wi-Fi'}</span> ({status?.default_route_ip || 'Auto-Gateway'}) • RFC 791/793 Frame Dissection Active
              </p>
            </div>
          </div>

          {/* Interface Selector & Action Buttons */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Interface Picker */}
            <div className="flex items-center gap-1.5">
              <Server className="w-4 h-4 text-soc-text-muted" />
              <select
                value={selectedInterface}
                onChange={(e) => setSelectedInterface(e.target.value)}
                disabled={status?.is_sniffing}
                className="px-2.5 py-1.5 rounded bg-soc-bg border border-soc-border text-xs font-mono text-soc-text focus:outline-none focus:border-soc-primary disabled:opacity-60"
              >
                {interfaces.map((iface) => (
                  <option key={iface.name} value={iface.name}>
                    {iface.name} ({iface.ip}){iface.is_default ? ' [Default Gateway]' : ''}
                  </option>
                ))}
              </select>
            </div>

            {/* Start/Stop Button — NEVER DISABLED */}
            <button
              type="button"
              onClick={handleToggleSniffing}
              disabled={isStarting}
              className={`px-4 py-2 rounded text-xs font-mono font-bold inline-flex items-center gap-2 transition-all shadow-sm ${
                status?.is_sniffing
                  ? 'bg-red-600 hover:bg-red-700 text-white'
                  : 'bg-soc-primary hover:bg-soc-primary-hover text-white'
              }`}
            >
              {status?.is_sniffing ? (
                <>
                  <Square className="w-3.5 h-3.5 fill-current" />
                  <span>Stop Sniffing</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Start NIC Sniffing</span>
                </>
              )}
            </button>

            {/* Clear Button */}
            <button
              type="button"
              onClick={handleClearBuffer}
              className="px-3 py-2 rounded border border-soc-border bg-soc-card hover:bg-soc-card-hover text-soc-text-secondary hover:text-soc-text text-xs font-mono transition-colors"
              title="Clear captured packets"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Real-time Streaming Bandwidth & PPS Timeline Chart */}
      <LiveBandwidthChart metrics={metrics} status={status} />

      {/* Wireshark Quick Filter & Wire Search Bar */}
      <WireFilterBar
        filterQuery={filterQuery}
        onFilterChange={setFilterQuery}
        audioEnabled={audioAlarmEnabled}
        onToggleAudio={() => setAudioAlarmEnabled((prev) => !prev)}
        isPaused={isPaused}
        onTogglePause={() => setIsPaused((prev) => !prev)}
        packetCount={packets.length}
        filteredCount={filteredPackets.length}
      />

      {/* Live Wirefeed Packet Table */}
      <div className="rounded-lg border border-soc-border bg-soc-card shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-soc-border bg-soc-bg/50 text-[11px] uppercase tracking-wider text-soc-text-muted">
                <th className="py-2.5 px-3 w-16">#</th>
                <th className="py-2.5 px-3 w-28">Time</th>
                <th className="py-2.5 px-3">Source (Local)</th>
                <th className="py-2.5 px-3">Destination (Remote Host)</th>
                <th className="py-2.5 px-3 w-20">Proto</th>
                <th className="py-2.5 px-3 w-32">State / Flags</th>
                <th className="py-2.5 px-3 w-20">Bytes</th>
                <th className="py-2.5 px-3">Detection Verdict</th>
                <th className="py-2.5 px-3 text-right w-24">Dissect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border/60">
              {filteredPackets.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-16 text-center text-soc-text-muted">
                    <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    <p className="text-xs">
                      {status?.is_sniffing
                        ? 'Monitoring physical interface... Packets will populate in real time.'
                        : 'Capture is currently idle. Click "Start NIC Sniffing" above to begin ingestion.'}
                    </p>
                  </td>
                </tr>
              ) : (
                filteredPackets.map((pkt) => {
                  const isIntrusion = pkt.verdict?.status === 'INTRUSION';
                  return (
                    <tr
                      key={pkt.id}
                      onClick={() => setInspectedPacket(pkt)}
                      className={`cursor-pointer transition-colors hover:bg-soc-card-hover group ${
                        isIntrusion
                          ? 'bg-red-500/5 hover:bg-red-500/10'
                          : 'hover:bg-soc-card-hover'
                      }`}
                    >
                      <td className="py-2 px-3 text-soc-text-muted font-bold">{pkt.id}</td>
                      <td className="py-2 px-3 text-soc-text-secondary whitespace-nowrap">{pkt.timestamp}</td>
                      <td className="py-2 px-3 text-soc-text">
                        {pkt.src_ip}:{pkt.src_port}
                      </td>
                      <td className="py-2 px-3">
                        {renderProviderBadge(pkt)}
                      </td>
                      <td className="py-2 px-3">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            pkt.protocol === 'TCP'
                              ? 'bg-blue-500/10 text-blue-500'
                              : pkt.protocol === 'UDP'
                              ? 'bg-amber-500/10 text-amber-500'
                              : 'bg-emerald-500/10 text-emerald-500'
                          }`}
                        >
                          {pkt.protocol}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-soc-text-secondary truncate max-w-[140px]">
                        {pkt.tcp_state || 'ESTABLISHED'}
                      </td>
                      <td className="py-2 px-3 text-soc-text-muted">{pkt.length} B</td>
                      <td className="py-2 px-3">
                        <div className="flex items-center gap-2">
                          {isIntrusion ? (
                            <div className="flex items-center gap-1.5 text-red-600 dark:text-red-400 font-bold">
                              <ShieldAlert className="w-3.5 h-3.5 text-red-500 shrink-0" />
                              <span>{pkt.verdict?.attack_type || 'ANOMALY'}</span>
                            </div>
                          ) : (
                            <span className="text-emerald-600 dark:text-emerald-400 font-medium">
                              NORMAL
                            </span>
                          )}
                          {pkt.verdict?.severity && (
                            <SeverityBadge severity={pkt.verdict.severity} size="sm" />
                          )}
                        </div>
                      </td>
                      <td className="py-2 px-3 text-right">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setInspectedPacket(pkt);
                          }}
                          className="px-2 py-1 rounded bg-soc-bg border border-soc-border hover:border-soc-primary text-soc-primary text-[11px] font-medium inline-flex items-center gap-1 opacity-80 group-hover:opacity-100 transition-all"
                        >
                          <span>Dissect</span>
                          <ChevronRight className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Deep Packet Inspector & Hex Dissector Modal */}
      {inspectedPacket && (
        <PacketDissector
          packet={inspectedPacket}
          onClose={() => setInspectedPacket(null)}
        />
      )}
    </div>
  );
};
