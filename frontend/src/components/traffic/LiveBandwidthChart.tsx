// components/traffic/LiveBandwidthChart.tsx — Real-time Throughput, PPS & Threat Timeline Chart.

import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  Line,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';
import type { TimelineMetricPoint, SnifferStatus } from '../../types';
import { ArrowDownLeft, ArrowUpRight, Zap, ShieldAlert, Cpu } from 'lucide-react';

interface Props {
  metrics: TimelineMetricPoint[];
  status: SnifferStatus | null;
}

export const LiveBandwidthChart: React.FC<Props> = ({ metrics, status }) => {
  const latest = metrics[metrics.length - 1];

  // Tooltip formatter
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload as TimelineMetricPoint;
      return (
        <div className="p-2.5 rounded bg-soc-card border border-soc-border shadow-xl text-xs font-mono space-y-1 z-50">
          <div className="font-semibold text-soc-text text-[11px] border-b border-soc-border/60 pb-1 mb-1">
            Time: {label}
          </div>
          <div className="flex items-center justify-between gap-4 text-emerald-600 dark:text-emerald-400">
            <span>Ingress:</span>
            <span className="font-bold">{data.kbps_in.toFixed(2)} KB/s</span>
          </div>
          <div className="flex items-center justify-between gap-4 text-sky-600 dark:text-sky-400">
            <span>Egress:</span>
            <span className="font-bold">{data.kbps_out.toFixed(2)} KB/s</span>
          </div>
          <div className="flex items-center justify-between gap-4 text-amber-600 dark:text-amber-400">
            <span>Rate:</span>
            <span className="font-bold">{data.pps} PPS</span>
          </div>
          {data.alerts > 0 && (
            <div className="pt-1 border-t border-red-500/30 flex items-center justify-between gap-4 text-red-600 dark:text-red-400 font-bold">
              <span>Threats:</span>
              <span>{data.alerts} Intercepted ({data.severity})</span>
            </div>
          )}
        </div>
      );
    }
    return null;
  };

  // Find threat points to highlight
  const threatPoints = metrics.filter((m) => m.alerts > 0);

  return (
    <div className="rounded border border-soc-border bg-soc-card overflow-hidden">
      {/* Metric Stat Tiles Banner */}
      <div className="grid grid-cols-2 sm:grid-cols-5 divide-x divide-y sm:divide-y-0 divide-soc-border border-b border-soc-border bg-soc-bg/30">
        <div className="p-3">
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-soc-text-secondary uppercase">
            <ArrowDownLeft className="w-3.5 h-3.5 text-emerald-500" />
            <span>Ingress (In)</span>
          </div>
          <div className="text-lg font-bold font-mono text-soc-text mt-0.5">
            {(latest?.kbps_in ?? status?.current_throughput_kbps_in ?? 0).toFixed(1)} <span className="text-xs text-soc-text-muted font-normal">KB/s</span>
          </div>
        </div>

        <div className="p-3">
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-soc-text-secondary uppercase">
            <ArrowUpRight className="w-3.5 h-3.5 text-sky-500" />
            <span>Egress (Out)</span>
          </div>
          <div className="text-lg font-bold font-mono text-soc-text mt-0.5">
            {(latest?.kbps_out ?? status?.current_throughput_kbps_out ?? 0).toFixed(1)} <span className="text-xs text-soc-text-muted font-normal">KB/s</span>
          </div>
        </div>

        <div className="p-3">
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-soc-text-secondary uppercase">
            <Zap className="w-3.5 h-3.5 text-amber-500" />
            <span>Packet Rate</span>
          </div>
          <div className="text-lg font-bold font-mono text-soc-text mt-0.5">
            {latest?.pps ?? status?.current_pps ?? 0} <span className="text-xs text-soc-text-muted font-normal">PPS</span>
          </div>
        </div>

        <div className="p-3">
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-soc-text-secondary uppercase">
            <Cpu className="w-3.5 h-3.5 text-indigo-500" />
            <span>Wire Frames</span>
          </div>
          <div className="text-lg font-bold font-mono text-soc-text mt-0.5">
            {(status?.total_packets ?? 0).toLocaleString()}
          </div>
        </div>

        <div className="p-3 col-span-2 sm:col-span-1">
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-soc-text-secondary uppercase">
            <ShieldAlert className="w-3.5 h-3.5 text-red-500" />
            <span>Threats Flagged</span>
          </div>
          <div className="text-lg font-bold font-mono text-red-600 dark:text-red-400 mt-0.5">
            {(status?.total_intrusions ?? 0).toLocaleString()}
          </div>
        </div>
      </div>

      {/* Chart Canvas */}
      <div className="p-3">
        <div className="flex items-center justify-between text-xs font-mono text-soc-text-secondary mb-2">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500 inline-block" />
              Ingress Throughput (KB/s)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-sky-500 inline-block" />
              Egress Throughput (KB/s)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-0.5 bg-amber-400 inline-block" />
              PPS (Right Axis)
            </span>
          </div>
          {threatPoints.length > 0 && (
            <div className="flex items-center gap-1.5 text-red-500 font-semibold animate-pulse">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              <span>{threatPoints.length} Threat Markers on Timeline</span>
            </div>
          )}
        </div>

        <div className="h-44 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={metrics} margin={{ top: 8, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="ingressGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="egressGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#0284c7" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#0284c7" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="time"
                stroke="currentColor"
                className="text-soc-text-muted text-[10px] font-mono"
                tickLine={false}
                axisLine={{ stroke: 'var(--soc-border, #334155)', opacity: 0.5 }}
                interval={Math.max(1, Math.floor(metrics.length / 6))}
              />
              <YAxis
                yAxisId="left"
                stroke="currentColor"
                className="text-soc-text-muted text-[10px] font-mono"
                tickLine={false}
                axisLine={false}
                unit="K"
              />
              <YAxis
                yAxisId="right"
                orientation="right"
                stroke="currentColor"
                className="text-amber-500/70 text-[10px] font-mono"
                tickLine={false}
                axisLine={false}
              />
              <Tooltip content={<CustomTooltip />} />
              <Area
                yAxisId="left"
                type="monotone"
                dataKey="kbps_in"
                stroke="#10b981"
                strokeWidth={1.8}
                fillOpacity={1}
                fill="url(#ingressGrad)"
                isAnimationActive={false}
              />
              <Area
                yAxisId="left"
                type="monotone"
                dataKey="kbps_out"
                stroke="#0284c7"
                strokeWidth={1.8}
                fillOpacity={1}
                fill="url(#egressGrad)"
                isAnimationActive={false}
              />
              <Line
                yAxisId="right"
                type="monotone"
                dataKey="pps"
                stroke="#f59e0b"
                strokeWidth={1.2}
                dot={false}
                strokeDasharray="2 2"
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};
