// components/traffic/WireFilterBar.tsx — Wireshark-like quick search, filter bar & audio toggle.

import React, { useState } from 'react';
import { Search, X, Volume2, VolumeX, Pause, Play, HelpCircle } from 'lucide-react';

interface Props {
  filterQuery: string;
  onFilterChange: (query: string) => void;
  audioEnabled: boolean;
  onToggleAudio: () => void;
  isPaused: boolean;
  onTogglePause: () => void;
  packetCount: number;
  filteredCount: number;
}

export const WireFilterBar: React.FC<Props> = ({
  filterQuery,
  onFilterChange,
  audioEnabled,
  onToggleAudio,
  isPaused,
  onTogglePause,
  packetCount,
  filteredCount,
}) => {
  const [showHelp, setShowHelp] = useState(false);

  const presets = [
    { label: 'All Wirefeed', query: '' },
    { label: '🚨 Intrusions Only', query: 'verdict:intrusion' },
    { label: '🔒 HTTPS / 443', query: 'port:443' },
    { label: '🌐 DNS / 53', query: 'port:53' },
    { label: '⚡ TCP SYN / Scans', query: 'proto:tcp state:syn' },
    { label: '⚠️ Critical Only', query: 'severity:critical' },
    { label: '☁️ Google Cloud', query: 'host:google' },
    { label: '🛡️ Cloudflare', query: 'host:cloudflare' },
  ];

  return (
    <div className="space-y-2">
      {/* Search Input Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
        <div className="relative flex-1">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-soc-text-muted">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={filterQuery}
            onChange={(e) => onFilterChange(e.target.value)}
            placeholder='Apply display filter... (e.g. proto:tcp, port:443, host:google, verdict:intrusion, rule:exfil)'
            className="w-full pl-9 pr-9 py-2 rounded bg-soc-card border border-soc-border text-xs font-mono text-soc-text placeholder:text-soc-text-muted focus:outline-none focus:border-soc-primary focus:ring-1 focus:ring-soc-primary transition-all"
          />
          {filterQuery && (
            <button
              onClick={() => onFilterChange('')}
              className="absolute inset-y-0 right-0 pr-3 flex items-center text-soc-text-muted hover:text-soc-text"
              title="Clear filter"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          {/* Pause / Resume Feed */}
          <button
            type="button"
            onClick={onTogglePause}
            className={`px-3 py-2 rounded border text-xs font-mono font-medium inline-flex items-center gap-1.5 transition-colors ${
              isPaused
                ? 'border-amber-500/40 bg-amber-500/10 text-amber-500 hover:bg-amber-500/20'
                : 'border-soc-border bg-soc-card hover:bg-soc-card-hover text-soc-text-secondary'
            }`}
            title={isPaused ? 'Resume live autoscroll' : 'Pause wirefeed autoscroll'}
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? 'Paused' : 'Auto-Scroll'}</span>
          </button>

          {/* Audio Chime Alarm Toggle */}
          <button
            type="button"
            onClick={onToggleAudio}
            className={`px-3 py-2 rounded border text-xs font-mono font-medium inline-flex items-center gap-1.5 transition-colors ${
              audioEnabled
                ? 'border-red-500/40 bg-red-500/10 text-red-500 hover:bg-red-500/20'
                : 'border-soc-border bg-soc-card hover:bg-soc-card-hover text-soc-text-muted'
            }`}
            title={audioEnabled ? 'Audible SOC Alarm: Enabled (chimes on CRITICAL threats)' : 'Audible Alarm: Muted'}
          >
            {audioEnabled ? <Volume2 className="w-3.5 h-3.5 text-red-500" /> : <VolumeX className="w-3.5 h-3.5" />}
            <span className="hidden sm:inline">{audioEnabled ? 'Alarm On' : 'Alarm Muted'}</span>
          </button>

          {/* Syntax Help Toggle */}
          <button
            type="button"
            onClick={() => setShowHelp((prev) => !prev)}
            className={`p-2 rounded border text-xs transition-colors ${
              showHelp
                ? 'border-soc-primary bg-soc-primary/10 text-soc-primary'
                : 'border-soc-border bg-soc-card hover:bg-soc-card-hover text-soc-text-muted'
            }`}
            title="Wireshark filter syntax guide"
          >
            <HelpCircle className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Syntax Guide Dropdown Panel */}
      {showHelp && (
        <div className="p-3 rounded border border-soc-border bg-soc-bg/60 text-xs font-mono space-y-2 text-soc-text-secondary">
          <div className="flex items-center justify-between text-soc-text font-semibold text-[11px] uppercase tracking-wider">
            <span>Wireshark-Style Display Filter Syntax</span>
            <button onClick={() => setShowHelp(false)} className="text-soc-text-muted hover:text-soc-text">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 text-[11px]">
            <div className="p-1.5 rounded bg-soc-card border border-soc-border">
              <span className="font-semibold text-soc-primary">proto:&lt;tcp|udp|icmp&gt;</span>
              <p className="text-soc-text-muted mt-0.5">Filter by L4 transport protocol</p>
            </div>
            <div className="p-1.5 rounded bg-soc-card border border-soc-border">
              <span className="font-semibold text-soc-primary">port:&lt;num&gt;</span>
              <p className="text-soc-text-muted mt-0.5">Matches source or destination port</p>
            </div>
            <div className="p-1.5 rounded bg-soc-card border border-soc-border">
              <span className="font-semibold text-soc-primary">host:&lt;name|ip&gt;</span>
              <p className="text-soc-text-muted mt-0.5">Matches domain, provider, or IP prefix</p>
            </div>
            <div className="p-1.5 rounded bg-soc-card border border-soc-border">
              <span className="font-semibold text-soc-primary">verdict:&lt;intrusion|normal&gt;</span>
              <p className="text-soc-text-muted mt-0.5">Filter detection classification</p>
            </div>
            <div className="p-1.5 rounded bg-soc-card border border-soc-border">
              <span className="font-semibold text-soc-primary">severity:&lt;critical|high|...&gt;</span>
              <p className="text-soc-text-muted mt-0.5">Filter by severity rating</p>
            </div>
            <div className="p-1.5 rounded bg-soc-card border border-soc-border">
              <span className="font-semibold text-soc-primary">rule:&lt;exfil|dos|port_scan&gt;</span>
              <p className="text-soc-text-muted mt-0.5">Filter specific deterministic rule match</p>
            </div>
          </div>
        </div>
      )}

      {/* Preset Quick Chips */}
      <div className="flex items-center justify-between gap-2 overflow-x-auto pb-1 text-xs font-mono">
        <div className="flex items-center gap-1.5 shrink-0">
          <span className="text-[10px] text-soc-text-muted uppercase tracking-wider mr-1">Presets:</span>
          {presets.map((p, idx) => {
            const isActive = filterQuery.toLowerCase() === p.query.toLowerCase();
            return (
              <button
                key={idx}
                type="button"
                onClick={() => onFilterChange(p.query)}
                className={`px-2 py-1 rounded text-[11px] font-mono transition-colors whitespace-nowrap border ${
                  isActive
                    ? 'border-soc-primary bg-soc-primary/15 text-soc-primary font-semibold shadow-sm'
                    : 'border-soc-border bg-soc-card hover:bg-soc-card-hover text-soc-text-secondary'
                }`}
              >
                {p.label}
              </button>
            );
          })}
        </div>

        <div className="text-[11px] text-soc-text-muted shrink-0">
          Showing <span className="font-semibold text-soc-text">{filteredCount}</span> of {packetCount} frames
        </div>
      </div>
    </div>
  );
};
