import { useState } from 'react';
import { LiveNicWorkbench } from '../components/traffic/LiveNicWorkbench';
import { TrafficInspector } from '../components/traffic/TrafficInspector';
import { SimulationConsole } from '../components/simulation/SimulationConsole';
import { Radio, Activity, Swords } from 'lucide-react';

type Tab = 'sniffer' | 'inspect' | 'simulate';

export default function TrafficPage() {
  const [tab, setTab] = useState<Tab>('sniffer');

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold text-soc-text flex items-center gap-2">
          <span>Live Traffic & Network Wire Workbench</span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500 border border-emerald-500/30 font-bold uppercase">
            Enterprise Ingestion
          </span>
        </h1>
        <p className="text-sm text-soc-text-secondary mt-0.5 font-mono">
          Physical NIC packet capture, Wireshark-style deep dissection, and live telemetry analysis
        </p>
      </div>

      {/* Tab bar */}
      <div className="flex border-b border-soc-border">
        {([
          { id: 'sniffer' as Tab, label: 'Live NIC Sniffer & Wirefeed', icon: Radio },
          { id: 'inspect' as Tab, label: 'Manual Flow Inspector', icon: Activity },
          { id: 'simulate' as Tab, label: 'Attack Simulation', icon: Swords },
        ] as const).map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors inline-flex items-center gap-2 ${
              tab === id
                ? 'border-soc-primary text-soc-primary font-semibold'
                : 'border-transparent text-soc-text-secondary hover:text-soc-text'
            }`}
          >
            <Icon className="w-4 h-4" />
            <span>{label}</span>
          </button>
        ))}
      </div>

      {tab === 'sniffer' && <LiveNicWorkbench />}
      {tab === 'inspect' && <TrafficInspector />}
      {tab === 'simulate' && <SimulationConsole />}
    </div>
  );
}

