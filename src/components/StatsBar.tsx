import { Shield, Activity, Ban, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';

interface StatsBarProps {
  stats: {
    totalPackets: number;
    threatsDetected: number;
    blocked: number;
    falsePositives: number;
    truePositives: number;
  };
}

export function StatsBar({ stats }: StatsBarProps) {
  const items = [
    { icon: Activity, label: 'Packets', value: stats.totalPackets, color: 'text-foreground' },
    { icon: AlertTriangle, label: 'Threats', value: stats.threatsDetected, color: 'text-warning' },
    { icon: Ban, label: 'Blocked', value: stats.blocked, color: 'text-danger' },
    { icon: CheckCircle, label: 'True+', value: stats.truePositives, color: 'text-safe' },
    { icon: XCircle, label: 'False+', value: stats.falsePositives, color: 'text-info' },
  ];

  const accuracy = stats.truePositives + stats.falsePositives > 0
    ? ((stats.truePositives / (stats.truePositives + stats.falsePositives)) * 100).toFixed(1)
    : '—';

  return (
    <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
      {items.map(({ icon: Icon, label, value, color }) => (
        <div key={label} className="rounded-md border border-glow bg-card p-3 flex flex-col items-center gap-1">
          <Icon className={`w-4 h-4 ${color}`} />
          <span className="text-lg font-bold font-display">{value}</span>
          <span className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</span>
        </div>
      ))}
      <div className="rounded-md border border-glow bg-card p-3 flex flex-col items-center gap-1">
        <Shield className="w-4 h-4 text-primary" />
        <span className="text-lg font-bold font-display">{accuracy}%</span>
        <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Accuracy</span>
      </div>
    </div>
  );
}
