import { ThreatLevel } from '@/lib/network-engine';

interface StatusIndicatorProps {
  level: ThreatLevel;
  size?: 'sm' | 'md';
  showLabel?: boolean;
}

const config: Record<ThreatLevel, { color: string; label: string }> = {
  safe: { color: 'bg-safe', label: 'SAFE' },
  low: { color: 'bg-info', label: 'LOW' },
  medium: { color: 'bg-warning', label: 'MED' },
  high: { color: 'bg-accent', label: 'HIGH' },
  critical: { color: 'bg-danger', label: 'CRIT' },
};

export function StatusIndicator({ level, size = 'sm', showLabel = false }: StatusIndicatorProps) {
  const { color, label } = config[level];
  const dotSize = size === 'sm' ? 'w-2 h-2' : 'w-3 h-3';

  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`${dotSize} rounded-full ${color} animate-pulse-green`} />
      {showLabel && <span className="text-xs uppercase tracking-wider">{label}</span>}
    </span>
  );
}
