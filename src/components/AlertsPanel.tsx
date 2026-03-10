import { Alert } from '@/lib/network-engine';
import { StatusIndicator } from './StatusIndicator';
import { ScrollArea } from '@/components/ui/scroll-area';

interface AlertsPanelProps {
  alerts: Alert[];
  onAcknowledge: (id: string) => void;
}

export function AlertsPanel({ alerts, onAcknowledge }: AlertsPanelProps) {
  return (
    <div className="rounded-md border border-glow overflow-hidden">
      <div className="px-3 py-2 border-b bg-secondary/50 flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-danger animate-pulse-green" />
        <span className="text-xs font-display uppercase tracking-widest text-foreground">Alerts & IPS Actions</span>
        <span className="ml-auto text-xs text-muted-foreground">{alerts.filter(a => !a.acknowledged).length} active</span>
      </div>
      <ScrollArea className="h-[240px]">
        {alerts.length === 0 ? (
          <div className="p-4 text-center text-muted-foreground text-xs">No alerts yet</div>
        ) : (
          <div className="divide-y divide-border/50">
            {alerts.map(alert => (
              <div
                key={alert.id}
                className={`px-3 py-2 text-xs flex items-center gap-3 ${
                  alert.acknowledged ? 'opacity-50' : ''
                }`}
              >
                <StatusIndicator level={alert.threatLevel} />
                <span className="text-muted-foreground w-16">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                <span className="flex-1">{alert.srcIp}</span>
                <span className="text-accent">{alert.attackType}</span>
                <span className="text-muted-foreground">{alert.action}</span>
                {!alert.acknowledged && (
                  <button
                    onClick={() => onAcknowledge(alert.id)}
                    className="text-[10px] text-primary hover:underline"
                  >
                    ACK
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </ScrollArea>
    </div>
  );
}
