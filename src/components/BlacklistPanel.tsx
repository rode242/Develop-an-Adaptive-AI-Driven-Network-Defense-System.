import { ScrollArea } from '@/components/ui/scroll-area';
import { X } from 'lucide-react';

interface BlacklistPanelProps {
  blacklist: string[];
  onRemove: (ip: string) => void;
}

export function BlacklistPanel({ blacklist, onRemove }: BlacklistPanelProps) {
  return (
    <div className="rounded-md border border-glow overflow-hidden">
      <div className="px-3 py-2 border-b bg-secondary/50 flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-danger" />
        <span className="text-xs font-display uppercase tracking-widest text-foreground">Blacklist (Firewall Drop)</span>
        <span className="ml-auto text-xs text-muted-foreground">{blacklist.length} IPs</span>
      </div>
      <ScrollArea className="h-[200px]">
        {blacklist.length === 0 ? (
          <div className="p-4 text-center text-muted-foreground text-xs">No blocked IPs</div>
        ) : (
          <div className="p-2 space-y-1">
            {blacklist.map(ip => (
              <div key={ip} className="flex items-center justify-between px-2 py-1 rounded bg-danger/10 text-xs">
                <span className="text-danger">{ip}</span>
                <button onClick={() => onRemove(ip)} className="text-muted-foreground hover:text-foreground">
                  <X className="w-3 h-3" />
                </button>
              </div>
            ))}
          </div>
        )}
      </ScrollArea>
    </div>
  );
}
