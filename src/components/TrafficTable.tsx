import { Packet } from '@/lib/network-engine';
import { StatusIndicator } from './StatusIndicator';
import { ScrollArea } from '@/components/ui/scroll-area';

interface TrafficTableProps {
  packets: Packet[];
  onReview?: (id: string, isThreat: boolean) => void;
}

export function TrafficTable({ packets, onReview }: TrafficTableProps) {
  return (
    <div className="rounded-md border border-glow overflow-hidden">
      <div className="px-3 py-2 border-b bg-secondary/50 flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-safe animate-pulse-green" />
        <span className="text-xs font-display uppercase tracking-widest text-foreground">Live Traffic Monitor</span>
        <span className="ml-auto text-xs text-muted-foreground">{packets.length} packets</span>
      </div>
      <ScrollArea className="h-[320px]">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-card">
            <tr className="border-b text-muted-foreground">
              <th className="px-2 py-1.5 text-left">ID</th>
              <th className="px-2 py-1.5 text-left">Source IP</th>
              <th className="px-2 py-1.5 text-left">Dest IP</th>
              <th className="px-2 py-1.5 text-left">Proto</th>
              <th className="px-2 py-1.5 text-right">Size</th>
              <th className="px-2 py-1.5 text-right">RF</th>
              <th className="px-2 py-1.5 text-right">IF</th>
              <th className="px-2 py-1.5 text-center">Threat</th>
              <th className="px-2 py-1.5 text-left">Type</th>
              <th className="px-2 py-1.5 text-center">Action</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((pkt) => (
              <tr
                key={pkt.id}
                className={`border-b border-border/50 hover:bg-secondary/30 transition-colors ${
                  pkt.blocked ? 'bg-danger/10' : pkt.flagged ? 'bg-warning/10' : ''
                }`}
              >
                <td className="px-2 py-1 text-muted-foreground">{pkt.id}</td>
                <td className="px-2 py-1">{pkt.srcIp}</td>
                <td className="px-2 py-1">{pkt.dstIp}</td>
                <td className="px-2 py-1">{pkt.protocol}</td>
                <td className="px-2 py-1 text-right">{pkt.packetLength}B</td>
                <td className="px-2 py-1 text-right">{pkt.rfScore.toFixed(2)}</td>
                <td className="px-2 py-1 text-right">{pkt.ifScore.toFixed(2)}</td>
                <td className="px-2 py-1 text-center">
                  <StatusIndicator level={pkt.threatLevel} showLabel />
                </td>
                <td className="px-2 py-1">
                  <span className={pkt.attackType !== 'Normal' ? 'text-accent' : 'text-muted-foreground'}>
                    {pkt.attackType}
                  </span>
                </td>
                <td className="px-2 py-1 text-center">
                  {pkt.blocked && <span className="text-danger text-[10px] font-bold">BLOCKED</span>}
                  {pkt.flagged && !pkt.reviewed && onReview && (
                    <span className="inline-flex gap-1">
                      <button onClick={() => onReview(pkt.id, true)} className="text-danger hover:underline text-[10px]">Threat</button>
                      <button onClick={() => onReview(pkt.id, false)} className="text-safe hover:underline text-[10px]">Safe</button>
                    </span>
                  )}
                  {pkt.reviewed && <span className="text-muted-foreground text-[10px]">Reviewed</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </ScrollArea>
    </div>
  );
}
