import { useEffect, useState, useRef } from 'react';
import { Packet } from '@/lib/network-engine';

interface ThreatChartProps {
  packets: Packet[];
}

interface DataPoint {
  time: string;
  safe: number;
  threats: number;
  blocked: number;
}

export function ThreatChart({ packets }: ThreatChartProps) {
  const [data, setData] = useState<DataPoint[]>([]);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    // Aggregate last 20 seconds in 2-second buckets
    const now = Date.now();
    const buckets: DataPoint[] = [];
    for (let i = 9; i >= 0; i--) {
      const start = now - (i + 1) * 2000;
      const end = now - i * 2000;
      const bucket = packets.filter(p => p.timestamp >= start && p.timestamp < end);
      buckets.push({
        time: `-${(i * 2)}s`,
        safe: bucket.filter(p => p.threatLevel === 'safe' || p.threatLevel === 'low').length,
        threats: bucket.filter(p => p.threatLevel === 'medium' || p.threatLevel === 'high').length,
        blocked: bucket.filter(p => p.threatLevel === 'critical').length,
      });
    }
    setData(buckets);
  }, [packets]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || data.length === 0) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const maxVal = Math.max(5, ...data.map(d => d.safe + d.threats + d.blocked));
    const barWidth = (w - 40) / data.length;

    // Grid lines
    ctx.strokeStyle = 'hsla(150, 30%, 18%, 0.5)';
    ctx.lineWidth = 0.5;
    for (let i = 0; i <= 4; i++) {
      const y = h - 20 - (i / 4) * (h - 30);
      ctx.beginPath();
      ctx.moveTo(30, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    data.forEach((d, i) => {
      const x = 30 + i * barWidth + barWidth * 0.1;
      const bw = barWidth * 0.8;
      const totalH = ((d.safe + d.threats + d.blocked) / maxVal) * (h - 30);

      // Safe (green)
      const safeH = (d.safe / maxVal) * (h - 30);
      ctx.fillStyle = 'hsl(150, 80%, 45%)';
      ctx.fillRect(x, h - 20 - safeH, bw, safeH);

      // Threats (yellow)
      const threatH = (d.threats / maxVal) * (h - 30);
      ctx.fillStyle = 'hsl(45, 90%, 50%)';
      ctx.fillRect(x, h - 20 - safeH - threatH, bw, threatH);

      // Blocked (red)
      const blockedH = (d.blocked / maxVal) * (h - 30);
      ctx.fillStyle = 'hsl(0, 85%, 55%)';
      ctx.fillRect(x, h - 20 - totalH, bw, blockedH);

      // Label
      ctx.fillStyle = 'hsl(150, 15%, 45%)';
      ctx.font = '9px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.fillText(d.time, x + bw / 2, h - 6);
    });
  }, [data]);

  return (
    <div className="rounded-md border border-glow overflow-hidden">
      <div className="px-3 py-2 border-b bg-secondary/50 flex items-center gap-2">
        <span className="text-xs font-display uppercase tracking-widest text-foreground">Traffic Timeline</span>
        <span className="ml-auto flex items-center gap-3 text-[10px]">
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-safe" /> Safe</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-warning" /> Threats</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-danger" /> Blocked</span>
        </span>
      </div>
      <div className="p-2">
        <canvas ref={canvasRef} className="w-full h-[140px]" />
      </div>
    </div>
  );
}
