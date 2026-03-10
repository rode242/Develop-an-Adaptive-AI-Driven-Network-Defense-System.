import { useState } from 'react';
import { Shield, Play, Pause, Zap } from 'lucide-react';
import { useNetworkMonitor } from '@/hooks/use-network-monitor';
import { StatsBar } from '@/components/StatsBar';
import { TrafficTable } from '@/components/TrafficTable';
import { AlertsPanel } from '@/components/AlertsPanel';
import { BlacklistPanel } from '@/components/BlacklistPanel';
import { ThreatChart } from '@/components/ThreatChart';

const Index = () => {
  const [isRunning, setIsRunning] = useState(true);
  const [speed, setSpeed] = useState(600);
  const { packets, alerts, blacklist, stats, reviewPacket, removeFromBlacklist, acknowledgeAlert } = useNetworkMonitor(isRunning, speed);

  return (
    <div className="min-h-screen bg-background scanline">
      {/* Header */}
      <header className="border-b px-4 py-3 flex items-center gap-3">
        <Shield className="w-6 h-6 text-primary glow-green" />
        <div>
          <h1 className="text-sm font-display font-bold tracking-wider glow-green">ADAPTIVE NETWORK DEFENSE SYSTEM</h1>
          <p className="text-[10px] text-muted-foreground">Hybrid ML Engine — Random Forest + Isolation Forest</p>
        </div>
        <div className="ml-auto flex items-center gap-3">
          <select
            value={speed}
            onChange={e => setSpeed(Number(e.target.value))}
            className="bg-secondary text-foreground text-xs rounded px-2 py-1 border"
          >
            <option value={200}>Fast (200ms)</option>
            <option value={600}>Normal (600ms)</option>
            <option value={1500}>Slow (1.5s)</option>
          </select>
          <button
            onClick={() => setIsRunning(!isRunning)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-bold border transition-colors ${
              isRunning
                ? 'border-danger text-danger hover:bg-danger/10'
                : 'border-primary text-primary hover:bg-primary/10'
            }`}
          >
            {isRunning ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3" />}
            {isRunning ? 'PAUSE' : 'START'}
          </button>
          <Zap className={`w-4 h-4 ${isRunning ? 'text-safe animate-pulse-green' : 'text-muted-foreground'}`} />
        </div>
      </header>

      {/* Main Content */}
      <main className="p-4 space-y-4 max-w-[1600px] mx-auto">
        <StatsBar stats={stats} />

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2">
            <ThreatChart packets={packets} />
          </div>
          <BlacklistPanel blacklist={blacklist} onRemove={removeFromBlacklist} />
        </div>

        <TrafficTable packets={packets} onReview={reviewPacket} />

        <AlertsPanel alerts={alerts} onAcknowledge={acknowledgeAlert} />

        {/* Model Info */}
        <div className="rounded-md border border-glow p-4 bg-card">
          <h2 className="text-xs font-display uppercase tracking-widest text-foreground mb-3">Detection Architecture</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-muted-foreground">
            <div>
              <span className="text-primary font-bold">Random Forest (Supervised)</span>
              <p className="mt-1">Trained on known attack signatures. High accuracy for DDoS, Brute Force, SQL Injection patterns. Score: 0–1.</p>
            </div>
            <div>
              <span className="text-warning font-bold">Isolation Forest (Unsupervised)</span>
              <p className="mt-1">Detects anomalous behavior unseen in training data. Key for Zero-Day threat identification. Score: -1 to 1.</p>
            </div>
            <div>
              <span className="text-info font-bold">Adaptive Feedback Loop</span>
              <p className="mt-1">Flagged packets (score 0.4–0.6) are queued for human review. Confirmed labels retrain the model to reduce false positives.</p>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Index;
