import { useState, useEffect, useCallback, useRef } from 'react';
import { Packet, Alert, generatePacket } from '@/lib/network-engine';

const MAX_PACKETS = 200;
const MAX_ALERTS = 50;

export function useNetworkMonitor(isRunning: boolean, speed: number = 500) {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [blacklist, setBlacklist] = useState<string[]>([]);
  const [stats, setStats] = useState({
    totalPackets: 0,
    threatsDetected: 0,
    blocked: 0,
    falsePositives: 0,
    truePositives: 0,
  });
  const intervalRef = useRef<ReturnType<typeof setInterval>>();

  const addPacket = useCallback(() => {
    const pkt = generatePacket();

    setPackets(prev => {
      const next = [pkt, ...prev].slice(0, MAX_PACKETS);
      return next;
    });

    setStats(prev => ({
      ...prev,
      totalPackets: prev.totalPackets + 1,
      threatsDetected: prev.threatsDetected + (pkt.threatScore >= 0.4 ? 1 : 0),
      blocked: prev.blocked + (pkt.blocked ? 1 : 0),
    }));

    if (pkt.blocked) {
      setBlacklist(prev => {
        if (prev.includes(pkt.srcIp)) return prev;
        return [pkt.srcIp, ...prev].slice(0, 100);
      });

      const alert: Alert = {
        id: `ALT-${Date.now()}`,
        timestamp: pkt.timestamp,
        srcIp: pkt.srcIp,
        attackType: pkt.attackType,
        threatScore: pkt.threatScore,
        threatLevel: pkt.threatLevel,
        action: 'BLOCKED — IP added to blacklist',
        acknowledged: false,
      };
      setAlerts(prev => [alert, ...prev].slice(0, MAX_ALERTS));
    } else if (pkt.threatLevel === 'high') {
      const alert: Alert = {
        id: `ALT-${Date.now()}`,
        timestamp: pkt.timestamp,
        srcIp: pkt.srcIp,
        attackType: pkt.attackType,
        threatScore: pkt.threatScore,
        threatLevel: pkt.threatLevel,
        action: 'FLAGGED — Monitoring',
        acknowledged: false,
      };
      setAlerts(prev => [alert, ...prev].slice(0, MAX_ALERTS));
    }
  }, []);

  useEffect(() => {
    if (isRunning) {
      intervalRef.current = setInterval(addPacket, speed);
    } else {
      if (intervalRef.current) clearInterval(intervalRef.current);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [isRunning, speed, addPacket]);

  const reviewPacket = useCallback((packetId: string, isThreat: boolean) => {
    setPackets(prev => prev.map(p =>
      p.id === packetId ? { ...p, reviewed: true, flagged: false } : p
    ));
    setStats(prev => ({
      ...prev,
      falsePositives: prev.falsePositives + (isThreat ? 0 : 1),
      truePositives: prev.truePositives + (isThreat ? 1 : 0),
    }));
  }, []);

  const removeFromBlacklist = useCallback((ip: string) => {
    setBlacklist(prev => prev.filter(i => i !== ip));
  }, []);

  const acknowledgeAlert = useCallback((alertId: string) => {
    setAlerts(prev => prev.map(a =>
      a.id === alertId ? { ...a, acknowledged: true } : a
    ));
  }, []);

  return { packets, alerts, blacklist, stats, reviewPacket, removeFromBlacklist, acknowledgeAlert };
}
