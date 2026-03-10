// Synthetic traffic generator and ML simulation engine

export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS' | 'DNS' | 'SSH' | 'FTP';
export type ThreatLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';
export type AttackType = 'Normal' | 'DDoS' | 'Port Scan' | 'Brute Force' | 'SQL Injection' | 'XSS' | 'Zero-Day' | 'C2 Beacon' | 'Data Exfiltration';

export interface Packet {
  id: string;
  timestamp: number;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: Protocol;
  packetLength: number;
  flowDuration: number;
  threatScore: number;
  threatLevel: ThreatLevel;
  attackType: AttackType;
  flagged: boolean;
  reviewed: boolean;
  blocked: boolean;
  rfScore: number;    // Random Forest score
  ifScore: number;    // Isolation Forest anomaly score
}

export interface Alert {
  id: string;
  timestamp: number;
  srcIp: string;
  attackType: AttackType;
  threatScore: number;
  threatLevel: ThreatLevel;
  action: string;
  acknowledged: boolean;
}

const PROTOCOLS: Protocol[] = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP'];
const NORMAL_IPS = ['192.168.1.', '10.0.0.', '172.16.0.'];
const SUSPICIOUS_IPS = ['45.33.32.', '185.220.101.', '91.219.236.', '23.129.64.'];
const INTERNAL_IPS = ['192.168.1.1', '192.168.1.10', '192.168.1.50', '10.0.0.1', '10.0.0.5'];

let packetCounter = 0;

function rand(min: number, max: number): number {
  return Math.random() * (max - min) + min;
}

function randInt(min: number, max: number): number {
  return Math.floor(rand(min, max));
}

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function generateIp(suspicious: boolean): string {
  if (suspicious) {
    return pick(SUSPICIOUS_IPS) + randInt(1, 255);
  }
  return pick(NORMAL_IPS) + randInt(1, 255);
}

function getThreatLevel(score: number): ThreatLevel {
  if (score < 0.2) return 'safe';
  if (score < 0.4) return 'low';
  if (score < 0.6) return 'medium';
  if (score < 0.85) return 'high';
  return 'critical';
}

// Simulated Random Forest classifier
function simulateRFScore(packet: Partial<Packet>, isMalicious: boolean): number {
  if (!isMalicious) return rand(0.01, 0.25);
  const base = rand(0.6, 0.99);
  // Known attack patterns get higher scores
  if (packet.protocol === 'SSH' && packet.dstPort === 22) return Math.min(base + 0.1, 1);
  return base;
}

// Simulated Isolation Forest anomaly detector
function simulateIFScore(packet: Partial<Packet>, isMalicious: boolean): number {
  if (!isMalicious) return rand(-0.3, 0.1); // Normal traffic has low anomaly
  // Zero-day / unusual patterns
  if (packet.packetLength && packet.packetLength > 5000) return rand(0.5, 0.95);
  return rand(0.3, 0.8);
}

export function generatePacket(): Packet {
  const isMalicious = Math.random() < 0.15; // 15% malicious traffic
  const isZeroDay = isMalicious && Math.random() < 0.2; // 20% of malicious = zero-day

  const attackTypes: AttackType[] = ['DDoS', 'Port Scan', 'Brute Force', 'SQL Injection', 'XSS', 'C2 Beacon', 'Data Exfiltration'];
  
  const srcIp = isMalicious ? generateIp(true) : generateIp(false);
  const dstIp = pick(INTERNAL_IPS);
  const protocol = isMalicious ? pick(['TCP', 'SSH', 'HTTP'] as Protocol[]) : pick(PROTOCOLS);
  const dstPort = isMalicious 
    ? pick([22, 80, 443, 3389, 8080, 3306]) 
    : pick([80, 443, 53, 8080, 25, 110, 993]);
  const packetLength = isMalicious ? randInt(100, 15000) : randInt(40, 1500);
  const flowDuration = isMalicious ? rand(0.01, 300) : rand(0.1, 60);

  const partial: Partial<Packet> = { protocol, dstPort, packetLength };
  const rfScore = simulateRFScore(partial, isMalicious && !isZeroDay);
  const ifScore = simulateIFScore(partial, isMalicious);
  
  // Hybrid score: weighted combination
  const threatScore = isZeroDay
    ? Math.max(ifScore, 0.5) // Zero-day relies on anomaly detection
    : isMalicious
    ? rfScore * 0.7 + Math.max(ifScore, 0) * 0.3
    : rfScore * 0.5 + Math.max(ifScore, 0) * 0.5;

  const clampedScore = Math.max(0, Math.min(1, threatScore));
  const attackType: AttackType = isMalicious 
    ? (isZeroDay ? 'Zero-Day' : pick(attackTypes))
    : 'Normal';

  packetCounter++;

  return {
    id: `PKT-${packetCounter.toString().padStart(6, '0')}`,
    timestamp: Date.now(),
    srcIp,
    dstIp,
    srcPort: randInt(1024, 65535),
    dstPort,
    protocol,
    packetLength,
    flowDuration: Math.round(flowDuration * 100) / 100,
    threatScore: Math.round(clampedScore * 1000) / 1000,
    threatLevel: getThreatLevel(clampedScore),
    attackType,
    flagged: clampedScore > 0.4 && clampedScore < 0.6,
    reviewed: false,
    blocked: clampedScore >= 0.85,
    rfScore: Math.round(rfScore * 1000) / 1000,
    ifScore: Math.round(ifScore * 1000) / 1000,
  };
}

export function generateBurst(count: number): Packet[] {
  return Array.from({ length: count }, () => generatePacket());
}
