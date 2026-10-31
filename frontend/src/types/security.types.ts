/**
 * SecureNet — Security Event & Detection Types
 *
 * Reflects the expected shape of data from the ML intrusion
 * detection pipeline (Isolation Forest + XGBoost).
 * No values are invented — all data comes from the backend.
 */

// ── Severity / Classification ─────────────────────────────────────────────────

export type SeverityLevel = 'low' | 'medium' | 'high';

export type EventState = 'active' | 'investigating' | 'resolved' | 'false_positive';

export type DetectionMode = 'monitor' | 'protect';

export type ActionTaken =
  | 'logged'
  | 'alerted'
  | 'blocked'
  | 'terminated'
  | 'none';

export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'other';

// ── Contributing Feature (for detection reason display) ───────────────────────

export interface ContributingFeature {
  name: string;
  value: number | string;
  contribution: number; // e.g. SHAP value or importance score
}

/** One of the model's guesses of which attack the abnormal traffic might be. */
export interface AttackGuess {
  label: string;
  probability: number;         // 0–1
}

// ── Security Event ────────────────────────────────────────────────────────────

export interface SecurityEvent {
  id: string;
  timestamp: string;           // ISO 8601
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  protocol: Protocol;
  anomalyScore: number;        // Stage 1 output
  severity: SeverityLevel;
  attackType: string | null;   // Stage 2 classification; null if normal
  confidence: number | null;   // Stage 2 confidence; null if normal
  mode: DetectionMode;
  state: EventState;
  actionTaken: ActionTaken;
  detectionReason: string | null;
  contributingFeatures: ContributingFeature[];
  /** stage 2's guesses, most likely first (empty for older events) */
  attackGuesses?: AttackGuess[];
  flowDurationMs: number | null;
  bytesSent: number | null;
  bytesReceived: number | null;
  packetsSent: number | null;
  packetsReceived: number | null;
}

// ── Dashboard Summary ─────────────────────────────────────────────────────────

export interface DashboardSummary {
  activeFlows: number;
  anomaliesLastHour: number;
  highSeverityCount: number;
  blockedCount: number;
  averageAnomalyScore: number;
  severityBreakdown: {
    low: number;
    medium: number;
    high: number;
  };
  attackTypeDistribution: AttackTypeCount[];
  recentEvents: SecurityEvent[];
}

export interface AttackTypeCount {
  attackType: string;
  count: number;
}

// ── Host Status ───────────────────────────────────────────────────────────────

export interface HostStatus {
  hostname: string | null;
  os: string | null;
  cpuPercent: number | null;
  memoryPercent: number | null;
  networkInterface: string | null;
  networkBytesPerSec: number | null;
  uptime: number | null;       // seconds
  lastUpdated: string | null;  // ISO 8601
}

// ── Protocol Distribution ─────────────────────────────────────────────────────

export interface ProtocolDistribution {
  tcp: number;
  udp: number;
  icmp: number;
  other: number;
  totalFlows: number;
}

// ── Top Source ────────────────────────────────────────────────────────────────

export interface TopSource {
  sourceIp: string;
  flowCount: number;
  anomalyCount: number;
  highSeverityCount: number;
  lastSeen: string; // ISO 8601
}

// ── Live Score (WebSocket event payload) ─────────────────────────────────────

export interface LiveScoreEvent {
  timestamp: string;
  anomalyScore: number;
  severity: SeverityLevel;
  sourceIp: string;
  destinationIp: string;
  protocol: Protocol;
  attackType: string | null;
}

export interface LiveChartPoint {
  time: string;       // display label
  score: number;
  severity: SeverityLevel;
  isAlert: boolean;
}
