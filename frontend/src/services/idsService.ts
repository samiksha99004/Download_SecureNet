/**
 * SecureNet — IDS Control Service
 *
 * OFF / Detection ("monitor") / Protection ("protect") control and status.
 */

import { apiClient } from './apiClient';

// ── Types ─────────────────────────────────────────────────────────────────────

export type IDSMode = 'monitor' | 'protect';

/** Table 2 row: how many abnormal flows stage 2 thought were this class. */
export interface GuessRow {
  label: string;
  flows: number;
  /** "Benign": stage 2 cancelled the alarm */
  cancelled: boolean;
}

/** One class in the rolling-window live breakdown (CLI-style). */
export interface RecentRow {
  label: string;
  flows: number;
  pct: number;
}

/** One point in the attack-% trend chart. */
export interface TrendPoint {
  t: number;   // epoch seconds
  pct: number; // attacks as % of recent flows
}

/** Verdict tables since the IDS was turned on. */
export interface VerdictSummary {
  scored: number;
  /** Table 1 — stage 1 */
  normal: number;
  abnormal: number;
  /** Table 2 — stage 2's guess for every abnormal flow */
  guesses: GuessRow[];
  /** final verdict (stage 2 can cancel a stage-1 alarm) */
  finalNormal: number;
  finalAbnormal: number;
  /** rolling-window live breakdown — what the CLI printed each refresh */
  recent?: RecentRow[];
  recentTotal?: number;
  recentAbnormalPct?: number;
  /** attack-% history for the dashboard trend chart */
  trend?: TrendPoint[];
}

export interface IDSStatus {
  enabled: boolean;
  mode: IDSMode;
  mlLoaded: boolean;
  /** "none" | "isolation_forest" | "xgboost" | "isolation_forest+xgboost" */
  detector: string;
  /** stage-1 threshold in use right now */
  threshold?: number | null;
  captureActive: boolean;
  captureError: string | null;
  packetsProcessed: number;
  flowsAnalyzed: number;
  activeFlows: number;
  anomaliesDetected: number;
  attacksDetected: number;
  blockedIps: number;
  uptimeSeconds: number;
  /** incidents counted but not stored during an attack storm */
  alertsNotStored?: number;
  verdicts?: VerdictSummary | null;
}

export interface IDSControlRequest {
  enabled: boolean;
  mode?: IDSMode;
}

export const MODE_LABELS: Record<IDSMode, string> = {
  monitor: 'Detection',
  protect: 'Protection',
};

export const DETECTOR_LABELS: Record<string, string> = {
  none: 'No model loaded',
  isolation_forest: 'Isolation Forest',
  xgboost: 'XGBoost',
  'isolation_forest+xgboost': 'Isolation Forest + XGBoost',
};

// ── API Calls ─────────────────────────────────────────────────────────────────

/** GET /api/ids/status */
export async function getIDSStatus(): Promise<IDSStatus> {
  return apiClient.get<IDSStatus>('/ids/status');
}

/** POST /api/ids/control */
export async function controlIDS(request: IDSControlRequest): Promise<IDSStatus> {
  return apiClient.post<IDSStatus>('/ids/control', request);
}

export async function startIDS(mode?: IDSMode): Promise<IDSStatus> {
  return controlIDS({ enabled: true, mode });
}

export async function stopIDS(): Promise<IDSStatus> {
  return controlIDS({ enabled: false });
}

export async function setIDSMode(mode: IDSMode): Promise<IDSStatus> {
  return controlIDS({ enabled: true, mode });
}
