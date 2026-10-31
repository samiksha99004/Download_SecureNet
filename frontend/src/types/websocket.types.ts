/**
 * SecureNet — WebSocket Types
 *
 * Defines the message protocol for the live monitoring WebSocket feed.
 * The backend will send messages conforming to these shapes.
 */

// ── Connection State ──────────────────────────────────────────────────────────

import type { NotificationItem } from './notifications.types';

export type WebSocketStatus =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'disconnected'
  | 'reconnecting'
  | 'error';

// ── Message Types ─────────────────────────────────────────────────────────────

export type WebSocketMessageType =
  | 'live_score'
  | 'host_status'
  | 'protocol_distribution'
  | 'top_sources'
  | 'alert'
  | 'system_status'
  | 'ping'
  | 'pong';

// ── Base Message ──────────────────────────────────────────────────────────────

export interface WebSocketMessage<T = unknown> {
  type: WebSocketMessageType;
  timestamp: string;  // ISO 8601
  payload: T;
}

// ── Specific Payloads ─────────────────────────────────────────────────────────

export interface LiveScorePayload {
  anomalyScore: number;
  severity: string;
  /** true when the flow crossed the threshold and was stored as an event */
  isAlert: boolean;
  /** final verdict for this flow */
  verdict?: 'normal' | 'abnormal';
  /** stage 1 found it unusual (stage 2 may still have cancelled it) */
  flagged?: boolean;
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  attackType: string | null;
}

export interface HostStatusPayload {
  cpuPercent: number;
  memoryPercent: number;
  networkBytesPerSec: number;
  uptime: number;
}

/** `alert` payload — identical to a GET /api/notifications item. */
export type AlertPayload = NotificationItem;

export interface SystemStatusPayload {
  detectionEnabled: boolean;
  mode: string;
  modelStatus: string;
  activeFlows: number;
}
