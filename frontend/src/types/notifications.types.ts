/**
 * SecureNet — Notification Types
 *
 * One NotificationItem per stored security event. The same shape is returned
 * by GET /api/notifications and pushed live as the WebSocket `alert` payload.
 */

import type { ActionTaken, Protocol, SeverityLevel } from './security.types';

export interface NotificationItem {
  eventId: string;
  timestamp: string;          // ISO 8601 (UTC, "Z")
  severity: SeverityLevel;
  /** "abnormal" for a detected attack; "protection" for a success/failure outcome notice */
  verdict?: 'abnormal' | 'protection';
  /** only on a protection notice: did the block work (network benign again)? */
  success?: boolean;
  attackType: string | null;  // null = the model could not name it
  confidence?: number | null;
  /** the model's best guess, e.g. "DDoS (97%)" */
  possibleAttack?: string;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  protocol: Protocol;
  anomalyScore: number;
  actionTaken: ActionTaken;
  message: string;
  /** set by the backend's abnormal-state scheduler: this alert should pop an OS desktop
   *  notification (every 3 min while abnormal). Per-flow alerts omit it, so they don't spam. */
  desktopPop?: boolean;
}

export type EmailDeliveryStatus = 'enabled' | 'disabled' | 'misconfigured';

export interface NotificationStatus {
  emailDelivery: EmailDeliveryStatus;   // server SMTP configuration
  emailAlertsEnabled: boolean;          // Settings → Notifications → email alerts
  recipientCount: number;
  recipients: string[];                 // only returned to admins
  batchSeconds: number;
  /** at most one attack email this often (seconds) */
  intervalSeconds?: number;
  emailsSent: number;
  lastError: string | null;
}
