/**
 * SecureNet — Reports Types
 *
 * The day is split into four 6-hour windows (12am-6am, 6am-12pm, 12pm-6pm,
 * 6pm-12am). A report exists for a window only once it has ended and it had
 * at least one attack.
 */

export type ReportFormat = 'txt' | 'pdf';

export interface ReportWindow {
  key: string;           // window start "YYYY-MM-DDTHH" (local) — the download id
  date: string;          // YYYY-MM-DD, local calendar day
  rangeLabel: string;    // e.g. "12:00 am - 6:00 am"
  total: number;
  high: number;
  medium: number;
  low: number;
  topAttack: string | null;
  sources: number;       // distinct attacking source IPs
  firstSeen: string;     // ISO 8601 (UTC, "Z")
  lastSeen: string;      // ISO 8601 (UTC, "Z")
}
