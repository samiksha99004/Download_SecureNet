/**
 * SecureNet — Reports Types
 *
 * A daily report exists for every (local) day on which attacks were detected.
 */

export type DailyReportFormat = 'txt' | 'pdf';

export interface DailyReport {
  date: string;          // YYYY-MM-DD, local calendar day
  total: number;
  high: number;
  medium: number;
  low: number;
  topAttack: string | null;
  sources: number;       // distinct attacking source IPs
  firstSeen: string;     // ISO 8601 (UTC, "Z")
  lastSeen: string;      // ISO 8601 (UTC, "Z")
}
