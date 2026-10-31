/**
 * SecureNet — Reports Service
 *
 * Daily reports are built by the backend from the detected attacks — one per
 * local day that had attacks. Days are computed in the browser's time zone.
 */

import { apiClient } from './apiClient';
import type { DailyReport, DailyReportFormat } from '../types/reports.types';

/** Minutes east of UTC for this browser (India = 330). */
function tzOffset(): number {
  return -new Date().getTimezoneOffset();
}

/** GET /reports/daily — newest day first; empty when no attack has happened. */
export async function getDailyReports(): Promise<DailyReport[]> {
  return apiClient.get<DailyReport[]>(`/reports/daily?tzOffset=${tzOffset()}`);
}

/** GET /reports/daily/:date/download — saves that day's report file. */
export async function downloadDailyReport(date: string, format: DailyReportFormat): Promise<void> {
  await apiClient.download(
    `/reports/daily/${date}/download?format=${format}&tzOffset=${tzOffset()}`,
    `SecureNet-daily-report-${date}.${format}`
  );
}
