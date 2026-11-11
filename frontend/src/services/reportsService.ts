/**
 * SecureNet — Reports Service
 *
 * Reports are built by the backend from the detected attacks — one per 6-hour
 * window (local time) that had attacks, created only after the window ends.
 * Windows are computed in the browser's time zone.
 */

import { apiClient } from './apiClient';
import type { ReportWindow, ReportFormat } from '../types/reports.types';

/** Minutes east of UTC for this browser (India = 330). */
function tzOffset(): number {
  return -new Date().getTimezoneOffset();
}

/** GET /reports/windows — finished 6-hour windows with attacks, newest first. */
export async function getWindowReports(): Promise<ReportWindow[]> {
  return apiClient.get<ReportWindow[]>(`/reports/windows?tzOffset=${tzOffset()}`);
}

/** GET /reports/windows/:key/download — saves that window's report file. */
export async function downloadWindowReport(key: string, format: ReportFormat): Promise<void> {
  await apiClient.download(
    `/reports/windows/${encodeURIComponent(key)}/download?format=${format}&tzOffset=${tzOffset()}`,
    `SecureNet-report-${key.replace(/:/g, '')}.${format}`
  );
}
