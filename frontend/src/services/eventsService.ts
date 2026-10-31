/**
 * SecureNet — Security Events Service
 *
 * CRUD + query operations for security event history.
 *
 */

import { apiClient } from './apiClient';
import type { SecurityEvent } from '../types/security.types';
import type {
  PaginatedResponse,
  EventFilterParams,
  MessageResponse,
} from '../types/api.types';

/**
 * Fetch a paginated, filtered list of security events.
 * GET /events
 */
export async function getEvents(
  params: Partial<EventFilterParams>
): Promise<PaginatedResponse<SecurityEvent>> {
  const qs = buildQueryString(params);
  return apiClient.get<PaginatedResponse<SecurityEvent>>(`/events?${qs}`);
}

/**
 * Fetch a single security event by ID.
 * GET /events/:id
 */
export async function getEventById(id: string): Promise<SecurityEvent> {
  return apiClient.get<SecurityEvent>(`/events/${id}`);
}

/**
 * Mark an event as resolved.
 * POST /events/:id/resolve
 */
export async function resolveEvent(id: string): Promise<MessageResponse> {
  return apiClient.post<MessageResponse>(`/events/${id}/resolve`, {});
}

/**
 * Mark an event as a false positive.
 * POST /events/:id/false-positive
 */
export async function markFalsePositive(id: string): Promise<MessageResponse> {
  return apiClient.post<MessageResponse>(`/events/${id}/false-positive`, {});
}

/**
 * Download events matching the current filters (CSV / PDF / JSON).
 * GET /api/events/export
 */
export async function exportEvents(
  params: Partial<EventFilterParams>,
  format: 'csv' | 'pdf' | 'json'
): Promise<void> {
  const { page: _page, pageSize: _pageSize, ...filters } = params;
  const qs = buildQueryString({ ...filters, format } as Partial<EventFilterParams>);
  await apiClient.download(`/events/export?${qs}`, `securenet-events.${format}`);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function buildQueryString(params: Partial<EventFilterParams>): string {
  const entries = Object.entries(params).filter(
    ([, v]) => v !== null && v !== undefined && v !== ''
  );
  return new URLSearchParams(
    entries.map(([k, v]) => [k, String(v)])
  ).toString();
}
