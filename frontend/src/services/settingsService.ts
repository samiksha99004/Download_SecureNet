/**
 * SecureNet — Settings Service
 *
 * Read and update all application settings categories.
 *
 */

import { apiClient } from './apiClient';
import type {
  AllSettings,
  DetectionSettings,
  ProtectionSettings,
  AdvancedProtection,
  NotificationSettings,
  SystemSettings,
  WhitelistEntry,
  CreateWhitelistEntryRequest,
} from '../types/settings.types';
import type { MessageResponse } from '../types/api.types';

// ── Read Settings ─────────────────────────────────────────────────────────────

/** GET /settings */
export async function getAllSettings(): Promise<AllSettings> {
  return apiClient.get<AllSettings>('/settings');
}

/** GET /settings/detection */
export async function getDetectionSettings(): Promise<DetectionSettings> {
  return apiClient.get<DetectionSettings>('/settings/detection');
}

/** GET /settings/protection */
export async function getProtectionSettings(): Promise<ProtectionSettings> {
  return apiClient.get<ProtectionSettings>('/settings/protection');
}

/** GET /settings/advanced-protection */
export async function getAdvancedProtection(): Promise<AdvancedProtection> {
  return apiClient.get<AdvancedProtection>('/settings/advanced-protection');
}

export interface AdvancedProtectionChallenge {
  confirmToken: string;
  sentTo: string;
  message: string;
}

/** PUT /settings/advanced-protection — turn protection ON directly (no code). OFF is refused here. */
export async function updateAdvancedProtection(enabled: boolean): Promise<AdvancedProtection> {
  return apiClient.put<AdvancedProtection>('/settings/advanced-protection', { enabled });
}

/** POST /settings/advanced-protection/request-code — emails a code to confirm turning protection OFF. */
export async function requestAdvancedProtectionCode(enabled: boolean): Promise<AdvancedProtectionChallenge> {
  return apiClient.post<AdvancedProtectionChallenge>('/settings/advanced-protection/request-code', { enabled });
}

/** POST /settings/advanced-protection/confirm — applies the change (on or off) with the emailed code. */
export async function confirmAdvancedProtection(token: string, otp: string): Promise<AdvancedProtection> {
  return apiClient.post<AdvancedProtection>('/settings/advanced-protection/confirm', { token, otp });
}

/** GET /settings/notifications */
export async function getNotificationSettings(): Promise<NotificationSettings> {
  return apiClient.get<NotificationSettings>('/settings/notifications');
}

/** GET /settings/system */
export async function getSystemSettings(): Promise<SystemSettings> {
  return apiClient.get<SystemSettings>('/settings/system');
}

// ── Update Settings ───────────────────────────────────────────────────────────

/** PUT /settings/detection */
export async function updateDetectionSettings(
  data: Partial<DetectionSettings>
): Promise<DetectionSettings> {
  return apiClient.put<DetectionSettings>('/settings/detection', data);
}

/** PUT /settings/protection */
export async function updateProtectionSettings(
  data: Partial<ProtectionSettings>
): Promise<ProtectionSettings> {
  return apiClient.put<ProtectionSettings>('/settings/protection', data);
}

/** PUT /settings/notifications */
export async function updateNotificationSettings(
  data: Partial<NotificationSettings>
): Promise<NotificationSettings> {
  return apiClient.put<NotificationSettings>('/settings/notifications', data);
}

/** PUT /settings/system */
export async function updateSystemSettings(
  data: Partial<SystemSettings>
): Promise<SystemSettings> {
  return apiClient.put<SystemSettings>('/settings/system', data);
}

// ── Whitelist ─────────────────────────────────────────────────────────────────

/** GET /settings/whitelist */
export async function getWhitelist(): Promise<WhitelistEntry[]> {
  return apiClient.get<WhitelistEntry[]>('/settings/whitelist');
}

/** POST /settings/whitelist */
export async function addWhitelistEntry(
  data: CreateWhitelistEntryRequest
): Promise<WhitelistEntry> {
  return apiClient.post<WhitelistEntry>('/settings/whitelist', data);
}

/** DELETE /settings/whitelist/:id */
export async function removeWhitelistEntry(id: string): Promise<MessageResponse> {
  return apiClient.delete<MessageResponse>(`/settings/whitelist/${id}`);
}
