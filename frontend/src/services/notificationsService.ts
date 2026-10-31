/**
 * SecureNet — Notifications Service
 */

import { apiClient } from './apiClient';
import type { MessageResponse } from '../types/api.types';
import type { NotificationItem, NotificationStatus } from '../types/notifications.types';

/** GET /notifications — most recent alerts, newest first. */
export async function getNotifications(limit = 30): Promise<NotificationItem[]> {
  return apiClient.get<NotificationItem[]>(`/notifications?limit=${limit}`);
}

/** GET /notifications/status — email delivery configuration and recipients. */
export async function getNotificationStatus(): Promise<NotificationStatus> {
  return apiClient.get<NotificationStatus>('/notifications/status');
}

/** POST /notifications/test-email — send a sample alert to the signed-in user's email. */
export async function sendTestEmail(): Promise<MessageResponse> {
  return apiClient.post<MessageResponse>('/notifications/test-email', {});
}
