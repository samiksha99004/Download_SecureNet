/**
 * SecureNet — Support Service
 */

import { apiClient } from './apiClient';
import type { ContactInfo } from '../types/settings.types';
import type { MessageResponse } from '../types/api.types';

/** GET /support/contact — "Contact us" details set by the admin (public, no sign-in needed). */
export async function getContactInfo(): Promise<ContactInfo> {
  return apiClient.get<ContactInfo>('/support/contact', { skipAuth: true });
}

/** POST /support/message — emails the SecureNet team; replies go to the user's own email. */
export async function sendSupportMessage(subject: string, message: string): Promise<MessageResponse> {
  return apiClient.post<MessageResponse>('/support/message', { subject, message });
}
