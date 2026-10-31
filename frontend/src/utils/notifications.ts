/**
 * SecureNet — notification helpers
 */

import type { NotificationItem } from '../types/notifications.types';
import { ABNORMAL_TRAFFIC } from './verdict';

/** Display title of an alert: the verdict (the attack is only the model's guess). */
export function titleOf(_item?: Pick<NotificationItem, 'attackType'>): string {
  return ABNORMAL_TRAFFIC;
}

/** "Possible attack: DDoS (97%)" line of an alert. */
export function guessOf(item: Pick<NotificationItem, 'attackType' | 'possibleAttack' | 'confidence'>): string {
  if (item.possibleAttack) return item.possibleAttack;
  if (!item.attackType) return 'Unknown';
  return item.confidence != null ? `${item.attackType} (${Math.round(item.confidence * 100)}%)` : item.attackType;
}
