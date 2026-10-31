/**
 * SecureNet — StatusBadge Component
 *
 * Generic status badge for event states, connection states, etc.
 */

import { cn } from '../../utils/cn';
import styles from './StatusBadge.module.css';

type StatusVariant =
  | 'active'
  | 'investigating'
  | 'resolved'
  | 'false_positive'
  | 'connected'
  | 'disconnected'
  | 'connecting'
  | 'error'
  | 'info'
  | 'pending';

interface StatusBadgeProps {
  status: StatusVariant;
  label?: string;
  className?: string;
}

const DEFAULT_LABELS: Record<StatusVariant, string> = {
  active: 'Active',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False Positive',
  connected: 'Connected',
  disconnected: 'Disconnected',
  connecting: 'Connecting',
  error: 'Error',
  info: 'Info',
  pending: 'Pending',
};

export function StatusBadge({ status, label, className }: StatusBadgeProps) {
  const displayLabel = label ?? DEFAULT_LABELS[status];
  return (
    <span
      className={cn(styles.badge, styles[status.replace('_', '-')], className)}
      aria-label={`Status: ${displayLabel}`}
    >
      {displayLabel}
    </span>
  );
}
