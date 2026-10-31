/**
 * SecureNet — SeverityBadge Component
 *
 * Uses both colour AND a text label so colour is never the only indicator.
 */

import type { SeverityLevel } from '../../types/security.types';
import { cn } from '../../utils/cn';
import styles from './SeverityBadge.module.css';

interface SeverityBadgeProps {
  severity: SeverityLevel;
  className?: string;
}

const LABELS: Record<SeverityLevel, string> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
};

const ARIA_LABELS: Record<SeverityLevel, string> = {
  low: 'Severity: Low',
  medium: 'Severity: Medium',
  high: 'Severity: High',
};

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span
      className={cn(styles.badge, styles[severity], className)}
      aria-label={ARIA_LABELS[severity]}
    >
      <span className={styles.dot} aria-hidden="true" />
      {LABELS[severity]}
    </span>
  );
}
