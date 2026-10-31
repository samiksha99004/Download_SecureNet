/**
 * SecureNet — KPICard
 *
 * Key performance indicator card used on the Dashboard.
 * Handles loading, unavailable, and value states.
 */

import type { ReactNode } from 'react';
import { cn } from '../../utils/cn';
import { Spinner } from './LoadingState';
import styles from './KPICard.module.css';

interface KPICardProps {
  title: string;
  value: string | number | null | undefined;
  /** Sub-label below the value */
  subtitle?: string;
  icon?: ReactNode;
  /** Colour accent on the icon area */
  accent?: 'default' | 'low' | 'medium' | 'high' | 'info';
  isLoading?: boolean;
  className?: string;
}

export function KPICard({
  title,
  value,
  subtitle,
  icon,
  accent = 'default',
  isLoading = false,
  className,
}: KPICardProps) {
  return (
    <div className={cn(styles.card, className)} role="figure" aria-label={title}>
      <div className={styles.top}>
        <span className={styles.title}>{title}</span>
        {icon && (
          <div
            className={cn(styles.iconWrap, styles[`accent-${accent}`])}
            aria-hidden="true"
          >
            {icon}
          </div>
        )}
      </div>

      <div className={styles.valueRow}>
        {isLoading ? (
          <Spinner size="sm" />
        ) : value === null || value === undefined ? (
          <span className={styles.unavailable}>Not available</span>
        ) : (
          <span className={styles.value}>{value}</span>
        )}
      </div>

      {subtitle && !isLoading && (
        <p className={styles.subtitle}>{subtitle}</p>
      )}
    </div>
  );
}
