/**
 * SecureNet — EmptyState Component
 *
 * Displays a consistent empty/no-data state.
 */

import type { ReactNode } from 'react';
import { cn } from '../../utils/cn';
import styles from './EmptyState.module.css';

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div className={cn(styles.container, className)} role="status" aria-live="polite">
      {icon && <div className={styles.icon} aria-hidden="true">{icon}</div>}
      <p className={styles.title}>{title}</p>
      {description && <p className={styles.description}>{description}</p>}
      {action && <div className={styles.action}>{action}</div>}
    </div>
  );
}
