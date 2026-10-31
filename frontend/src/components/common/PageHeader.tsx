/**
 * SecureNet — PageHeader
 *
 * Consistent in-page header with title, optional description,
 * and optional right-side action slot.
 */

import type { ReactNode } from 'react';
import { cn } from '../../utils/cn';
import styles from './PageHeader.module.css';

interface PageHeaderProps {
  title: string;
  description?: string;
  actions?: ReactNode;
  className?: string;
}

export function PageHeader({
  title,
  description,
  actions,
  className,
}: PageHeaderProps) {
  return (
    <div className={cn(styles.header, className)}>
      <div className={styles.text}>
        <h2 className={styles.title}>{title}</h2>
        {description && (
          <p className={styles.description}>{description}</p>
        )}
      </div>
      {actions && <div className={styles.actions}>{actions}</div>}
    </div>
  );
}
