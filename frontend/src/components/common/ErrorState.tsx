/**
 * SecureNet — ErrorState Component
 */

import { AlertTriangle } from 'lucide-react';
import { cn } from '../../utils/cn';
import styles from './ErrorState.module.css';

interface ErrorStateProps {
  title?: string;
  message?: string;
  onRetry?: () => void;
  className?: string;
}

export function ErrorState({
  title = 'Unable to load data',
  message = 'An error occurred. Please try again.',
  onRetry,
  className,
}: ErrorStateProps) {
  return (
    <div className={cn(styles.container, className)} role="alert">
      <AlertTriangle className={styles.icon} size={24} aria-hidden="true" />
      <p className={styles.title}>{title}</p>
      <p className={styles.message}>{message}</p>
      {onRetry && (
        <button className={styles.retryButton} onClick={onRetry} type="button">
          Try again
        </button>
      )}
    </div>
  );
}
