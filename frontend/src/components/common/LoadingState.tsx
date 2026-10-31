/**
 * SecureNet — LoadingState Component
 */

import { cn } from '../../utils/cn';
import styles from './LoadingState.module.css';

interface LoadingStateProps {
  message?: string;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  inline?: boolean;
}

export function LoadingState({
  message = 'Loading…',
  size = 'md',
  className,
  inline = false,
}: LoadingStateProps) {
  return (
    <div
      className={cn(
        styles.container,
        inline && styles.inline,
        className
      )}
      role="status"
      aria-live="polite"
      aria-label={message}
    >
      <span
        className={cn(styles.spinner, styles[size])}
        aria-hidden="true"
      />
      <span className={styles.message}>{message}</span>
    </div>
  );
}

/** Minimal spinner only — no text */
export function Spinner({ size = 'md', className }: { size?: 'sm' | 'md' | 'lg'; className?: string }) {
  return (
    <span
      className={cn(styles.spinner, styles[size], className)}
      role="status"
      aria-label="Loading"
    />
  );
}
