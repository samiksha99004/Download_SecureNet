/**
 * SecureNet — AuthDivider
 * "or" divider between primary and alternative auth actions.
 */

import styles from './AuthDivider.module.css';

interface AuthDividerProps {
  label?: string;
}

export function AuthDivider({ label = 'or' }: AuthDividerProps) {
  return (
    <div className={styles.divider} role="separator" aria-label={label}>
      <span className={styles.line} />
      <span className={styles.label}>{label}</span>
      <span className={styles.line} />
    </div>
  );
}
