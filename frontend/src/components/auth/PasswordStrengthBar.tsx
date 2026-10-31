/**
 * SecureNet — PasswordStrengthBar
 *
 * Visual indicator of password strength.
 * Uses text label + colour so it's not colour-only.
 */

import { getPasswordStrength } from '../../utils/validation';
import styles from './PasswordStrengthBar.module.css';

interface PasswordStrengthBarProps {
  password: string;
}

export function PasswordStrengthBar({ password }: PasswordStrengthBarProps) {
  if (!password) return null;

  const { score, label, color } = getPasswordStrength(password);
  const segments = 4;

  return (
    <div className={styles.container} aria-live="polite">
      <div className={styles.bars} role="img" aria-label={`Password strength: ${label}`}>
        {Array.from({ length: segments }).map((_, i) => (
          <div
            key={i}
            className={styles.segment}
            style={{
              backgroundColor: i < score ? color : 'var(--color-border)',
            }}
          />
        ))}
      </div>
      <span className={styles.label} style={{ color }}>
        {label}
      </span>
    </div>
  );
}
