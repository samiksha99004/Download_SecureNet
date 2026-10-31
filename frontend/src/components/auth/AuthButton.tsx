/**
 * SecureNet — AuthButton
 *
 * Primary and secondary button variants used in auth forms.
 */

import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { cn } from '../../utils/cn';
import { Spinner } from '../common/LoadingState';
import styles from './AuthButton.module.css';

interface AuthButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost';
  isLoading?: boolean;
  leftIcon?: ReactNode;
  children: ReactNode;
}

export function AuthButton({
  variant = 'primary',
  isLoading = false,
  leftIcon,
  children,
  disabled,
  className,
  ...rest
}: AuthButtonProps) {
  return (
    <button
      className={cn(styles.button, styles[variant], className)}
      disabled={disabled || isLoading}
      aria-busy={isLoading}
      {...rest}
    >
      {isLoading ? (
        <Spinner size="sm" />
      ) : (
        leftIcon && <span className={styles.icon} aria-hidden="true">{leftIcon}</span>
      )}
      <span>{children}</span>
    </button>
  );
}
