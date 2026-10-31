/**
 * SecureNet — FormField
 *
 * Labelled input wrapper with error and hint support.
 * Accepts all standard input attributes via spread.
 */

import {
  type InputHTMLAttributes,
  type ReactNode,
  forwardRef,
} from 'react';
import { cn } from '../../utils/cn';
import styles from './FormField.module.css';

interface FormFieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  id: string;
  error?: string;
  hint?: string;
  rightElement?: ReactNode;
}

export const FormField = forwardRef<HTMLInputElement, FormFieldProps>(
  ({ label, id, error, hint, rightElement, className, ...inputProps }, ref) => {
    const describedBy = [
      error ? `${id}-error` : null,
      hint ? `${id}-hint` : null,
    ]
      .filter(Boolean)
      .join(' ');

    return (
      <div className={styles.field}>
        <label htmlFor={id} className={styles.label}>
          {label}
        </label>
        <div className={styles.inputWrapper}>
          <input
            ref={ref}
            id={id}
            className={cn(styles.input, error && styles.inputError, className)}
            aria-invalid={error ? 'true' : undefined}
            aria-describedby={describedBy || undefined}
            {...inputProps}
          />
          {rightElement && (
            <span className={styles.rightElement}>{rightElement}</span>
          )}
        </div>
        {error && (
          <p id={`${id}-error`} className={styles.error} role="alert">
            {error}
          </p>
        )}
        {hint && !error && (
          <p id={`${id}-hint`} className={styles.hint}>
            {hint}
          </p>
        )}
      </div>
    );
  }
);

FormField.displayName = 'FormField';
