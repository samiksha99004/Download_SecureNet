/**
 * SecureNet — SettingsField
 *
 * A labelled row used in settings forms.
 * Supports toggle (checkbox), text input, number input, and select.
 */

import type { ReactNode, ChangeEvent } from 'react';
import styles from './SettingsField.module.css';

interface BaseProps {
  label: string;
  hint?: string;
  id: string;
  disabled?: boolean;
}

interface ToggleProps extends BaseProps {
  type: 'toggle';
  checked: boolean;
  onChange: (checked: boolean) => void;
}

interface TextProps extends BaseProps {
  type: 'text' | 'email' | 'number';
  value: string | number;
  onChange: (value: string) => void;
  min?: number;
  max?: number;
  step?: number;
  placeholder?: string;
}

interface SelectProps extends BaseProps {
  type: 'select';
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
}

interface CustomProps extends BaseProps {
  type: 'custom';
  children: ReactNode;
}

type SettingsFieldProps = ToggleProps | TextProps | SelectProps | CustomProps;

export function SettingsField(props: SettingsFieldProps) {
  return (
    <div className={styles.row}>
      <div className={styles.labelGroup}>
        <label htmlFor={props.id} className={styles.label}>
          {props.label}
        </label>
        {props.hint && <p className={styles.hint}>{props.hint}</p>}
      </div>
      <div className={styles.control}>
        {props.type === 'toggle' && (
          <button
            id={props.id}
            role="switch"
            aria-checked={props.checked}
            className={`${styles.toggle} ${props.checked ? styles.toggleOn : ''}`}
            onClick={() => !props.disabled && props.onChange(!props.checked)}
            disabled={props.disabled}
            type="button"
          >
            <span className={styles.toggleThumb} />
            <span className="sr-only">{props.checked ? 'On' : 'Off'}</span>
          </button>
        )}

        {(props.type === 'text' || props.type === 'email') && (
          <input
            id={props.id}
            type={props.type}
            value={props.value}
            onChange={(e: ChangeEvent<HTMLInputElement>) => props.onChange(e.target.value)}
            placeholder={props.placeholder}
            disabled={props.disabled}
            className={styles.input}
          />
        )}

        {props.type === 'number' && (
          <input
            id={props.id}
            type="number"
            value={props.value}
            onChange={(e: ChangeEvent<HTMLInputElement>) => props.onChange(e.target.value)}
            min={props.min}
            max={props.max}
            step={props.step}
            disabled={props.disabled}
            className={styles.inputNumber}
          />
        )}

        {props.type === 'select' && (
          <select
            id={props.id}
            value={props.value}
            onChange={(e: ChangeEvent<HTMLSelectElement>) => props.onChange(e.target.value)}
            disabled={props.disabled}
            className={styles.select}
          >
            {props.options.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        )}

        {props.type === 'custom' && props.children}
      </div>
    </div>
  );
}
