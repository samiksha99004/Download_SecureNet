/**
 * SecureNet — FilterDropdown
 *
 * Native <select>-based filter control with consistent SecureNet styling.
 */

import type { SelectHTMLAttributes } from 'react';
import { ChevronDown } from 'lucide-react';
import { cn } from '../../utils/cn';
import styles from './FilterDropdown.module.css';

export interface FilterOption {
  value: string;
  label: string;
}

interface FilterDropdownProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, 'onChange'> {
  label: string;
  options: FilterOption[];
  value: string;
  onChange: (value: string) => void;
  className?: string;
}

export function FilterDropdown({
  label,
  options,
  value,
  onChange,
  className,
  ...rest
}: FilterDropdownProps) {
  const selectId = `filter-${label.toLowerCase().replace(/\s+/g, '-')}`;

  return (
    <div className={cn(styles.wrapper, className)}>
      <label htmlFor={selectId} className={styles.label}>
        {label}
      </label>
      <div className={styles.selectWrapper}>
        <select
          id={selectId}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className={styles.select}
          {...rest}
        >
          {options.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <ChevronDown size={13} className={styles.chevron} aria-hidden="true" />
      </div>
    </div>
  );
}
