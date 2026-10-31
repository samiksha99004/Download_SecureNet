/**
 * SecureNet — SearchInput
 */

import type { InputHTMLAttributes } from 'react';
import { Search, X } from 'lucide-react';
import { cn } from '../../utils/cn';
import styles from './SearchInput.module.css';

interface SearchInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'onChange'> {
  value: string;
  onChange: (value: string) => void;
  onClear?: () => void;
  className?: string;
}

export function SearchInput({
  value,
  onChange,
  onClear,
  placeholder = 'Search…',
  className,
  ...rest
}: SearchInputProps) {
  return (
    <div className={cn(styles.wrapper, className)}>
      <Search size={15} className={styles.icon} aria-hidden="true" />
      <input
        type="search"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={styles.input}
        aria-label={placeholder}
        {...rest}
      />
      {value && (
        <button
          type="button"
          className={styles.clearButton}
          onClick={() => { onChange(''); onClear?.(); }}
          aria-label="Clear search"
        >
          <X size={13} />
        </button>
      )}
    </div>
  );
}
