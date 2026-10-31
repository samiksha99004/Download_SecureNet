/**
 * SecureNet — Class Name Utility
 *
 * Thin wrapper around `clsx` for merging conditional class names.
 *
 * Usage:
 *   cn('base-class', isActive && 'active', variant === 'primary' && 'btn-primary')
 */

import { clsx, type ClassValue } from 'clsx';

export function cn(...inputs: ClassValue[]): string {
  return clsx(...inputs);
}
