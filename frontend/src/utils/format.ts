/**
 * SecureNet — Formatting Utilities
 */

import type { SeverityLevel } from '../types/security.types';

// ── Date / Time ───────────────────────────────────────────────────────────────

/**
 * Format an ISO 8601 timestamp for display.
 * e.g. "14 Mar 2025, 09:42:15"
 */
export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    return new Intl.DateTimeFormat('en-GB', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}

/**
 * Format an ISO 8601 timestamp as a short time string.
 * e.g. "09:42:15"
 */
export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    return new Intl.DateTimeFormat('en-GB', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}

/**
 * Format an ISO 8601 timestamp as a date only.
 * e.g. "14 Mar 2025"
 */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    return new Intl.DateTimeFormat('en-GB', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}

/**
 * Format seconds as a human-readable duration.
 * e.g. 3661 → "1h 1m 1s"
 */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '—';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m}m ${s}s`;
  }
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return `${h}h ${m}m ${s}s`;
}

// ── Numbers ───────────────────────────────────────────────────────────────────

/**
 * Format a decimal score to a fixed number of decimal places.
 * e.g. 0.87321 → "0.873"
 */
export function formatScore(score: number | null | undefined, decimals = 3): string {
  if (score === null || score === undefined) return '—';
  return score.toFixed(decimals);
}

/**
 * Format a percentage.
 * e.g. 0.876 → "87.6%"
 */
export function formatPercent(
  value: number | null | undefined,
  decimals = 1
): string {
  if (value === null || value === undefined) return '—';
  return `${(value * 100).toFixed(decimals)}%`;
}

/**
 * Format bytes to a human-readable size.
 * e.g. 1536 → "1.5 KB"
 */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

/**
 * Format a large integer with commas.
 * e.g. 10000 → "10,000"
 */
export function formatNumber(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—';
  return new Intl.NumberFormat('en-US').format(n);
}

// ── Severity ──────────────────────────────────────────────────────────────────

export function severityLabel(severity: SeverityLevel): string {
  switch (severity) {
    case 'low': return 'Low';
    case 'medium': return 'Medium';
    case 'high': return 'High';
  }
}

export function severityColor(severity: SeverityLevel): string {
  switch (severity) {
    case 'low': return 'var(--color-severity-low)';
    case 'medium': return 'var(--color-severity-medium)';
    case 'high': return 'var(--color-severity-high)';
  }
}

// ── Text ──────────────────────────────────────────────────────────────────────

/**
 * Truncate text to a given length.
 */
export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}…`;
}

/**
 * Convert snake_case or camelCase to Title Case.
 * e.g. "dos_attack" → "Dos Attack"
 */
export function toTitleCase(str: string): string {
  return str
    .replace(/[_-]/g, ' ')
    .replace(/([A-Z])/g, ' $1')
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}
