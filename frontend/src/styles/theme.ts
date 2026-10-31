/**
 * SecureNet Design System — Theme Tokens
 *
 * Single source of truth for all design tokens.
 * Use these constants in components and CSS custom properties.
 */

// ── Colour Palette (dark theme — mirrors styles/globals.css) ────────────────────────────────────────────────────────────

export const colors = {
  // Base
  white: '#111A2B',
  peachLightest: '#0A1020',
  peachLight: '#1A2740',
  peachAccent: '#22D3EE',
  peachDark: '#38BDF8',

  // Text
  text: '#E2E8F0',
  textMuted: '#94A3B8',

  // Border / Surface
  border: '#22304A',
  surface: '#0E1627',

  // Severity / Status
  severityLow: '#34D399',
  severityMedium: '#FBBF24',
  severityHigh: '#F87171',
  severityInfo: '#60A5FA',

  // Semantic aliases
  success: '#34D399',
  warning: '#FBBF24',
  error: '#F87171',
  info: '#60A5FA',
} as const;

export type ColorToken = keyof typeof colors;

// ── Typography ────────────────────────────────────────────────────────────────

export const fonts = {
  /** Logo, headings, KPI numbers, important titles */
  heading: "'Space Grotesk', sans-serif",
  /** Body, forms, navigation, buttons, general UI */
  body: "'IBM Plex Sans', sans-serif",
  /** IPs, ports, scores, timestamps, technical values */
  mono: "'IBM Plex Mono', monospace",
} as const;

export const fontSizes = {
  xs: '0.75rem',   // 12px
  sm: '0.875rem',  // 14px
  base: '1rem',    // 16px
  lg: '1.125rem',  // 18px
  xl: '1.25rem',   // 20px
  '2xl': '1.5rem', // 24px
  '3xl': '1.875rem', // 30px
  '4xl': '2.25rem',  // 36px
} as const;

export const fontWeights = {
  regular: 400,
  medium: 500,
  semibold: 600,
  bold: 700,
} as const;

// ── Spacing ───────────────────────────────────────────────────────────────────

export const spacing = {
  1: '0.25rem',   // 4px
  2: '0.5rem',    // 8px
  3: '0.75rem',   // 12px
  4: '1rem',      // 16px
  5: '1.25rem',   // 20px
  6: '1.5rem',    // 24px
  8: '2rem',      // 32px
  10: '2.5rem',   // 40px
  12: '3rem',     // 48px
  16: '4rem',     // 64px
  20: '5rem',     // 80px
} as const;

// ── Border Radius ─────────────────────────────────────────────────────────────

export const radius = {
  sm: '4px',
  md: '8px',
  lg: '12px',
  xl: '16px',
  full: '9999px',
} as const;

// ── Shadows ───────────────────────────────────────────────────────────────────

export const shadows = {
  sm: '0 1px 3px rgba(0, 0, 0, 0.45)',
  md: '0 4px 12px rgba(0, 0, 0, 0.5)',
  lg: '0 8px 24px rgba(0, 0, 0, 0.6)',
} as const;

// ── Transitions ───────────────────────────────────────────────────────────────

export const transitions = {
  fast: '150ms ease',
  base: '200ms ease',
  slow: '300ms ease',
} as const;

// ── Layout ────────────────────────────────────────────────────────────────────

export const layout = {
  sidebarWidth: '240px',
  sidebarCollapsedWidth: '64px',
  topbarHeight: '60px',
  maxContentWidth: '1400px',
} as const;

// ── Breakpoints ───────────────────────────────────────────────────────────────

export const breakpoints = {
  sm: '640px',
  md: '768px',
  lg: '1024px',
  xl: '1280px',
  '2xl': '1536px',
} as const;
