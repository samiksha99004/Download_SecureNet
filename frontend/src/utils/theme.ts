/**
 * SecureNet — Theme (dark / light)
 *
 * The choice is remembered per browser and applied as <html data-theme>,
 * which switches every colour token in styles/globals.css. index.html applies
 * the saved theme before the app loads so there is no flash.
 */

import { useSyncExternalStore } from 'react';
import { storageGet, storageSet } from './storage';

export type Theme = 'dark' | 'light';

const THEME_KEY = 'sn_theme';
const EVENT = 'securenet:theme';

export function getTheme(): Theme {
  return storageGet(THEME_KEY) === 'light' ? 'light' : 'dark';
}

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'light' ? '#fbeee4' : '#0a1020');
}

export function setTheme(theme: Theme): void {
  storageSet(THEME_KEY, theme);
  applyTheme(theme);
  window.dispatchEvent(new Event(EVENT));
}

function subscribe(callback: () => void): () => void {
  window.addEventListener(EVENT, callback);
  return () => window.removeEventListener(EVENT, callback);
}

export function useTheme(): [Theme, (theme: Theme) => void] {
  const theme = useSyncExternalStore(subscribe, getTheme, () => 'dark' as Theme);
  return [theme, setTheme];
}
