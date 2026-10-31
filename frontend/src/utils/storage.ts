/**
 * SecureNet — Safe Web Storage
 *
 * localStorage / sessionStorage throw (SecurityError) when the browser blocks
 * site data, and can throw on quota. Every access goes through these helpers
 * so a storage problem degrades to "not remembered" instead of a blank page.
 */

type Area = 'local' | 'session';

function area(kind: Area): Storage | null {
  try {
    return kind === 'local' ? window.localStorage : window.sessionStorage;
  } catch {
    return null;
  }
}

export function storageGet(key: string, kind: Area = 'local'): string | null {
  try {
    return area(kind)?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

export function storageSet(key: string, value: string, kind: Area = 'local'): void {
  try {
    area(kind)?.setItem(key, value);
  } catch {
    // storage blocked or full — value is simply not remembered
  }
}

export function storageRemove(key: string, kind: Area = 'local'): void {
  try {
    area(kind)?.removeItem(key);
  } catch {
    // ignore
  }
}

/** Parse a JSON value from storage; returns `fallback` when missing or corrupt. */
export function storageGetJson<T>(key: string, fallback: T, kind: Area = 'local'): T {
  const raw = storageGet(key, kind);
  if (raw === null) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}
