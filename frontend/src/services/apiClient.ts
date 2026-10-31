/**
 * SecureNet — API Client
 *
 * Centralised HTTP client (base URL from VITE_API_BASE_URL).
 *  - Attaches the access token to every request
 *  - On 401 tries ONE silent refresh with the refresh token, then retries
 *  - Normalises every error into ApiClientError {status, code, message}
 *  - `download()` fetches files with the Authorization header (plain links
 *    cannot send it) and saves them via a temporary object URL
 *
 * All service files use this client — never raw fetch calls in components.
 */

import type { ApiError } from '../types/api.types';
import { storageGet, storageRemove, storageSet } from '../utils/storage';

// ── Configuration ─────────────────────────────────────────────────────────────

export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? '/api';

const ACCESS_TOKEN_KEY = 'sn_access_token';
const REFRESH_TOKEN_KEY = 'sn_refresh_token';
const USER_KEY = 'sn_user';

/** Fired on window when the session is gone (refresh failed). */
export const SESSION_EXPIRED_EVENT = 'securenet:session-expired';

// ── Error Handling ────────────────────────────────────────────────────────────

export class ApiClientError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: Record<string, string[]>;

  constructor(error: ApiError) {
    super(error.message);
    this.name = 'ApiClientError';
    this.status = error.status;
    this.code = error.code;
    this.details = error.details;
  }
}

async function parseErrorResponse(response: Response): Promise<ApiClientError> {
  let body: Partial<ApiError> & { detail?: unknown } = {};
  try {
    body = await response.json();
  } catch {
    // non-JSON error body
  }
  const message =
    (typeof body.message === 'string' && body.message) ||
    (typeof body.detail === 'string' && body.detail) ||
    'Something went wrong. Please try again.';
  return new ApiClientError({
    status: typeof body.status === 'number' ? body.status : response.status,
    code: typeof body.code === 'string' ? body.code : 'HTTP_ERROR',
    message,
    details: body.details as Record<string, string[]> | undefined,
  });
}

function networkError(): ApiClientError {
  return new ApiClientError({
    status: 0,
    code: 'NETWORK_ERROR',
    message: 'SecureNet can’t be reached right now. Please check that SecureNet is running and try again.',
  });
}

// ── Token Storage ─────────────────────────────────────────────────────────────

export const tokenStore = {
  getAccess: (): string | null => storageGet(ACCESS_TOKEN_KEY),
  getRefresh: (): string | null => storageGet(REFRESH_TOKEN_KEY),
  set(accessToken: string, refreshToken: string): void {
    storageSet(ACCESS_TOKEN_KEY, accessToken);
    storageSet(REFRESH_TOKEN_KEY, refreshToken);
  },
  clear(): void {
    storageRemove(ACCESS_TOKEN_KEY);
    storageRemove(REFRESH_TOKEN_KEY);
    storageRemove(USER_KEY);
  },
};

// Sessions saved by the previous app version (snake_case user, untyped JWTs)
// are not valid any more — drop them once instead of crashing on them.
const SESSION_FORMAT_KEY = 'sn_session_format';
const SESSION_FORMAT = '2';
if (storageGet(SESSION_FORMAT_KEY) !== SESSION_FORMAT) {
  tokenStore.clear();
  storageSet(SESSION_FORMAT_KEY, SESSION_FORMAT);
}

// ── Silent refresh (single in-flight request shared by all callers) ──────────

let refreshInFlight: Promise<boolean> | null = null;

async function tryRefresh(): Promise<boolean> {
  const refreshToken = tokenStore.getRefresh();
  if (!refreshToken) return false;
  refreshInFlight ??= (async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken }),
      });
      if (!response.ok) return false;
      const data = (await response.json()) as {
        tokens: { accessToken: string; refreshToken: string };
        user: unknown;
      };
      tokenStore.set(data.tokens.accessToken, data.tokens.refreshToken);
      storageSet(USER_KEY, JSON.stringify(data.user));
      return true;
    } catch {
      return false;
    } finally {
      setTimeout(() => { refreshInFlight = null; }, 0);
    }
  })();
  return refreshInFlight;
}

/** Seconds until a JWT expires (null if it can't be read). */
function secondsLeft(token: string): number | null {
  try {
    const part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(atob(part)) as { exp?: unknown };
    return typeof payload.exp === 'number' ? payload.exp - Date.now() / 1000 : null;
  } catch {
    return null;
  }
}

/**
 * The access token, refreshed first when it has (nearly) expired. For the live
 * WebSocket, which can't use the 401-refresh-retry path of normal requests.
 */
export async function freshAccessToken(): Promise<string | null> {
  const token = tokenStore.getAccess();
  if (!token) return null;
  const left = secondsLeft(token);
  if (left !== null && left > 30) return token;
  return (await tryRefresh()) ? tokenStore.getAccess() : token;
}

/** Get a new token pair now (e.g. the live connection rejected the token). */
export const refreshSession = tryRefresh;

function expireSession(): void {
  tokenStore.clear();
  window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
}

// ── Request Builder ───────────────────────────────────────────────────────────

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  headers?: Record<string, string>;
  /** Skip Authorization header (e.g. for login/signup) */
  skipAuth?: boolean;
}

async function rawFetch(path: string, options: RequestOptions): Promise<Response> {
  const { method = 'GET', body, headers = {}, skipAuth = false } = options;
  const resolvedHeaders: Record<string, string> = { ...headers };
  if (body !== undefined) resolvedHeaders['Content-Type'] = 'application/json';
  if (!skipAuth) {
    const token = tokenStore.getAccess();
    if (token) resolvedHeaders['Authorization'] = `Bearer ${token}`;
  }
  try {
    return await fetch(`${API_BASE_URL}${path}`, {
      method,
      headers: resolvedHeaders,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw networkError();
  }
}

/** Fetch with auth + one refresh-and-retry on 401. Throws ApiClientError. */
async function authorizedFetch(path: string, options: RequestOptions = {}): Promise<Response> {
  let response = await rawFetch(path, options);
  if (response.status === 401 && !options.skipAuth) {
    if (await tryRefresh()) {
      response = await rawFetch(path, options);
    }
    if (response.status === 401) {
      expireSession();
    }
  }
  if (!response.ok) throw await parseErrorResponse(response);
  return response;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const response = await authorizedFetch(path, options);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

/** Download a protected file and save it in the browser. */
async function download(path: string, fallbackName: string): Promise<void> {
  const response = await authorizedFetch(path);
  const disposition = response.headers.get('Content-Disposition') ?? '';
  const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition);
  const filename = match ? decodeURIComponent(match[1]) : fallbackName;

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ── Public API ────────────────────────────────────────────────────────────────

export const apiClient = {
  get: <T>(path: string, opts?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...opts, method: 'GET' }),

  post: <T>(path: string, body: unknown, opts?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...opts, method: 'POST', body }),

  put: <T>(path: string, body: unknown, opts?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...opts, method: 'PUT', body }),

  patch: <T>(path: string, body: unknown, opts?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...opts, method: 'PATCH', body }),

  delete: <T>(path: string, opts?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...opts, method: 'DELETE' }),

  download,
};
