/**
 * SecureNet — API / HTTP Types
 *
 * Common shapes for API requests, responses, pagination, and errors.
 */

// ── Paginated Response ────────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

// ── API Error ─────────────────────────────────────────────────────────────────

export interface ApiError {
  status: number;
  code: string;
  message: string;
  details?: Record<string, string[]>;
}

// ── Query Params ──────────────────────────────────────────────────────────────

export interface PaginationParams {
  page: number;
  pageSize: number;
}

export interface SortParams {
  sortBy: string;
  sortOrder: 'asc' | 'desc';
}

export interface DateRangeParams {
  from: string | null;   // ISO 8601
  to: string | null;     // ISO 8601
}

export interface EventFilterParams extends PaginationParams, SortParams, DateRangeParams {
  search: string | null;
  severity: string | null;
  state: string | null;
  mode: string | null;
  attackType: string | null;
  protocol: string | null;
}

// ── Common Response ───────────────────────────────────────────────────────────

export interface MessageResponse {
  message: string;
}

// ── Generic Result ────────────────────────────────────────────────────────────

export type AsyncResult<T> =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; data: T }
  | { status: 'error'; error: ApiError };
