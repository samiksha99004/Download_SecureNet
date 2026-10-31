/**
 * SecureNet — Async Data Hook
 *
 * Generic hook for fetching async data with loading/error/success states.
 *
 *  - `isLoading` is true only while there is no data yet (first load); later
 *    refetches keep showing the current data (`isRefreshing` is true).
 *  - Responses that arrive after a newer request started are ignored, so
 *    fast filter changes can never show stale results.
 *
 * Usage:
 *   const { data, isLoading, isError, refetch } = useAsyncData(getDashboardSummary);
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import type { ApiError } from '../types/api.types';
import { ApiClientError } from '../services/apiClient';

type AsyncStatus = 'idle' | 'loading' | 'success' | 'error';

interface AsyncState<T> {
  data: T | null;
  status: AsyncStatus;
  error: ApiError | null;
}

interface UseAsyncDataOptions {
  /** Set to false to prevent fetching on mount */
  fetchOnMount?: boolean;
}

function toApiError(err: unknown): ApiError {
  if (err instanceof ApiClientError) {
    return { status: err.status, code: err.code, message: err.message, details: err.details };
  }
  return {
    status: 0,
    code: 'NETWORK_ERROR',
    message: err instanceof Error ? err.message : 'An unexpected error occurred.',
  };
}

export function useAsyncData<T>(
  fetcher: () => Promise<T>,
  options: UseAsyncDataOptions = {}
) {
  const { fetchOnMount = true } = options;
  const [state, setState] = useState<AsyncState<T>>({
    data: null,
    status: fetchOnMount ? 'loading' : 'idle',
    error: null,
  });

  const isMounted = useRef(true);
  const requestId = useRef(0);

  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
    };
  }, []);

  const execute = useCallback(async () => {
    const id = ++requestId.current;
    setState((prev) => ({ ...prev, status: 'loading' }));
    try {
      const data = await fetcher();
      if (isMounted.current && id === requestId.current) {
        setState({ data, status: 'success', error: null });
      }
    } catch (err) {
      if (isMounted.current && id === requestId.current) {
        setState((prev) => ({ data: prev.data, status: 'error', error: toApiError(err) }));
      }
    }
  }, [fetcher]);

  useEffect(() => {
    if (fetchOnMount) {
      void execute();
    }
  }, [execute, fetchOnMount]);

  return {
    ...state,
    refetch: execute,
    isLoading: state.status === 'loading' && state.data === null,
    isRefreshing: state.status === 'loading' && state.data !== null,
    isSuccess: state.status === 'success',
    isError: state.status === 'error' && state.data === null,
  };
}
