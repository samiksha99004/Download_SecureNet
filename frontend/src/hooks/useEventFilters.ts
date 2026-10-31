/**
 * SecureNet — useEventFilters hook
 *
 * Manages the complete filter + pagination + sort state for the
 * History page. Keeps all query state in one place so filters,
 * table, and pagination stay in sync.
 */

import { useCallback, useState } from 'react';
import type { EventFilterParams } from '../types/api.types';

export type SortOrder = 'asc' | 'desc';

export interface HistoryFilters
  extends Omit<EventFilterParams, 'sortBy' | 'sortOrder'> {
  sortBy: string;
  sortOrder: SortOrder;
}

const DEFAULT_FILTERS: HistoryFilters = {
  page: 1,
  pageSize: 20,
  sortBy: 'timestamp',
  sortOrder: 'desc',
  search: null,
  severity: null,
  state: null,
  mode: null,
  attackType: null,
  protocol: null,
  from: null,
  to: null,
};

export function useEventFilters() {
  const [filters, setFilters] = useState<HistoryFilters>(DEFAULT_FILTERS);

  const setSearch = useCallback((value: string) => {
    setFilters((prev) => ({
      ...prev,
      search: value.trim() || null,
      page: 1,
    }));
  }, []);

  const setFilter = useCallback(
    (key: keyof Omit<HistoryFilters, 'page' | 'pageSize' | 'sortBy' | 'sortOrder'>, value: string | null) => {
      setFilters((prev) => ({ ...prev, [key]: value || null, page: 1 }));
    },
    []
  );

  const setPage = useCallback((page: number) => {
    setFilters((prev) => ({ ...prev, page }));
  }, []);

  const setSort = useCallback((sortBy: string) => {
    setFilters((prev) => ({
      ...prev,
      sortBy,
      sortOrder:
        prev.sortBy === sortBy && prev.sortOrder === 'asc' ? 'desc' : 'asc',
      page: 1,
    }));
  }, []);

  const resetFilters = useCallback(() => {
    setFilters(DEFAULT_FILTERS);
  }, []);

  const hasActiveFilters =
    filters.search !== null ||
    filters.severity !== null ||
    filters.state !== null ||
    filters.mode !== null ||
    filters.attackType !== null ||
    filters.protocol !== null ||
    filters.from !== null ||
    filters.to !== null;

  return {
    filters,
    setSearch,
    setFilter,
    setPage,
    setSort,
    resetFilters,
    hasActiveFilters,
  };
}
