/**
 * SecureNet — History Page
 *
 * Complete security event history with:
 *  - Summary cards (total / severity counts)
 *  - Filter toolbar (search, severity, state, mode, protocol)
 *  - Sortable event table
 *  - Pagination
 *  - Incident Details Drawer (with resolve / false-positive actions)
 *  - CSV / PDF export of the filtered events (authenticated download)
 *
 * Data fetched via eventsService → useAsyncData.
 * All filter/pagination state managed by useEventFilters.
 * No hardcoded security data.
 */

import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { MainLayout } from '../components/layout/MainLayout';
import { PageHeader } from '../components/common/PageHeader';
import { Pagination } from '../components/common/Pagination';
import { HistoryFilters } from '../components/history/HistoryFilters';
import { HistorySummaryCards, type HistoryCounts } from '../components/history/HistorySummaryCards';
import type { EventFilterParams } from '../types/api.types';
import { EventsTable } from '../components/history/EventsTable';
import { IncidentDetailsDrawer } from '../components/history/IncidentDetailsDrawer';
import { ExportButton } from '../components/history/ExportButton';
import { useEventFilters } from '../hooks/useEventFilters';
import { useAsyncData } from '../hooks/useAsyncData';
import { useToast } from '../components/common/Toast';
import { useAuth } from '../contexts/AuthContext';
import { getEvents, getEventById, resolveEvent, markFalsePositive } from '../services/eventsService';
import type { SecurityEvent } from '../types/security.types';
import styles from './HistoryPage.module.css';
import { errorMessage } from '../utils/errors';

export function HistoryPage() {
  const {
    filters,
    setSearch,
    setFilter,
    setPage,
    setSort,
    resetFilters,
    hasActiveFilters,
  } = useEventFilters();

  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const { showToast } = useToast();
  const { isAdmin } = useAuth();

  // Fetch events whenever filters change
  const fetcher = useCallback(
    () => getEvents(filters),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [JSON.stringify(filters)]
  );

  const { data, isLoading, isError, refetch } = useAsyncData(fetcher);

  // Overall counts for the summary cards (independent of the table filters)
  const countsFetcher = useCallback(async (): Promise<HistoryCounts> => {
    const count = async (params: Partial<EventFilterParams>) =>
      (await getEvents({ ...params, page: 1, pageSize: 1 })).total;
    const [total, high, medium, resolved] = await Promise.all([
      count({}),
      count({ severity: 'high' }),
      count({ severity: 'medium' }),
      count({ state: 'resolved' }),
    ]);
    return { total, high, medium, resolved };
  }, []);
  const counts = useAsyncData(countsFetcher);
  const refetchCounts = counts.refetch;

  const handleRowClick = useCallback((event: SecurityEvent) => {
    setSelectedEvent(event);
    setDrawerOpen(true);
  }, []);

  // Deep link from a notification: /history?event=<id> opens that incident
  const [searchParams, setSearchParams] = useSearchParams();
  const focusEventId = searchParams.get('event');
  useEffect(() => {
    if (!focusEventId) return;
    let cancelled = false;
    getEventById(focusEventId)
      .then((event) => {
        if (cancelled) return;
        setSelectedEvent(event);
        setDrawerOpen(true);
      })
      .catch((err: unknown) => {
        if (!cancelled) showToast({ message: errorMessage(err, 'Could not open the incident.'), variant: 'error' });
      });
    return () => {
      cancelled = true;
    };
  }, [focusEventId, showToast]);

  const handleCloseDrawer = useCallback(() => {
    setDrawerOpen(false);
    if (searchParams.has('event')) setSearchParams({}, { replace: true });
  }, [searchParams, setSearchParams]);

  // ── Resolve / False-positive ──────────────────────────────────────────────

  const handleResolve = useCallback(async (id: string) => {
    try {
      await resolveEvent(id);
      showToast({ message: 'Event marked as resolved.', variant: 'success' });
      void refetch();
      void refetchCounts();
      // Update the selected event state optimistically
      setSelectedEvent((prev) =>
        prev && prev.id === id ? { ...prev, state: 'resolved' } : prev
      );
    } catch (err) {
      showToast({ message: errorMessage(err, 'Could not resolve event.'), variant: 'error' });
    }
  }, [refetch, refetchCounts, showToast]);

  const handleMarkFalsePositive = useCallback(async (id: string) => {
    try {
      await markFalsePositive(id);
      showToast({ message: 'Event marked as false positive.', variant: 'success' });
      void refetch();
      void refetchCounts();
      setSelectedEvent((prev) =>
        prev && prev.id === id ? { ...prev, state: 'false_positive' } : prev
      );
    } catch (err) {
      showToast({ message: errorMessage(err, 'Could not update event.'), variant: 'error' });
    }
  }, [refetch, refetchCounts, showToast]);

  return (
    <MainLayout title="Event History">
      <div className={styles.page}>
        <PageHeader
          title="Event History"
          description="Browse and investigate all detected security events."
          actions={
            <ExportButton
              filters={filters}
              totalEvents={data?.total ?? null}
              disabled={isLoading || isError}
            />
          }
        />

        {/* Summary cards */}
        <HistorySummaryCards
          counts={counts.data}
          isLoading={counts.isLoading}
        />

        {/* Filters */}
        <HistoryFilters
          filters={filters}
          onSearch={setSearch}
          onFilter={setFilter}
          onReset={resetFilters}
          hasActiveFilters={hasActiveFilters}
        />

        {/* Results count */}
        {!isLoading && data && (
          <div className={styles.resultsInfo} aria-live="polite">
            <span className={styles.resultsCount}>
              {data.total.toLocaleString()} event{data.total !== 1 ? 's' : ''}
            </span>
            {hasActiveFilters && (
              <span className={styles.filterNote}>matching current filters</span>
            )}
          </div>
        )}

        {/* Events table */}
        <EventsTable
          events={data?.data ?? []}
          isLoading={isLoading}
          isError={isError}
          sortBy={filters.sortBy}
          sortOrder={filters.sortOrder}
          onSort={setSort}
          onRowClick={handleRowClick}
          onRetry={refetch}
        />

        {/* Pagination */}
        {data && data.totalPages > 1 && (
          <div className={styles.paginationRow}>
            <Pagination
              page={filters.page}
              totalPages={data.totalPages}
              onPageChange={setPage}
            />
            <span className={styles.pageInfo}>
              Page {filters.page} of {data.totalPages}
            </span>
          </div>
        )}
      </div>

      {/* Incident Details Drawer */}
      <IncidentDetailsDrawer
        event={selectedEvent}
        isOpen={drawerOpen}
        onClose={handleCloseDrawer}
        onResolve={isAdmin ? handleResolve : undefined}
        onMarkFalsePositive={isAdmin ? handleMarkFalsePositive : undefined}
      />
    </MainLayout>
  );
}
