/**
 * SecureNet — EventsTable
 *
 * Full sortable event history table with all 9 columns.
 * Clicking a row opens the IncidentDetailsDrawer.
 * Clicking a column header cycles sort asc/desc.
 */

import { ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react';
import type { SecurityEvent } from '../../types/security.types';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import { EmptyState } from '../common/EmptyState';
import { LoadingState } from '../common/LoadingState';
import { ErrorState } from '../common/ErrorState';
import { formatTimestamp, formatScore } from '../../utils/format';
import type { SortOrder } from '../../hooks/useEventFilters';
import styles from './EventsTable.module.css';
import { possibleAttack } from '../../utils/verdict';

interface Column {
  key: string;
  label: string;
  sortable?: boolean;
}

const COLUMNS: Column[] = [
  { key: 'timestamp',       label: 'Time',         sortable: true  },
  { key: 'sourceIp',        label: 'Source',        sortable: true  },
  { key: 'destinationIp',   label: 'Destination',   sortable: false },
  { key: 'anomalyScore',    label: 'Score',         sortable: true  },
  { key: 'severity',        label: 'Severity',      sortable: true  },
  { key: 'attackType',      label: 'Possible Attack', sortable: true  },
  { key: 'state',           label: 'State',         sortable: true  },
  { key: 'actionTaken',     label: 'Action',        sortable: false },
];

interface EventsTableProps {
  events: SecurityEvent[];
  isLoading: boolean;
  isError: boolean;
  sortBy: string;
  sortOrder: SortOrder;
  onSort: (key: string) => void;
  onRowClick: (event: SecurityEvent) => void;
  onRetry?: () => void;
}

function SortIcon({
  col,
  sortBy,
  sortOrder,
}: {
  col: string;
  sortBy: string;
  sortOrder: SortOrder;
}) {
  if (col !== sortBy) return <ChevronsUpDown size={12} className={styles.sortIcon} aria-hidden="true" />;
  return sortOrder === 'asc'
    ? <ChevronUp   size={12} className={styles.sortIconActive} aria-hidden="true" />
    : <ChevronDown size={12} className={styles.sortIconActive} aria-hidden="true" />;
}

export function EventsTable({
  events,
  isLoading,
  isError,
  sortBy,
  sortOrder,
  onSort,
  onRowClick,
  onRetry,
}: EventsTableProps) {
  if (isLoading) return <LoadingState message="Loading events…" />;

  if (isError) {
    return (
      <ErrorState
        title="Unable to load events"
        message="Could not load events. Please try again."
        onRetry={onRetry}
      />
    );
  }

  if (events.length === 0) {
    return (
      <EmptyState
        title="No security events available."
        description="No events match the current filters."
      />
    );
  }

  return (
    <div
      className={styles.tableWrapper}
      role="region"
      aria-label="Security event history"
    >
      <table className={styles.table}>
        <thead>
          <tr>
            {COLUMNS.map((col) => (
              <th
                key={col.key}
                scope="col"
                className={styles.th}
                aria-sort={
                  col.key === sortBy
                    ? sortOrder === 'asc'
                      ? 'ascending'
                      : 'descending'
                    : col.sortable
                    ? 'none'
                    : undefined
                }
              >
                {col.sortable ? (
                  <button
                    className={styles.sortButton}
                    onClick={() => onSort(col.key)}
                    aria-label={`Sort by ${col.label}`}
                  >
                    {col.label}
                    <SortIcon col={col.key} sortBy={sortBy} sortOrder={sortOrder} />
                  </button>
                ) : (
                  col.label
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr
              key={event.id}
              className={styles.tr}
              onClick={() => onRowClick(event)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') onRowClick(event);
              }}
              tabIndex={0}
              role="button"
              aria-label={`View details for event ${event.id}`}
            >
              <td className={styles.td}>
                <span className={styles.mono}>{formatTimestamp(event.timestamp)}</span>
              </td>
              <td className={styles.td}>
                <span className={styles.mono}>
                  {event.sourceIp}
                  <span className={styles.port}>:{event.sourcePort}</span>
                </span>
              </td>
              <td className={styles.td}>
                <span className={styles.mono}>
                  {event.destinationIp}
                  <span className={styles.port}>:{event.destinationPort}</span>
                </span>
              </td>
              <td className={styles.td}>
                <span className={styles.mono}>{formatScore(event.anomalyScore)}</span>
              </td>
              <td className={styles.td}>
                <SeverityBadge severity={event.severity} />
              </td>
              <td className={styles.td}>
                {event.attackType || event.attackGuesses?.length ? possibleAttack(event) : (
                  <span className={styles.normal}>Unknown</span>
                )}
              </td>
              <td className={styles.td}>
                <StatusBadge
                  status={
                    event.state as
                      | 'active'
                      | 'investigating'
                      | 'resolved'
                      | 'false_positive'
                  }
                />
              </td>
              <td className={styles.td}>
                <span className={styles.action}>{event.actionTaken}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
