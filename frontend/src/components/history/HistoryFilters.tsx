/**
 * SecureNet — HistoryFilters
 *
 * Filter toolbar for the History page.
 * Contains search input + dropdown filters for severity, state,
 * mode, attack type, and protocol.
 */

import { RotateCcw } from 'lucide-react';
import { SearchInput } from '../common/SearchInput';
import { FilterDropdown, type FilterOption } from '../common/FilterDropdown';
import type { HistoryFilters as FiltersState } from '../../hooks/useEventFilters';
import styles from './HistoryFilters.module.css';

interface HistoryFiltersProps {
  filters: FiltersState;
  onSearch: (value: string) => void;
  onFilter: (
    key: keyof Omit<FiltersState, 'page' | 'pageSize' | 'sortBy' | 'sortOrder'>,
    value: string | null
  ) => void;
  onReset: () => void;
  hasActiveFilters: boolean;
}

const ALL_OPT: FilterOption = { value: '', label: 'All' };

const SEVERITY_OPTIONS: FilterOption[] = [
  ALL_OPT,
  { value: 'low',    label: 'Low'    },
  { value: 'medium', label: 'Medium' },
  { value: 'high',   label: 'High'   },
];

const STATE_OPTIONS: FilterOption[] = [
  ALL_OPT,
  { value: 'active',          label: 'Active'         },
  { value: 'investigating',   label: 'Investigating'   },
  { value: 'resolved',        label: 'Resolved'        },
  { value: 'false_positive',  label: 'False Positive'  },
];

const PROTOCOL_OPTIONS: FilterOption[] = [
  ALL_OPT,
  { value: 'TCP',   label: 'TCP'   },
  { value: 'UDP',   label: 'UDP'   },
  { value: 'ICMP',  label: 'ICMP'  },
  { value: 'other', label: 'Other' },
];

export function HistoryFilters({
  filters,
  onSearch,
  onFilter,
  onReset,
  hasActiveFilters,
}: HistoryFiltersProps) {
  return (
    <div className={styles.wrapper}>
      {/* Search */}
      <SearchInput
        value={filters.search ?? ''}
        onChange={onSearch}
        placeholder="Search IP, attack type…"
        className={styles.search}
      />

      {/* Dropdowns */}
      <div className={styles.dropdowns}>
        <FilterDropdown
          label="Severity"
          options={SEVERITY_OPTIONS}
          value={filters.severity ?? ''}
          onChange={(v) => onFilter('severity', v || null)}
        />
        <FilterDropdown
          label="State"
          options={STATE_OPTIONS}
          value={filters.state ?? ''}
          onChange={(v) => onFilter('state', v || null)}
        />
        <FilterDropdown
          label="Protocol"
          options={PROTOCOL_OPTIONS}
          value={filters.protocol ?? ''}
          onChange={(v) => onFilter('protocol', v || null)}
        />
      </div>

      {/* Reset */}
      {hasActiveFilters && (
        <button
          type="button"
          className={styles.resetButton}
          onClick={onReset}
          aria-label="Reset all filters"
        >
          <RotateCcw size={13} aria-hidden="true" />
          Reset
        </button>
      )}
    </div>
  );
}
