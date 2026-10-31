/**
 * SecureNet — SecuritySummaryCard
 *
 * Shows severity breakdown (Low/Medium/High counts + proportional bars)
 * and attack type distribution list.
 * All values come from the backend — shows empty state until connected.
 */

import type { DashboardSummary } from '../../types/security.types';
import { LoadingState } from '../common/LoadingState';
import { ErrorState } from '../common/ErrorState';
import { EmptyState } from '../common/EmptyState';
import { IdsOffNote } from './IdsOffNote';
import styles from './SecuritySummaryCard.module.css';

interface SecuritySummaryCardProps {
  data: DashboardSummary | null;
  isLoading: boolean;
  isError: boolean;
  onRetry?: () => void;
  /** IDS is OFF: no live values on the dashboard */
  idsOff?: boolean;
}

interface SeverityBarProps {
  label: string;
  count: number;
  total: number;
  color: string;
  textColor: string;
}

function SeverityBar({ label, count, total, color, textColor }: SeverityBarProps) {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <div className={styles.severityRow}>
      <div className={styles.severityMeta}>
        <span className={styles.severityLabel} style={{ color: textColor }}>
          {label}
        </span>
        <span className={styles.severityCount}>{count.toLocaleString()}</span>
      </div>
      <div className={styles.barTrack} role="img" aria-label={`${label}: ${pct.toFixed(0)}%`}>
        <div
          className={styles.barFill}
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
    </div>
  );
}

export function SecuritySummaryCard({
  data,
  isLoading,
  isError,
  onRetry,
  idsOff = false,
}: SecuritySummaryCardProps) {
  if (idsOff) {
    return (
      <div className={styles.card}>
        <h3 className={styles.title}>Security Summary</h3>
        <IdsOffNote what="summary" />
      </div>
    );
  }
  const total = data
    ? data.severityBreakdown.low +
      data.severityBreakdown.medium +
      data.severityBreakdown.high
    : 0;

  return (
    <div className={styles.card}>
      <h3 className={styles.title}>Security Summary</h3>

      {isLoading && <LoadingState message="Loading summary…" />}
      {isError && !isLoading && (
        <ErrorState
          title="Unable to load summary"
          message="Could not load this information. Please try again."
          onRetry={onRetry}
        />
      )}

      {!isLoading && !isError && !data && (
        <EmptyState
          title="No summary data"
          description="Waiting for data…"
        />
      )}

      {!isLoading && !isError && data && (
        <div className={styles.content}>
          {/* Severity breakdown */}
          <section aria-label="Severity breakdown">
            <p className={styles.sectionLabel}>Severity Breakdown</p>
            <div className={styles.severityList}>
              <SeverityBar
                label="Low"
                count={data.severityBreakdown.low}
                total={total}
                color="var(--color-severity-low)"
                textColor="var(--color-severity-low)"
              />
              <SeverityBar
                label="Medium"
                count={data.severityBreakdown.medium}
                total={total}
                color="var(--color-severity-medium)"
                textColor="var(--color-severity-medium)"
              />
              <SeverityBar
                label="High"
                count={data.severityBreakdown.high}
                total={total}
                color="var(--color-severity-high)"
                textColor="var(--color-severity-high)"
              />
            </div>
          </section>

          {/* Attack type distribution */}
          <section aria-label="Attack type distribution">
            <p className={styles.sectionLabel}>Possible Attacks</p>
            {data.attackTypeDistribution.length === 0 ? (
              <p className={styles.noData}>No abnormal traffic yet.</p>
            ) : (
              <ul className={styles.attackList} role="list">
                {data.attackTypeDistribution.slice(0, 6).map((item) => (
                  <li key={item.attackType} className={styles.attackItem}>
                    <span className={styles.attackType}>{item.attackType}</span>
                    <span className={styles.attackCount}>
                      {item.count.toLocaleString()}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
