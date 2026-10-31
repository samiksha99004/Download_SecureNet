/**
 * SecureNet — TopSourcesCard
 *
 * Lists the top source IPs by anomaly/flow count.
 * IP addresses rendered in IBM Plex Mono.
 * No IP addresses are invented — empty state until backend connects.
 */

import type { TopSource } from '../../types/security.types';
import { LoadingState } from '../common/LoadingState';
import { EmptyState } from '../common/EmptyState';
import { IdsOffNote } from './IdsOffNote';
import { ErrorState } from '../common/ErrorState';
import { SeverityBadge } from '../common/SeverityBadge';
import { formatTimestamp } from '../../utils/format';
import styles from './TopSourcesCard.module.css';

interface TopSourcesCardProps {
  data: TopSource[];
  isLoading: boolean;
  isError: boolean;
  onRetry?: () => void;
  /** IDS is OFF: no live values on the dashboard */
  idsOff?: boolean;
}

export function TopSourcesCard({
  data,
  isLoading,
  isError,
  onRetry,
  idsOff = false,
}: TopSourcesCardProps) {
  if (idsOff) {
    return (
      <div className={styles.card}>
        <h3 className={styles.title}>Top Sources</h3>
        <IdsOffNote what="sources" />
      </div>
    );
  }
  return (
    <div className={styles.card}>
      <h3 className={styles.title}>Top Sources</h3>

      {isLoading && <LoadingState message="Loading sources…" />}

      {isError && !isLoading && (
        <ErrorState
          title="Unable to load sources"
          message="Could not load this information. Please try again."
          onRetry={onRetry}
        />
      )}

      {!isLoading && !isError && data.length === 0 && (
        <EmptyState
          title="No source data"
          description="No security events have been recorded yet."
        />
      )}

      {!isLoading && !isError && data.length > 0 && (
        <ul className={styles.list} role="list" aria-label="Top source IP addresses">
          {data.map((source, i) => (
            <li key={source.sourceIp} className={styles.item}>
              <span className={styles.rank} aria-hidden="true">{i + 1}</span>
              <div className={styles.info}>
                <span className={styles.ip}>{source.sourceIp}</span>
                <span className={styles.meta}>
                  Last seen: {formatTimestamp(source.lastSeen)}
                </span>
              </div>
              <div className={styles.stats}>
                <span className={styles.stat} title="Security events from this source (unresolved)">
                  {source.flowCount.toLocaleString()} event{source.flowCount !== 1 ? 's' : ''}
                  {source.anomalyCount > 0 && ` · ${source.anomalyCount.toLocaleString()} open`}
                </span>
                {source.highSeverityCount > 0 && (
                  <SeverityBadge severity="high" />
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
