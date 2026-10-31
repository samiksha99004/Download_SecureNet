/**
 * SecureNet — HostStatusCard
 *
 * Displays the monitored host: name, network throughput, uptime and OS.
 * All values come from the backend. Shows "Not available" until connected.
 */

import { Network, Clock, Monitor } from 'lucide-react';
import type { HostStatus } from '../../types/security.types';
import { formatBytes, formatDuration } from '../../utils/format';
import { LoadingState } from '../common/LoadingState';
import { ErrorState } from '../common/ErrorState';
import styles from './HostStatusCard.module.css';

interface HostStatusCardProps {
  data: HostStatus | null;
  isLoading: boolean;
  isError: boolean;
  onRetry?: () => void;
  /** IDS is OFF: no live values on the dashboard */
  idsOff?: boolean;
}

interface MetricRowProps {
  icon: React.ReactNode;
  label: string;
  value: string | null | undefined;
}

function MetricRow({ icon, label, value }: MetricRowProps) {
  return (
    <div className={styles.metricRow}>
      <span className={styles.metricIcon} aria-hidden="true">{icon}</span>
      <span className={styles.metricLabel}>{label}</span>
      <span className={styles.metricValue}>
        {value ?? <span className={styles.na}>Not available</span>}
      </span>
    </div>
  );
}

export function HostStatusCard({
  data,
  isLoading,
  isError,
  onRetry,
  idsOff = false,
}: HostStatusCardProps) {
  if (idsOff) {
    return (
      <div className={styles.card}>
        <div className={styles.header}>
          <Monitor size={16} className={styles.headerIcon} aria-hidden="true" />
          <h3 className={styles.title}>Host Status</h3>
        </div>
        <div className={styles.metrics}>
          <MetricRow icon={<Network size={14} />} label="Network" value="—" />
          <MetricRow icon={<Clock size={14} />} label="Uptime" value="—" />
          <MetricRow icon={<Monitor size={14} />} label="OS" value="—" />
          <p className={styles.noData}>IDS is off — no live values.</p>
        </div>
      </div>
    );
  }
  return (
    <div className={styles.card}>
      <div className={styles.header}>
        <Monitor size={16} className={styles.headerIcon} aria-hidden="true" />
        <h3 className={styles.title}>Host Status</h3>
        {data?.hostname && (
          <span className={styles.hostname}>{data.hostname}</span>
        )}
      </div>

      {isLoading && <LoadingState message="Loading host status…" />}

      {isError && !isLoading && (
        <ErrorState
          title="Unable to load host status"
          message="Could not load this information. Please try again."
          onRetry={onRetry}
        />
      )}

      {!isLoading && !isError && (
        <div className={styles.metrics}>
          {/* Network */}
          <MetricRow
            icon={<Network size={14} />}
            label="Network"
            value={data?.networkBytesPerSec !== null && data?.networkBytesPerSec !== undefined
              ? `${formatBytes(data.networkBytesPerSec)}/s`
              : null}
          />

          {/* Uptime */}
          <MetricRow
            icon={<Clock size={14} />}
            label="Uptime"
            value={data?.uptime !== null && data?.uptime !== undefined
              ? formatDuration(data.uptime)
              : null}
          />

          {/* OS */}
          {data?.os && (
            <MetricRow
              icon={<Monitor size={14} />}
              label="OS"
              value={data.os}
            />
          )}

          {!data && (
            <p className={styles.noData}>
              Waiting for data…
            </p>
          )}
        </div>
      )}
    </div>
  );
}
