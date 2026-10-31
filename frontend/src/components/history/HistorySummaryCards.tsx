/**
 * SecureNet — HistorySummaryCards
 *
 * Event counts at the top of the History page (all events, not filtered).
 */

import { ShieldAlert, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import styles from './HistorySummaryCards.module.css';

export interface HistoryCounts {
  total: number;
  high: number;
  medium: number;
  resolved: number;
}

interface HistorySummaryCardsProps {
  counts: HistoryCounts | null;
  isLoading: boolean;
}

interface SummaryCardProps {
  label: string;
  value: string | null;
  icon: React.ReactNode;
  variant: 'default' | 'high' | 'medium' | 'low';
}

function SummaryCard({ label, value, icon, variant }: SummaryCardProps) {
  return (
    <div className={`${styles.card} ${styles[variant]}`} role="figure" aria-label={label}>
      <div className={styles.iconWrap} aria-hidden="true">{icon}</div>
      <div className={styles.text}>
        <span className={styles.value}>
          {value ?? <span className={styles.na}>—</span>}
        </span>
        <span className={styles.label}>{label}</span>
      </div>
    </div>
  );
}

export function HistorySummaryCards({ counts, isLoading }: HistorySummaryCardsProps) {
  const show = (n: number | undefined) => (isLoading || n === undefined ? null : n.toLocaleString());
  const display = show(counts?.total);

  return (
    <div className={styles.grid} aria-label="Event summary">
      <SummaryCard
        label="Total Events"
        value={display}
        icon={<Clock size={18} />}
        variant="default"
      />
      <SummaryCard
        label="High Severity"
        value={show(counts?.high)}
        icon={<ShieldAlert size={18} />}
        variant="high"
      />
      <SummaryCard
        label="Medium Severity"
        value={show(counts?.medium)}
        icon={<AlertTriangle size={18} />}
        variant="medium"
      />
      <SummaryCard
        label="Resolved"
        value={show(counts?.resolved)}
        icon={<CheckCircle size={18} />}
        variant="low"
      />
    </div>
  );
}
