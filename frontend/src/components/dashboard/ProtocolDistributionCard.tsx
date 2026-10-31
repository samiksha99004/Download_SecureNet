/**
 * SecureNet — ProtocolDistributionCard
 *
 * Donut chart showing TCP/UDP/ICMP/Other distribution.
 * Uses Recharts PieChart. Shows empty state until backend provides data.
 */

import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import type { ProtocolDistribution } from '../../types/security.types';
import { LoadingState } from '../common/LoadingState';
import { EmptyState } from '../common/EmptyState';
import { IdsOffNote } from './IdsOffNote';
import { ErrorState } from '../common/ErrorState';
import styles from './ProtocolDistributionCard.module.css';

interface ProtocolDistributionCardProps {
  data: ProtocolDistribution | null;
  isLoading: boolean;
  isError: boolean;
  onRetry?: () => void;
  /** IDS is OFF: no live values on the dashboard */
  idsOff?: boolean;
}

const PROTOCOL_COLORS = {
  TCP:   '#38BDF8',
  UDP:   '#A78BFA',
  ICMP:  '#34D399',
  Other: '#64748B',
} as const;

export function ProtocolDistributionCard({
  data,
  isLoading,
  isError,
  onRetry,
  idsOff = false,
}: ProtocolDistributionCardProps) {
  if (idsOff) {
    return (
      <div className={styles.card}>
        <h3 className={styles.title}>Network Traffic</h3>
        <IdsOffNote what="traffic data" />
      </div>
    );
  }
  const chartData = data
    ? [
        { name: 'TCP',   value: data.tcp   },
        { name: 'UDP',   value: data.udp   },
        { name: 'ICMP',  value: data.icmp  },
        { name: 'Other', value: data.other },
      ].filter((d) => d.value > 0)
    : [];

  return (
    <div className={styles.card}>
      <h3 className={styles.title}>Network Traffic</h3>

      {isLoading && <LoadingState message="Loading traffic data…" />}

      {isError && !isLoading && (
        <ErrorState
          title="Unable to load traffic"
          message="Could not load this information. Please try again."
          onRetry={onRetry}
        />
      )}

      {!isLoading && !isError && (!data || chartData.length === 0) && (
        <EmptyState
          title="No traffic data"
          description="No security events have been recorded yet."
        />
      )}

      {!isLoading && !isError && chartData.length > 0 && (
        <>
          <div className={styles.chartArea} role="img" aria-label="Protocol distribution chart">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius="55%"
                  outerRadius="80%"
                  paddingAngle={2}
                  dataKey="value"
                >
                  {chartData.map((entry) => (
                    <Cell
                      key={entry.name}
                      fill={PROTOCOL_COLORS[entry.name as keyof typeof PROTOCOL_COLORS]}
                    />
                  ))}
                </Pie>
                <Tooltip
                  formatter={(value, name) => [
                    typeof value === 'number' ? value.toLocaleString() : String(value),
                    name,
                  ]}
                  contentStyle={{
                    background: 'var(--color-white)',
                    color: 'var(--color-text)',
                    fontFamily: 'var(--font-body)',
                    fontSize: '0.8125rem',
                    border: '1px solid var(--color-border)',
                    borderRadius: '8px',
                  }}
                  itemStyle={{ color: 'var(--color-text)' }}
                />
                <Legend
                  iconType="circle"
                  iconSize={8}
                  formatter={(value) => (
                    <span style={{ fontFamily: 'var(--font-body)', fontSize: '0.8125rem', color: 'var(--color-text)' }}>
                      {value}
                    </span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {data && (
            <p className={styles.totalFlows}>
              Total flows:{' '}
              <span className={styles.totalValue}>
                {data.totalFlows.toLocaleString()}
              </span>
            </p>
          )}
        </>
      )}
    </div>
  );
}
