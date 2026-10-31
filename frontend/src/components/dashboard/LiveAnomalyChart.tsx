/**
 * SecureNet — LiveAnomalyChart
 *
 * Real-time anomaly score line chart powered by Recharts.
 * Data comes exclusively from the WebSocket feed via useLiveMonitoring().
 *
 * States:
 *  - Idle / connecting / reconnecting: spinner + status message
 *  - Connected but no data yet: "Waiting for data…"
 *  - Connected with data: renders live chart
 *  - Disconnected / error: "Live monitoring unavailable"
 *
 * No fake data points are ever generated.
 */

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import { useLiveMonitoring } from '../../hooks/useLiveMonitoring';
import { StatusBadge } from '../common/StatusBadge';
import { Spinner } from '../common/LoadingState';
import type { LiveChartPoint } from '../../types/security.types';
import styles from './LiveAnomalyChart.module.css';


interface TooltipEntry {
  value?: number;
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: TooltipEntry[];
  label?: string;
}

function CustomTooltip({ active, payload, label }: CustomTooltipProps) {
  if (!active || !payload?.length) return null;
  const score = payload[0]?.value;
  return (
    <div className={styles.tooltip}>
      <p className={styles.tooltipTime}>{label}</p>
      <p className={styles.tooltipScore}>
        Score: <span className={styles.tooltipValue}>{score?.toFixed(4)}</span>
      </p>
    </div>
  );
}

function scoreToColor(score: number, threshold: number): string {
  if (score >= threshold + (1 - threshold) * 0.5) return 'var(--color-severity-high)';
  if (score >= threshold) return 'var(--color-severity-medium)';
  return 'var(--color-severity-low)';
}

interface AlertDotProps {
  cx?: number;
  cy?: number;
  payload?: LiveChartPoint;
}

/** Only flows that became security events get a marker. */
function AlertDot({ cx, cy, payload }: AlertDotProps) {
  if (!payload?.isAlert || cx === undefined || cy === undefined) return null;
  return <circle cx={cx} cy={cy} r={4} fill="var(--color-severity-high)" stroke="var(--color-white)" strokeWidth={1} />;
}

interface LiveAnomalyChartProps {
  /** Current detection threshold θ (from Settings → Detection) */
  threshold?: number;
  /** IDS is OFF: no live scores */
  idsOff?: boolean;
}

export function LiveAnomalyChart({ threshold = 0.5, idsOff = false }: LiveAnomalyChartProps) {
  const { status, chartData, lastScore, isConnecting } = useLiveMonitoring();

  if (idsOff) {
    return (
      <div className={styles.card}>
        <div className={styles.header}>
          <div className={styles.headerLeft}>
            <h3 className={styles.title}>Live Anomaly Score</h3>
          </div>
        </div>
        <div className={styles.chartArea}>
          <div className={styles.overlayMessage}>
            <p className={styles.waitingText}>IDS is off</p>
            <p className={styles.unavailableSubtext}>Live scores appear here while the IDS is ON.</p>
          </div>
        </div>
      </div>
    );
  }

  const isUnavailable =
    status === 'disconnected' || status === 'error';
  const isWaiting =
    status === 'idle' || isConnecting;
  const isConnected = status === 'connected';

  return (
    <div className={styles.card}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <h3 className={styles.title}>Live Anomaly Score</h3>
          {lastScore !== null && isConnected && (
            <span
              className={styles.liveScore}
              style={{ color: scoreToColor(lastScore, threshold) }}
              aria-label={`Current anomaly score: ${lastScore.toFixed(4)}`}
            >
              {lastScore.toFixed(4)}
            </span>
          )}
        </div>
        <StatusBadge
          status={
            isConnected
              ? 'connected'
              : isConnecting
              ? 'connecting'
              : isUnavailable
              ? 'disconnected'
              : 'connecting'
          }
        />
      </div>

      {/* Chart area */}
      <div className={styles.chartArea} role="img" aria-label="Live anomaly score chart">
        {/* Unavailable */}
        {isUnavailable && (
          <div className={styles.overlayMessage}>
            <p className={styles.unavailableText}>Live monitoring unavailable</p>
            <p className={styles.unavailableSubtext}>
              The live feed is not connected. Reload the page to try again.
            </p>
          </div>
        )}

        {/* Waiting / connecting */}
        {isWaiting && !isUnavailable && (
          <div className={styles.overlayMessage}>
            <Spinner size="md" />
            <p className={styles.waitingText}>
              {status === 'idle' ? 'Initialising…' : 'Connecting to live feed…'}
            </p>
          </div>
        )}

        {/* Connected, no data yet */}
        {isConnected && chartData.length === 0 && (
          <div className={styles.overlayMessage}>
            <p className={styles.waitingText}>Waiting for scored traffic</p>
            <p className={styles.unavailableSubtext}>
              Scores appear here once the IDS is ON and a detection model is loaded.
            </p>
          </div>
        )}

        {/* Chart */}
        {isConnected && chartData.length > 0 && (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={chartData}
              margin={{ top: 8, right: 16, bottom: 4, left: 0 }}
            >
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="var(--color-border)"
                vertical={false}
              />
              <XAxis
                dataKey="time"
                tick={{ fontFamily: 'var(--font-mono)', fontSize: 11, fill: 'var(--color-text-muted)' }}
                tickLine={false}
                axisLine={false}
                interval="preserveStartEnd"
              />
              <YAxis
                domain={[0, 1]}
                tick={{ fontFamily: 'var(--font-mono)', fontSize: 11, fill: 'var(--color-text-muted)' }}
                tickLine={false}
                axisLine={false}
                tickFormatter={(v: number) => v.toFixed(1)}
                width={36}
              />
              <Tooltip content={<CustomTooltip />} />
              <ReferenceLine
                y={threshold}
                stroke="var(--color-severity-medium)"
                strokeDasharray="4 2"
                label={{
                  value: 'threshold',
                  position: 'right',
                  fontSize: 10,
                  fill: 'var(--color-text-muted)',
                  fontFamily: 'var(--font-mono)',
                }}
              />
              <Line
                type="monotone"
                dataKey="score"
                stroke="var(--color-peach-dark)"
                strokeWidth={2}
                dot={<AlertDot />}
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
