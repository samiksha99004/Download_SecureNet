/**
 * SessionStatsCard — a compact summary of the current monitoring session.
 *
 * Shows throughput + flow accounting that the other cards don't: how much
 * traffic has been scored since the IDS turned on, the normal/attack split,
 * and the processing rate. All from idsStatus (no extra API call).
 */
import type { IDSStatus } from '../../services/idsService';
import { formatDuration, formatNumber } from '../../utils/format';

interface Props {
  idsStatus: IDSStatus | null;
  idsOff?: boolean;
}

export function SessionStatsCard({ idsStatus, idsOff = false }: Props) {
  const v = idsStatus?.verdicts;
  const up = idsStatus?.uptimeSeconds ?? 0;
  const flows = idsStatus?.flowsAnalyzed ?? 0;
  const rate = up > 0 ? flows / up : 0;                        // flows per second
  const scored = v?.scored ?? 0;
  const normal = v?.finalNormal ?? 0;
  const attacks = v?.finalAbnormal ?? 0;
  const attackPct = scored > 0 ? (attacks / scored) * 100 : 0;

  const card: React.CSSProperties = {
    background: 'var(--color-white)', border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-lg)', padding: 'var(--space-5)',
  };
  const grid: React.CSSProperties = {
    display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 'var(--space-4)',
  };
  const label: React.CSSProperties = {
    fontSize: 11, textTransform: 'uppercase', letterSpacing: '.04em', color: 'var(--color-text-muted)',
  };
  const value: React.CSSProperties = { fontSize: 22, fontWeight: 700, color: 'var(--color-text)', lineHeight: 1.2 };

  const Stat = ({ l, val, color }: { l: string; val: string; color?: string }) => (
    <div>
      <div style={label}>{l}</div>
      <div style={{ ...value, color: color ?? value.color }}>{val}</div>
    </div>
  );

  return (
    <div style={card}>
      <h3 style={{ margin: '0 0 var(--space-3)', fontSize: 16, fontWeight: 700, color: 'var(--color-text)' }}>
        Monitoring Session
      </h3>
      {idsOff ? (
        <div style={{ color: 'var(--color-text-muted)', fontSize: 13, padding: '20px 0', textAlign: 'center' }}>
          IDS is off — press ON to start a session.
        </div>
      ) : (
        <div style={grid}>
          <Stat l="Flows scored" val={formatNumber(scored)} />
          <Stat l="Normal" val={formatNumber(normal)} color="#22c55e" />
          <Stat l="Attacks" val={formatNumber(attacks)} color={attacks > 0 ? '#ef4444' : undefined} />
          <Stat l="Attack share" val={`${attackPct.toFixed(1)}%`} color={attackPct > 30 ? '#ef4444' : undefined} />
          <Stat l="Throughput" val={`${rate.toFixed(1)}/s`} />
          <Stat l="Uptime" val={up ? formatDuration(up) : '—'} />
        </div>
      )}
    </div>
  );
}
