/**
 * AttackTrendCard — abnormal (attack) % of traffic over time.
 *
 * X = time (minutes ago → now), Y = attack % (0–100). When traffic is normal the
 * line sits flat on the bottom; it rises as attacks increase. The dashed line marks
 * the 30% level above which the network is counted ABNORMAL. Points are 5s apart,
 * up to the last ~6 minutes. Theme-aware (CSS variables) for light + dark mode.
 */
import type { TrendPoint } from '../../services/idsService';

interface Props {
  trend?: TrendPoint[];
  threshold?: number;
  idsOff?: boolean;
}

export function AttackTrendCard({ trend = [], threshold = 30, idsOff = false }: Props) {
  const pts = trend.slice(-72);
  const n = pts.length;

  const W = 640, H = 200;
  const padL = 38, padR = 14, padT = 14, padB = 26;   // room for axis labels
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const xi = (i: number) => (n <= 1 ? padL : padL + (i / (n - 1)) * plotW);
  const yv = (v: number) => padT + (1 - Math.max(0, Math.min(100, v)) / 100) * plotH;

  const line = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${xi(i).toFixed(1)},${yv(p.pct).toFixed(1)}`).join(' ');
  const area = n > 0
    ? `${line} L${xi(n - 1).toFixed(1)},${(padT + plotH).toFixed(1)} L${xi(0).toFixed(1)},${(padT + plotH).toFixed(1)} Z`
    : '';
  const cur = n ? pts[n - 1].pct : 0;
  const peak = n ? Math.max(...pts.map((p) => p.pct)) : 0;
  const danger = cur > threshold;
  const stroke = danger ? '#ef4444' : '#22c55e';

  // X time ticks: now, 2m, 4m, 6m ago (each minute = 12 points at 5s spacing)
  const xTicks = [0, 2, 4, 6]
    .map((m) => ({ m, i: n - 1 - m * 12 }))
    .filter((t) => t.i >= 0);

  const card: React.CSSProperties = {
    background: 'var(--color-white)', border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-lg)', padding: 'var(--space-5)',
  };

  return (
    <div style={card}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 'var(--space-3)' }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: 'var(--color-text)' }}>
          Attack Trend <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--color-text-muted)' }}>· abnormal % over time</span>
        </h3>
        <span style={{ fontSize: 13, color: 'var(--color-text-muted)' }}>
          now <b style={{ color: stroke }}>{cur.toFixed(1)}%</b> · peak {peak.toFixed(1)}%
        </span>
      </div>
      {idsOff || n === 0 ? (
        <div style={{ color: 'var(--color-text-muted)', fontSize: 13, padding: '46px 0', textAlign: 'center' }}>
          {idsOff ? 'IDS is off' : 'Waiting for traffic…'}
        </div>
      ) : (
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ display: 'block' }}>
          <defs>
            <linearGradient id="attackTrendGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={stroke} stopOpacity="0.28" />
              <stop offset="100%" stopColor={stroke} stopOpacity="0" />
            </linearGradient>
          </defs>

          {/* Y grid + labels (0 / 50 / 100 %) */}
          {[0, 50, 100].map((v) => (
            <g key={v}>
              <line x1={padL} x2={W - padR} y1={yv(v)} y2={yv(v)} stroke="var(--color-border)" strokeWidth="1" strokeOpacity="0.5" />
              <text x={padL - 6} y={yv(v) + 3} textAnchor="end" fontSize="10" fill="var(--color-text-muted)">{v}%</text>
            </g>
          ))}

          {/* data */}
          <path d={area} fill="url(#attackTrendGrad)" />
          <path d={line} fill="none" stroke={stroke} strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round" />

          {/* X time labels */}
          {xTicks.map((t) => (
            <text key={t.m} x={xi(t.i)} y={H - 8} textAnchor="middle" fontSize="10" fill="var(--color-text-muted)">
              {t.m === 0 ? 'now' : `${t.m}m`}
            </text>
          ))}
        </svg>
      )}
    </div>
  );
}
