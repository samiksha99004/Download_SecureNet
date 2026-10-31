/**
 * SecureNet — RecentEventsTable
 *
 * Groups security events into HOURLY incident groups instead of one row per flow,
 * so the dashboard isn't flooded with a new row every second. Each row = one hour
 * that had attacks, summarising: when (the hour + the active span inside it), how
 * many flows, which attack types, which sources, and the worst severity.
 *
 * Columns: Time (hour · active span) | Attacks | Attack Types | Sources | Severity
 */

import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import type { SecurityEvent, SeverityLevel } from '../../types/security.types';
import { SeverityBadge } from '../common/SeverityBadge';
import { EmptyState } from '../common/EmptyState';
import { IdsOffNote } from './IdsOffNote';
import { LoadingState } from '../common/LoadingState';
import styles from './RecentEventsTable.module.css';

interface RecentEventsTableProps {
  events: SecurityEvent[];
  isLoading: boolean;
  idsOff?: boolean;
}

interface HourGroup {
  key: string;
  latest: number;
  hourLabel: string;
  spanLabel: string;
  count: number;
  types: { label: string; n: number }[];
  sources: string[];
  severity: SeverityLevel;
}

const SEV_RANK: Record<string, number> = { high: 3, medium: 2, low: 1 };
const p2 = (n: number) => String(n).padStart(2, '0');
const hm = (d: Date) => `${p2(d.getHours())}:${p2(d.getMinutes())}`;
const hms = (d: Date) => `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
const dmy = (d: Date) => d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' });

function groupByHour(events: SecurityEvent[]): HourGroup[] {
  const map = new Map<string, SecurityEvent[]>();
  for (const e of events) {
    const d = new Date(e.timestamp);
    const key = `${d.getFullYear()}-${p2(d.getMonth())}-${p2(d.getDate())}-${p2(d.getHours())}`;
    (map.get(key) ?? map.set(key, []).get(key)!).push(e);
  }
  const groups: HourGroup[] = [];
  for (const [key, evs] of map) {
    const times = evs.map((e) => new Date(e.timestamp).getTime());
    const first = new Date(Math.min(...times));
    const last = new Date(Math.max(...times));
    const hourStart = new Date(first); hourStart.setMinutes(0, 0, 0);
    const hourEnd = new Date(hourStart.getTime() + 3600_000);

    const tmap = new Map<string, number>();
    for (const e of evs) {
      const l = e.attackType || 'Unknown';
      tmap.set(l, (tmap.get(l) ?? 0) + 1);
    }
    const types = [...tmap.entries()].sort((a, b) => b[1] - a[1]).map(([label, n]) => ({ label, n }));
    const sources = [...new Set(evs.map((e) => e.sourceIp))];
    const severity = evs.reduce<SeverityLevel>(
      (s, e) => ((SEV_RANK[e.severity] ?? 0) > (SEV_RANK[s] ?? 0) ? (e.severity as SeverityLevel) : s),
      'low',
    );
    groups.push({
      key,
      latest: Math.max(...times),
      hourLabel: `${dmy(hourStart)} · ${hm(hourStart)}–${hm(hourEnd)}`,
      spanLabel: `active ${hms(first)} – ${hms(last)}`,
      count: evs.length,
      types,
      sources,
      severity,
    });
  }
  return groups.sort((a, b) => b.latest - a.latest);
}

function summarise<T>(items: T[], render: (t: T) => string, max = 2): string {
  if (items.length === 0) return '—';
  const shown = items.slice(0, max).map(render).join(', ');
  return items.length > max ? `${shown} +${items.length - max}` : shown;
}

export function RecentEventsTable({ events, isLoading, idsOff = false }: RecentEventsTableProps) {
  const groups = groupByHour(events);

  return (
    <div className={styles.card}>
      <div className={styles.header}>
        <h3 className={styles.title}>Recent Security Events <span style={{ fontSize: 12, fontWeight: 400, color: 'var(--color-text-muted)' }}>· grouped by hour</span></h3>
        <Link to="/history" className={styles.viewAll} aria-label="View all security events">
          View All <ArrowRight size={14} aria-hidden="true" />
        </Link>
      </div>

      {idsOff && <IdsOffNote what="events" />}
      {!idsOff && isLoading && <LoadingState message="Loading recent events…" />}
      {!idsOff && !isLoading && groups.length === 0 && (
        <EmptyState title="No security events available." description="No attacks have been recorded yet." />
      )}

      {!idsOff && !isLoading && groups.length > 0 && (
        <div className={styles.tableWrapper} role="region" aria-label="Recent security events, grouped by hour">
          <table className={styles.table}>
            <thead>
              <tr>
                <th scope="col" className={styles.th}>Time (hour)</th>
                <th scope="col" className={styles.th}>Attacks</th>
                <th scope="col" className={styles.th}>Attack Types</th>
                <th scope="col" className={styles.th}>Sources</th>
                <th scope="col" className={styles.th}>Severity</th>
              </tr>
            </thead>
            <tbody>
              {groups.map((g) => (
                <tr key={g.key} className={styles.tr}>
                  <td className={styles.td}>
                    <span className={styles.mono}>{g.hourLabel}</span>
                    <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginTop: 2 }}>{g.spanLabel}</div>
                  </td>
                  <td className={styles.td}><b>{g.count}</b></td>
                  <td className={styles.td}>{summarise(g.types, (t) => `${t.label} ×${t.n}`)}</td>
                  <td className={styles.td}><span className={styles.mono}>{summarise(g.sources, (s) => s)}</span></td>
                  <td className={styles.td}><SeverityBadge severity={g.severity} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
