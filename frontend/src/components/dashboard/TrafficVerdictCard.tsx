/**
 * SecureNet — TrafficVerdictCard
 *
 * How much of the traffic checked since the IDS was turned on was normal and how much
 * was abnormal (the final verdict). Plain words only — no model names. Which attack it
 * could be is shown right under the big status in the IDS widget (AttackGuessTable).
 * Real counts from /api/ids/status only; nothing is shown until connections were checked.
 */

import type { VerdictSummary } from '../../services/idsService';
import { EmptyState } from '../common/EmptyState';
import { IdsOffNote } from './IdsOffNote';
import styles from './TrafficVerdictCard.module.css';

interface TrafficVerdictCardProps {
  verdicts: VerdictSummary | null | undefined;
  mlLoaded: boolean;
  /** IDS is OFF: no live values on the dashboard */
  idsOff?: boolean;
}

function share(n: number, total: number): string {
  if (total <= 0) return '—';
  const p = (n / total) * 100;
  return `${p >= 99.995 || p === 0 ? p.toFixed(0) : p.toFixed(2)}%`;
}

export function TrafficVerdictCard({ verdicts, mlLoaded, idsOff = false }: TrafficVerdictCardProps) {
  const title = 'Traffic Check';

  if (idsOff) {
    return (
      <div className={styles.card}>
        <h3 className={styles.title}>{title}</h3>
        <IdsOffNote what="results" />
      </div>
    );
  }
  if (!mlLoaded || !verdicts || verdicts.scored === 0) {
    return (
      <div className={styles.card}>
        <h3 className={styles.title}>{title}</h3>
        <EmptyState
          title={mlLoaded ? 'Waiting for traffic' : 'Detection is not set up yet'}
          description={mlLoaded
            ? 'The results appear as soon as the first network connections have been checked.'
            : 'Traffic is counted, but nothing can be checked until detection is set up.'}
        />
      </div>
    );
  }

  const { scored, finalNormal, finalAbnormal } = verdicts;

  return (
    <div className={styles.card}>
      <div className={styles.header}>
        <h3 className={styles.title}>{title}</h3>
        <span className={styles.meta}>{scored.toLocaleString()} connections checked since the IDS was turned on</span>
      </div>

      <table className={styles.table}>
        <thead>
          <tr>
            <th scope="col">Result</th>
            <th scope="col" className={styles.num}>Connections</th>
            <th scope="col" className={styles.num}>Share</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Normal traffic</td>
            <td className={styles.num}>{finalNormal.toLocaleString()}</td>
            <td className={styles.num}>{share(finalNormal, scored)}</td>
          </tr>
          <tr className={finalAbnormal > 0 ? styles.rowAlert : undefined}>
            <td>Abnormal traffic</td>
            <td className={styles.num}>{finalAbnormal.toLocaleString()}</td>
            <td className={styles.num}>{share(finalAbnormal, scored)}</td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}
