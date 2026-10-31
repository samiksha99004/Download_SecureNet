/**
 * SecureNet — AttackGuessTable
 *
 * Shown right under the big ABNORMAL TRAFFIC DETECTED status: what kind of attack it
 * could be, with the chance of each. Plain words only — no model names, and no tiny
 * rows (attacks under 5 % are left out).
 */

import type { AttackChance } from '../../utils/verdict';
import styles from './AttackGuessTable.module.css';

interface AttackGuessTableProps {
  rows: AttackChance[];
  basis: 'traffic' | 'latest' | null;
  total: number;
}

export function AttackGuessTable({ rows, basis, total }: AttackGuessTableProps) {
  if (rows.length === 0) return null;
  return (
    <div className={styles.box}>
      <h3 className={styles.title}>What kind of attack could it be?</h3>
      <table className={styles.table}>
        <thead>
          <tr>
            <th scope="col">Attack type</th>
            <th scope="col" className={styles.chanceHead}>Chance</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={row.label} className={i === 0 ? styles.top : undefined}>
              <td className={styles.name}>{row.label}</td>
              <td className={styles.chance}>
                <span className={styles.bar} aria-hidden="true">
                  <span className={styles.fill} style={{ width: `${Math.max(3, Math.round(row.chance * 100))}%` }} />
                </span>
                <span className={styles.percent}>{Math.round(row.chance * 100)}%</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className={styles.note}>
        {basis === 'traffic'
          ? `Based on ${total.toLocaleString()} abnormal connection${total === 1 ? '' : 's'} since the IDS was turned on. `
          : 'Based on the latest alert. '}
        This is SecureNet’s best guess, not a certainty.
      </p>
    </div>
  );
}
