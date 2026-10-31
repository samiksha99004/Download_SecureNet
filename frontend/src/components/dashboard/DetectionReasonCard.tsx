/**
 * SecureNet — DetectionReasonCard
 *
 * Displays contributing features from the ML model's latest detection.
 * Data comes from the backend — empty state shown until connected.
 *
 * The feature table is designed to receive SHAP-style values:
 *   Feature | Value | Contribution
 */

import type { ContributingFeature } from '../../types/security.types';
import { EmptyState } from '../common/EmptyState';
import { IdsOffNote } from './IdsOffNote';
import { Lightbulb } from 'lucide-react';
import styles from './DetectionReasonCard.module.css';
import { plainReason } from '../../utils/verdict';

interface DetectionReasonCardProps {
  reason: string | null;
  features: ContributingFeature[];
  attackType: string | null;
  confidence: number | null;
  /** IDS is OFF: no live values on the dashboard */
  idsOff?: boolean;
}

export function DetectionReasonCard({
  reason,
  features,
  attackType,
  confidence,
  idsOff = false,
}: DetectionReasonCardProps) {
  const hasData = features.length > 0 || reason !== null;

  return (
    <div className={styles.card}>
      <div className={styles.header}>
        <Lightbulb size={16} className={styles.headerIcon} aria-hidden="true" />
        <h3 className={styles.title}>Why was this detected?</h3>
      </div>

      {idsOff && <IdsOffNote what="detection details" />}

      {!idsOff && attackType && (
        <div className={styles.meta}>
          <span className={styles.attackLabel}>
            Possible attack: {attackType}
            {confidence !== null && (
              <span className={styles.confidence}>
                {(confidence * 100).toFixed(0)}% confidence
              </span>
            )}
          </span>
        </div>
      )}

      {!idsOff && reason && (
        <p className={styles.reason}>{plainReason(reason)}</p>
      )}

      {idsOff ? null : !hasData ? (
        <EmptyState
          title="No detection data"
          description="Select an event to see why it was flagged."
        />
      ) : features.length === 0 ? null : (
        <div className={styles.tableWrapper}>
          <p className={styles.tableHeading}>Top contributing features</p>
          <table className={styles.table}>
            <thead>
              <tr>
                <th scope="col" className={styles.th}>Feature</th>
                <th scope="col" className={styles.th}>Value</th>
                <th scope="col" className={styles.th}>Contribution</th>
              </tr>
            </thead>
            <tbody>
              {features.map((f, i) => (
                <tr key={i} className={styles.tr}>
                  <td className={styles.tdName}>{f.name}</td>
                  <td className={styles.tdValue}>
                    <span className={styles.mono}>
                      {typeof f.value === 'number'
                        ? f.value.toFixed(4)
                        : String(f.value)}
                    </span>
                  </td>
                  <td className={styles.tdContrib}>
                    <ContributionBar value={f.contribution} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ContributionBar({ value }: { value: number }) {
  const abs = Math.abs(value);
  const max = 1; // Normalise to ±1
  const width = Math.min(100, (abs / max) * 100);
  const color = value > 0
    ? 'var(--color-severity-high)'
    : 'var(--color-severity-info)';

  return (
    <div className={styles.contribRow}>
      <span
        className={styles.contribBar}
        style={{ width: `${width}%`, backgroundColor: color }}
        aria-hidden="true"
      />
      <span className={styles.contribNum} style={{ color }}>
        {value > 0 ? '+' : ''}{value.toFixed(3)}
      </span>
    </div>
  );
}
