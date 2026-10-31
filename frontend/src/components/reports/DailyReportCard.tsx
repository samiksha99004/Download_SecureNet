/**
 * SecureNet — DailyReportCard
 *
 * One box per day that had attacks: counts by severity, most common attack,
 * number of attacking sources, first/last detection time, and downloads of
 * that day's report (.txt, .pdf).
 */

import { useState } from 'react';
import { Download, FileText } from 'lucide-react';
import { useToast } from '../common/Toast';
import { downloadDailyReport } from '../../services/reportsService';
import type { DailyReport, DailyReportFormat } from '../../types/reports.types';
import styles from './DailyReportCard.module.css';

const FORMATS: { id: DailyReportFormat; label: string }[] = [
  { id: 'txt', label: '.txt' },
  { id: 'pdf', label: '.pdf' },
];

function formatDay(date: string): string {
  const [y, m, d] = date.split('-').map(Number);
  return new Date(y, m - 1, d).toLocaleDateString(undefined, {
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric',
  });
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

export function DailyReportCard({ report }: { report: DailyReport }) {
  const { showToast } = useToast();
  const [busy, setBusy] = useState<DailyReportFormat | null>(null);

  async function download(format: DailyReportFormat) {
    setBusy(format);
    try {
      await downloadDailyReport(report.date, format);
    } catch (err) {
      showToast({
        message: err instanceof Error && err.message ? err.message : 'Could not download the report.',
        variant: 'error',
      });
    } finally {
      setBusy(null);
    }
  }

  return (
    <article className={styles.card}>
      <header className={styles.header}>
        <FileText size={18} className={styles.icon} aria-hidden="true" />
        <div>
          <h3 className={styles.day}>{formatDay(report.date)}</h3>
          <p className={styles.range}>
            {report.total} abnormal traffic alert{report.total === 1 ? '' : 's'} · {formatTime(report.firstSeen)}
            {report.total > 1 && <> – {formatTime(report.lastSeen)}</>}
          </p>
        </div>
      </header>

      <div className={styles.severities}>
        <span className={`${styles.chip} ${styles.high}`}>High {report.high}</span>
        <span className={`${styles.chip} ${styles.medium}`}>Medium {report.medium}</span>
        <span className={`${styles.chip} ${styles.low}`}>Low {report.low}</span>
      </div>

      <dl className={styles.facts}>
        <div>
          <dt>Most likely attack (model’s guess)</dt>
          <dd>{report.topAttack ?? 'Unknown'}</dd>
        </div>
        <div>
          <dt>Sources</dt>
          <dd>{report.sources}</dd>
        </div>
      </dl>

      <div className={styles.downloads}>
        <span className={styles.downloadLabel}>
          <Download size={14} aria-hidden="true" /> Download report
        </span>
        <div className={styles.buttons}>
          {FORMATS.map(({ id, label }) => (
            <button
              key={id}
              type="button"
              className={`${styles.button} ${id === 'txt' ? styles.primary : ''}`}
              onClick={() => void download(id)}
              disabled={busy !== null}
              aria-label={`Download ${formatDay(report.date)} report as ${label}`}
            >
              {busy === id ? '…' : label}
            </button>
          ))}
        </div>
      </div>
    </article>
  );
}
