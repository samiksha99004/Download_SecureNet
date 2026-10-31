/**
 * SecureNet — ExportButton
 *
 * Exports the events matching the current History filters as CSV or PDF
 * (GET /api/events/export, downloaded with the user's access token).
 */

import { useState } from 'react';
import { Download, FileText, FileSpreadsheet, X } from 'lucide-react';
import { cn } from '../../utils/cn';
import { errorMessage } from '../../utils/errors';
import { exportEvents } from '../../services/eventsService';
import type { EventFilterParams } from '../../types/api.types';
import styles from './ExportButton.module.css';

interface ExportButtonProps {
  /** Current History filters */
  filters: Partial<EventFilterParams>;
  /** Total events matching current filters */
  totalEvents: number | null;
  disabled?: boolean;
}

type ExportFormat = 'csv' | 'pdf';

export function ExportButton({ filters, totalEvents, disabled = false }: ExportButtonProps) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  async function handleExport(format: ExportFormat) {
    setOpen(false);
    setExportError(null);
    setBusy(true);
    try {
      await exportEvents(filters, format);
    } catch (err) {
      setExportError(errorMessage(err, 'Export failed.'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={styles.wrapper}>
      {/* Error notice */}
      {exportError && (
        <div className={styles.unavailableNotice} role="alert">
          <span>{exportError}</span>
          <button
            className={styles.dismissBtn}
            onClick={() => setExportError(null)}
            aria-label="Dismiss"
          >
            <X size={13} />
          </button>
        </div>
      )}

      {/* Trigger button */}
      <button
        type="button"
        className={cn(styles.trigger, open && styles.triggerOpen)}
        onClick={() => setOpen((p) => !p)}
        disabled={disabled || busy || totalEvents === 0}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Export events"
      >
        <Download size={14} aria-hidden="true" />
        {busy ? 'Exporting…' : 'Export'}
      </button>

      {/* Dropdown menu */}
      {open && (
        <>
          <div className={styles.backdrop} onClick={() => setOpen(false)} aria-hidden="true" />
          <div className={styles.menu} role="menu">
            <p className={styles.menuTitle}>Export format</p>

            <button
              role="menuitem"
              className={styles.menuItem}
              onClick={() => void handleExport('csv')}
            >
              <FileSpreadsheet size={14} aria-hidden="true" />
              <span>CSV Spreadsheet</span>
            </button>

            <button
              role="menuitem"
              className={styles.menuItem}
              onClick={() => void handleExport('pdf')}
            >
              <FileText size={14} aria-hidden="true" />
              <span>PDF Report</span>
            </button>

            {totalEvents !== null && (
              <p className={styles.menuNote}>
                {totalEvents.toLocaleString()} event{totalEvents !== 1 ? 's' : ''} will be exported
              </p>
            )}
          </div>
        </>
      )}
    </div>
  );
}
