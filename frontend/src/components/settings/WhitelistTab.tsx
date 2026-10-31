/**
 * SecureNet — WhitelistTab
 *
 * Manages the security event whitelist.
 * Supports: view table, add entry, delete with confirmation.
 * Full loading / error / empty states.
 */

import { useCallback, useState } from 'react';
import { Plus, Trash2, ShieldOff } from 'lucide-react';
import { useAsyncData } from '../../hooks/useAsyncData';
import { useToast } from '../common/Toast';
import {
  getWhitelist,
  addWhitelistEntry,
  removeWhitelistEntry,
} from '../../services/settingsService';
import type { WhitelistEntry, CreateWhitelistEntryRequest } from '../../types/settings.types';
import { ConfirmDialog } from '../common/ConfirmDialog';
import { AddWhitelistEntryModal } from './AddWhitelistEntryModal';
import { LoadingState } from '../common/LoadingState';
import { ErrorState } from '../common/ErrorState';
import { EmptyState } from '../common/EmptyState';
import { formatTimestamp } from '../../utils/format';
import styles from './WhitelistTab.module.css';
import { errorMessage } from '../../utils/errors';

const TYPE_LABELS: Record<string, string> = {
  ip: 'IP Address',
  cidr: 'CIDR Range',
  port: 'Port',
  protocol: 'Protocol',
};

export function WhitelistTab() {
  const { showToast } = useToast();
  const { data, isLoading, isError, refetch } = useAsyncData(
    useCallback(() => getWhitelist(), [])
  );

  const [addOpen, setAddOpen] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  const [deleteTarget, setDeleteTarget] = useState<WhitelistEntry | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  async function handleAdd(req: CreateWhitelistEntryRequest) {
    setIsSaving(true);
    try {
      await addWhitelistEntry(req);
      showToast({ message: 'Whitelist entry added.', variant: 'success' });
      setAddOpen(false);
      void refetch();
    } catch (err) {
      showToast({ message: errorMessage(err, 'Could not add entry.'), variant: 'error' });
    } finally {
      setIsSaving(false);
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    setIsDeleting(true);
    try {
      await removeWhitelistEntry(deleteTarget.id);
      showToast({ message: 'Whitelist entry removed.', variant: 'success' });
      setDeleteTarget(null);
      void refetch();
    } catch (err) {
      showToast({ message: errorMessage(err, 'Could not remove entry.'), variant: 'error' });
    } finally {
      setIsDeleting(false);
    }
  }

  return (
    <div className={styles.tabContent}>
      {/* Header row */}
      <div className={styles.topRow}>
        <div>
          <h3 className={styles.heading}>Whitelist</h3>
          <p className={styles.subheading}>
            Whitelisted entries are excluded from anomaly detection.
          </p>
        </div>
        <button
          type="button"
          className={styles.addBtn}
          onClick={() => setAddOpen(true)}
        >
          <Plus size={14} aria-hidden="true" />
          Add Entry
        </button>
      </div>

      {/* Table area */}
      {isLoading && <LoadingState message="Loading whitelist…" />}

      {isError && (
        <ErrorState
          title="Whitelist unavailable"
          message="The whitelist could not be loaded. Please try again."
          onRetry={refetch}
        />
      )}

      {!isLoading && !isError && data && data.length === 0 && (
        <EmptyState
          icon={<ShieldOff size={32} />}
          title="No whitelist entries"
          description="Add trusted IPs, CIDR ranges, ports, or protocols to exclude them from detection."
          action={
            <button className={styles.addBtnEmpty} onClick={() => setAddOpen(true)}>
              <Plus size={14} aria-hidden="true" />
              Add first entry
            </button>
          }
        />
      )}

      {!isLoading && !isError && data && data.length > 0 && (
        <div className={styles.tableWrapper}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th className={styles.th}>Type</th>
                <th className={styles.th}>Value</th>
                <th className={styles.th}>Description</th>
                <th className={styles.th}>Added</th>
                <th className={styles.th}>Status</th>
                <th className={styles.th} aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {data.map((entry) => (
                <tr key={entry.id} className={styles.tr}>
                  <td className={styles.td}>
                    <span className={styles.typeBadge}>
                      {TYPE_LABELS[entry.type] ?? entry.type}
                    </span>
                  </td>
                  <td className={styles.tdMono}>{entry.value}</td>
                  <td className={styles.td}>
                    {entry.description ?? <span className={styles.muted}>—</span>}
                  </td>
                  <td className={styles.tdMono}>{formatTimestamp(entry.createdAt)}</td>
                  <td className={styles.td}>
                    <span className={entry.active ? styles.activeBadge : styles.inactiveBadge}>
                      {entry.active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className={styles.tdAction}>
                    <button
                      className={styles.deleteBtn}
                      onClick={() => setDeleteTarget(entry)}
                      aria-label={`Delete whitelist entry ${entry.value}`}
                    >
                      <Trash2 size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Add modal */}
      <AddWhitelistEntryModal
        isOpen={addOpen}
        isSaving={isSaving}
        onConfirm={handleAdd}
        onCancel={() => setAddOpen(false)}
      />

      {/* Delete confirm */}
      <ConfirmDialog
        isOpen={deleteTarget !== null}
        title="Remove Whitelist Entry"
        description={
          deleteTarget
            ? `Remove "${deleteTarget.value}" (${TYPE_LABELS[deleteTarget.type] ?? deleteTarget.type}) from the whitelist? Traffic from this source will be included in detection again.`
            : ''
        }
        confirmLabel="Remove"
        variant="danger"
        isLoading={isDeleting}
        onConfirm={handleDelete}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
}
