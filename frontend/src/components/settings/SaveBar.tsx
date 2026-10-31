/**
 * SecureNet — SaveBar
 *
 * Sticky save/cancel bar shown at the bottom of settings tabs
 * when there are unsaved changes.
 */

import styles from './SaveBar.module.css';

interface SaveBarProps {
  isDirty: boolean;
  isSaving: boolean;
  onSave: () => void;
  onDiscard: () => void;
}

export function SaveBar({ isDirty, isSaving, onSave, onDiscard }: SaveBarProps) {
  if (!isDirty) return null;

  return (
    <div className={styles.bar} role="region" aria-label="Unsaved changes">
      <p className={styles.message}>You have unsaved changes.</p>
      <div className={styles.actions}>
        <button
          type="button"
          className={styles.discardBtn}
          onClick={onDiscard}
          disabled={isSaving}
        >
          Discard
        </button>
        <button
          type="button"
          className={styles.saveBtn}
          onClick={onSave}
          disabled={isSaving}
          aria-busy={isSaving}
        >
          {isSaving ? 'Saving…' : 'Save changes'}
        </button>
      </div>
    </div>
  );
}
