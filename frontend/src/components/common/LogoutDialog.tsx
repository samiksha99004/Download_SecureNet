/**
 * SecureNet — LogoutDialog
 *
 * Signing out needs the account PASSWORD. This is deliberate — logging out turns
 * detection AND Advanced Protection OFF, so an attacker who reached an open session
 * must not be able to sign out (and disable monitoring) without the owner's password.
 *
 * A correct password ends the session; a wrong one keeps the user signed in.
 */

import { useEffect, useRef, useState } from 'react';
import { X, LogOut } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import styles from './LogoutDialog.module.css';

interface LogoutDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onLoggedOut: () => void;
}

export function LogoutDialog({ isOpen, onClose, onLoggedOut }: LogoutDialogProps) {
  const { logout } = useAuth();
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  // On open: reset the form.
  useEffect(() => {
    if (!isOpen) return;
    setPassword('');
    setError(null);
    setSubmitting(false);
    setTimeout(() => passwordRef.current?.focus(), 50);
  }, [isOpen]);

  // Close on Escape.
  useEffect(() => {
    if (!isOpen) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape' && !submitting) onClose();
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [isOpen, submitting, onClose]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!password) {
      setError('Enter your password to sign out.');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await logout(password);
      onLoggedOut();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-out failed. Check your password.');
      setSubmitting(false);
    }
  }

  if (!isOpen) return null;

  return (
    <div
      className={styles.overlay}
      onClick={(e) => { if (e.target === e.currentTarget && !submitting) onClose(); }}
      role="presentation"
    >
      <form
        className={styles.dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby="logout-title"
        onSubmit={handleSubmit}
      >
        <div className={styles.header}>
          <h2 id="logout-title" className={styles.title}>Confirm sign out</h2>
          <button
            type="button"
            className={styles.closeButton}
            onClick={onClose}
            disabled={submitting}
            aria-label="Close dialog"
          >
            <X size={16} />
          </button>
        </div>

        <div className={styles.body}>
          <p className={styles.warning}>
            Signing out turns <strong>detection and Advanced Protection off</strong>. For that reason
            it needs your password — so no one on an open session can sign out without it.
          </p>

          <div className={styles.fieldGroup}>
            <label htmlFor="logout-password" className={styles.label}>Password</label>
            <input
              ref={passwordRef}
              id="logout-password"
              type="password"
              className={styles.input}
              value={password}
              onChange={(e) => { setPassword(e.target.value); setError(null); }}
              autoComplete="current-password"
              placeholder="Your account password"
            />
          </div>

          {error && <p className={styles.error} role="alert">{error}</p>}
        </div>

        <div className={styles.actions}>
          <button type="button" className={styles.cancelButton} onClick={onClose} disabled={submitting}>
            Cancel
          </button>
          <button
            type="submit"
            className={styles.confirmButton}
            disabled={submitting}
            aria-busy={submitting}
          >
            <LogOut size={15} style={{ marginRight: 6, verticalAlign: '-2px' }} aria-hidden="true" />
            {submitting ? 'Signing out…' : 'Sign out'}
          </button>
        </div>
      </form>
    </div>
  );
}
