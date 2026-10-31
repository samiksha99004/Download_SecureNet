/**
 * SecureNet — EditProfileCard
 *
 * Every user can change their own name, phone number and email. The details are
 * verified (format + a changed email must be free) and saved immediately — no
 * emailed code. The old address is notified when the email changes.
 */

import { useState, type FormEvent } from 'react';
import { Card } from '../common/Card';
import { useToast } from '../common/Toast';
import { useAuth } from '../../contexts/AuthContext';
import * as authService from '../../services/authService';
import type { ProfileChangeRequest, User } from '../../types/auth.types';
import { isValidEmail, isValidPhone } from '../../utils/validation';
import styles from './ChangePasswordCard.module.css';
import local from './EditProfileCard.module.css';

export function EditProfileCard({ user }: { user: User }) {
  const { completeLogin } = useAuth();
  const { showToast } = useToast();

  const [fullName, setFullName] = useState(user.fullName);
  const [phone, setPhone] = useState(user.phoneNumber ?? '');
  const [email, setEmail] = useState(user.email);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const changes: ProfileChangeRequest = {};
  if (fullName.trim() !== user.fullName) changes.fullName = fullName.trim();
  if (phone.trim() !== (user.phoneNumber ?? '')) changes.phoneNumber = phone.trim();
  if (email.trim().toLowerCase() !== user.email.toLowerCase()) changes.email = email.trim();
  const hasChanges = Object.keys(changes).length > 0;

  function validate(): string | null {
    if (fullName.trim().length < 2) return 'Full name must be at least 2 characters.';
    if (!isValidPhone(phone)) return 'Enter a valid phone number (7–15 digits, e.g. +91 98765 43210).';
    if (!isValidEmail(email)) return 'Please enter a valid email address.';
    return null;
  }

  async function save(e?: FormEvent<HTMLFormElement>) {
    e?.preventDefault();
    setError(null);
    const invalid = validate();
    if (invalid) { setError(invalid); return; }
    if (!hasChanges) { setError('Nothing to change — your details are the same.'); return; }
    setBusy(true);
    try {
      const updated = await authService.updateProfile(changes);
      completeLogin(updated);
      setFullName(updated.fullName);
      setPhone(updated.phoneNumber ?? '');
      setEmail(updated.email);
      showToast({ message: 'Your details have been updated.', variant: 'success' });
    } catch (err) {
      setError(err instanceof Error && err.message ? err.message : 'Could not update your details. Please try again.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card padding="lg">
      <h3 className={styles.heading}>Edit Details</h3>
      <p className={local.intro}>
        Change your name, phone number or email. The details are verified and saved right away.
      </p>

      <form onSubmit={save} className={styles.form} noValidate>
        <div className={styles.fieldGroup}>
          <label htmlFor="edit-name" className={styles.label}>Full Name</label>
          <input id="edit-name" className={styles.input} value={fullName} disabled={busy}
                 autoComplete="name" onChange={(e) => { setFullName(e.target.value); setError(null); }} />
        </div>
        <div className={styles.fieldGroup}>
          <label htmlFor="edit-phone" className={styles.label}>Phone Number</label>
          <input id="edit-phone" className={styles.input} value={phone} disabled={busy} type="tel" inputMode="tel"
                 autoComplete="tel" onChange={(e) => { setPhone(e.target.value); setError(null); }} />
        </div>
        <div className={styles.fieldGroup}>
          <label htmlFor="edit-email" className={styles.label}>Email</label>
          <input id="edit-email" className={styles.input} value={email} disabled={busy} type="email"
                 autoComplete="email" onChange={(e) => { setEmail(e.target.value); setError(null); }} />
        </div>

        {error && <p className={styles.error} role="alert">{error}</p>}

        <div className={styles.actions}>
          <button type="submit" className={styles.submitBtn} disabled={busy || !hasChanges}>
            {busy ? 'Saving…' : 'Verify and update'}
          </button>
        </div>
      </form>
    </Card>
  );
}
