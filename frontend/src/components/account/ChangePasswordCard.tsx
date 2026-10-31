/**
 * SecureNet — ChangePasswordCard
 *
 * Two-step password change for local-auth users (Google accounts see a note):
 *   1. current + new password → the server checks them and emails a 6-digit
 *      code to the registered address (authService.changePassword)
 *   2. the code confirms it (authService.confirmPasswordChange)
 * Nothing changes until the code is entered, so a signed-in session alone
 * can't change the password.
 */

import { useState, type FormEvent } from 'react';
import { Eye, EyeOff } from 'lucide-react';
import type { User } from '../../types/auth.types';
import { changePassword, confirmPasswordChange } from '../../services/authService';
import { useToast } from '../common/Toast';
import { Card } from '../common/Card';
import { isValidOtp, isValidPassword } from '../../utils/validation';
import styles from './ChangePasswordCard.module.css';
import local from './EditProfileCard.module.css';
import { errorMessage } from '../../utils/errors';

interface ChangePasswordCardProps {
  user: User;
}

export function ChangePasswordCard({ user }: ChangePasswordCardProps) {
  const { showToast } = useToast();

  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNext, setShowNext] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [isSaving, setIsSaving] = useState(false);
  const [pending, setPending] = useState<{ token: string; message: string } | null>(null);
  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState<string | null>(null);

  // Google OAuth users cannot change their password through SecureNet
  if (user.authProvider === 'google') {
    return (
      <Card padding="lg">
        <h3 className={styles.heading}>Security</h3>
        <div className={styles.oauthNotice} role="note">
          <p className={styles.oauthTitle}>Password change not available</p>
          <p className={styles.oauthDesc}>
            Your account is authenticated via Google OAuth. Password management
            is handled by your Google account settings.
          </p>
        </div>
      </Card>
    );
  }

  function validate(): boolean {
    const errs: Record<string, string> = {};
    if (!current.trim()) errs.current = 'Current password is required.';
    if (!isValidPassword(next)) {
      errs.next = 'New password must be at least 8 characters and include a letter and a number.';
    }
    if (next !== confirm) errs.confirm = 'Passwords do not match.';
    if (next === current && next !== '') errs.next = 'New password must differ from your current password.';
    setErrors(errs);
    return Object.keys(errs).length === 0;
  }

  // Step 1 (and "Resend code"): check the passwords, email a code
  async function sendCode(e?: FormEvent<HTMLFormElement>) {
    e?.preventDefault();
    if (!pending && !validate()) return;
    setIsSaving(true);
    setCodeError(null);
    try {
      const started = await changePassword({
        currentPassword: current,
        newPassword: next,
        confirmNewPassword: confirm,
      });
      setPending({ token: started.changeToken, message: started.message });
      setCode('');
    } catch (err) {
      const message = errorMessage(err, 'Could not send the code. Please try again.');
      if (pending) setCodeError(message);
      else showToast({ message, variant: 'error' });
    } finally {
      setIsSaving(false);
    }
  }

  // Step 2: the emailed code confirms the new password
  async function confirmCode(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!pending) return;
    if (!isValidOtp(code)) { setCodeError('Enter the 6-digit code from the email.'); return; }
    setIsSaving(true);
    setCodeError(null);
    try {
      await confirmPasswordChange({ changeToken: pending.token, otp: code.trim(), newPassword: next });
      showToast({ message: 'Your password has been changed.', variant: 'success' });
      reset();
    } catch (err) {
      setCodeError(errorMessage(err, 'Could not confirm the change. Please try again.'));
    } finally {
      setIsSaving(false);
    }
  }

  function reset() {
    setPending(null);
    setCode('');
    setCodeError(null);
    setCurrent(''); setNext(''); setConfirm('');
    setErrors({});
  }

  if (pending) {
    return (
      <Card padding="lg">
        <h3 className={styles.heading}>Change Password</h3>
        <form onSubmit={confirmCode} className={styles.form} noValidate>
          <p className={local.sent} role="status">{pending.message}</p>
          <div className={styles.fieldGroup}>
            <label htmlFor="pwd-code" className={styles.label}>Verification Code</label>
            <input id="pwd-code" className={styles.input} value={code} disabled={isSaving} inputMode="numeric"
                   autoComplete="one-time-code" maxLength={6} placeholder="6-digit code"
                   onChange={(e) => { setCode(e.target.value.replace(/\D/g, '').slice(0, 6)); setCodeError(null); }} />
          </div>

          {codeError && <p className={styles.error} role="alert">{codeError}</p>}

          <div className={local.buttons}>
            <button type="submit" className={styles.submitBtn} disabled={isSaving || code.length < 6}>
              {isSaving ? 'Confirming…' : 'Confirm new password'}
            </button>
            <button type="button" className={local.secondary} onClick={() => void sendCode()} disabled={isSaving}>
              Resend code
            </button>
            <button type="button" className={local.secondary} onClick={reset} disabled={isSaving}>
              Cancel
            </button>
          </div>
        </form>
      </Card>
    );
  }

  return (
    <Card padding="lg">
      <h3 className={styles.heading}>Change Password</h3>
      <p className={local.intro}>
        For your safety, we&apos;ll email a 6-digit code to your registered address before the new password is saved.
      </p>

      <form onSubmit={sendCode} className={styles.form} noValidate>
        {/* Current password */}
        <div className={styles.fieldGroup}>
          <label htmlFor="pwd-current" className={styles.label}>Current Password</label>
          <div className={styles.inputWrap}>
            <input
              id="pwd-current"
              type={showCurrent ? 'text' : 'password'}
              className={styles.input}
              value={current}
              onChange={(e) => { setCurrent(e.target.value); setErrors((p) => ({ ...p, current: '' })); }}
              autoComplete="current-password"
            />
            <button
              type="button"
              className={styles.eyeBtn}
              onClick={() => setShowCurrent((p) => !p)}
              aria-label={showCurrent ? 'Hide password' : 'Show password'}
            >
              {showCurrent ? <EyeOff size={15} /> : <Eye size={15} />}
            </button>
          </div>
          {errors.current && <p className={styles.error}>{errors.current}</p>}
        </div>

        {/* New password */}
        <div className={styles.fieldGroup}>
          <label htmlFor="pwd-new" className={styles.label}>New Password</label>
          <div className={styles.inputWrap}>
            <input
              id="pwd-new"
              type={showNext ? 'text' : 'password'}
              className={styles.input}
              value={next}
              onChange={(e) => { setNext(e.target.value); setErrors((p) => ({ ...p, next: '' })); }}
              autoComplete="new-password"
            />
            <button
              type="button"
              className={styles.eyeBtn}
              onClick={() => setShowNext((p) => !p)}
              aria-label={showNext ? 'Hide password' : 'Show password'}
            >
              {showNext ? <EyeOff size={15} /> : <Eye size={15} />}
            </button>
          </div>
          {errors.next && <p className={styles.error}>{errors.next}</p>}
        </div>

        {/* Confirm */}
        <div className={styles.fieldGroup}>
          <label htmlFor="pwd-confirm" className={styles.label}>Confirm New Password</label>
          <div className={styles.inputWrap}>
            <input
              id="pwd-confirm"
              type={showConfirm ? 'text' : 'password'}
              className={styles.input}
              value={confirm}
              onChange={(e) => { setConfirm(e.target.value); setErrors((p) => ({ ...p, confirm: '' })); }}
              autoComplete="new-password"
            />
            <button
              type="button"
              className={styles.eyeBtn}
              onClick={() => setShowConfirm((p) => !p)}
              aria-label={showConfirm ? 'Hide password' : 'Show password'}
            >
              {showConfirm ? <EyeOff size={15} /> : <Eye size={15} />}
            </button>
          </div>
          {errors.confirm && <p className={styles.error}>{errors.confirm}</p>}
        </div>

        <div className={styles.actions}>
          <button
            type="submit"
            className={styles.submitBtn}
            disabled={isSaving}
            aria-busy={isSaving}
          >
            {isSaving ? 'Sending code…' : 'Update Password'}
          </button>
        </div>
      </form>
    </Card>
  );
}
