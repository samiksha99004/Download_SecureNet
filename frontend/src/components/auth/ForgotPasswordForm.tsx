/**
 * SecureNet — ForgotPasswordForm
 *
 *  1. Enter the account email → a 6-digit code is emailed (from the admin Gmail)
 *  2. Enter the code (checked by the backend; wrong codes are counted)
 *  3. Choose the new password → back to sign in with a confirmation
 *
 * The backend answers step 1 the same way whether or not the account exists.
 */

import { useEffect, useState, type FormEvent } from 'react';
import { Eye, EyeOff } from 'lucide-react';
import { useNavigate, Link } from 'react-router-dom';
import * as authService from '../../services/authService';
import { isValidEmail, isValidOtp, isValidPassword, isNonEmpty } from '../../utils/validation';
import { FormField } from './FormField';
import { AuthButton } from './AuthButton';
import { PasswordStrengthBar } from './PasswordStrengthBar';
import styles from './SignupForm.module.css';
import local from './ForgotPasswordForm.module.css';

type Step = 'email' | 'code' | 'password';
const RESEND_COOLDOWN_SECONDS = 60;

export function ForgotPasswordForm() {
  const navigate = useNavigate();

  const [step, setStep] = useState<Step>('email');
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const [fieldError, setFieldError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  async function run(action: () => Promise<void>) {
    setFormError(null);
    setBusy(true);
    try {
      await action();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Something went wrong. Please try again.');
    } finally {
      setBusy(false);
    }
  }

  async function sendCode(e?: FormEvent<HTMLFormElement>) {
    e?.preventDefault();
    setFieldError(null);
    if (!isNonEmpty(email) || !isValidEmail(email)) {
      setFieldError('Please enter a valid email address.');
      return;
    }
    await run(async () => {
      const response = await authService.forgotPassword(email.trim());
      setInfo(response.message);
      setCode('');
      setCooldown(RESEND_COOLDOWN_SECONDS);
      setStep('code');
    });
  }

  async function verifyCode(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFieldError(null);
    if (!isValidOtp(code)) {
      setFieldError('Enter the 6-digit code from the email.');
      return;
    }
    await run(async () => {
      const response = await authService.verifyPasswordReset({ email: email.trim(), otp: code.trim() });
      setResetToken(response.resetToken);
      setInfo(null);
      setStep('password');
    });
  }

  async function savePassword(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFieldError(null);
    if (!isValidPassword(password)) {
      setFieldError('Password must be at least 8 characters and include a letter and a number.');
      return;
    }
    if (password !== confirmPassword) {
      setFieldError('Passwords do not match.');
      return;
    }
    await run(async () => {
      const response = await authService.resetPassword({ resetToken, password, confirmPassword });
      navigate('/login', { replace: true, state: { notice: response.message } });
    });
  }

  const subtitle = {
    email: 'Step 1 of 3 — enter your account email and we’ll send you a verification code.',
    code: `Step 2 of 3 — enter the 6-digit code sent to ${email.trim()}.`,
    password: 'Step 3 of 3 — choose your new password.',
  }[step];

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h1 className={styles.title}>Reset password</h1>
        <p className={styles.subtitle}>{subtitle}</p>
      </div>

      {formError && (
        <div className={styles.formError} role="alert">
          {formError}
        </div>
      )}
      {info && !formError && (
        <div className={local.info} role="status">
          {info}
        </div>
      )}

      {step === 'email' && (
        <form onSubmit={sendCode} className={styles.form} noValidate>
          <FormField
            id="forgot-email"
            label="Email address"
            type="email"
            value={email}
            onChange={(e) => { setEmail(e.target.value); setFieldError(null); }}
            autoComplete="email"
            placeholder="you@gmail.com"
            error={fieldError ?? undefined}
            disabled={busy}
          />
          <AuthButton type="submit" isLoading={busy} disabled={busy}>
            Send verification code
          </AuthButton>
        </form>
      )}

      {step === 'code' && (
        <form onSubmit={verifyCode} className={styles.form} noValidate>
          <FormField
            id="forgot-code"
            label="Verification code"
            type="text"
            inputMode="numeric"
            maxLength={6}
            value={code}
            onChange={(e) => { setCode(e.target.value.replace(/\D/g, '').slice(0, 6)); setFieldError(null); }}
            autoComplete="one-time-code"
            placeholder="6-digit code"
            error={fieldError ?? undefined}
            disabled={busy}
          />
          <AuthButton type="submit" isLoading={busy} disabled={busy || code.length < 6}>
            Verify code
          </AuthButton>
          <p className={local.resendRow}>
            {cooldown > 0 ? (
              <>Resend available in <span className={local.countdown}>{cooldown}s</span></>
            ) : (
              <>
                Didn&apos;t receive a code?{' '}
                <button type="button" className={local.textButton} onClick={() => void sendCode()} disabled={busy}>
                  Resend code
                </button>
              </>
            )}
            {' · '}
            <button type="button" className={local.textButton} onClick={() => { setStep('email'); setInfo(null); setFormError(null); }}>
              Change email
            </button>
          </p>
        </form>
      )}

      {step === 'password' && (
        <form onSubmit={savePassword} className={styles.form} noValidate>
          <input type="email" name="email" autoComplete="username" value={email.trim()} readOnly hidden />
          <div>
            <FormField
              id="forgot-password"
              label="New password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => { setPassword(e.target.value); setFieldError(null); }}
              autoComplete="new-password"
              placeholder="Choose a strong password"
              disabled={busy}
              hint="At least 8 characters with a letter and a number."
              rightElement={
                <button
                  type="button"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  onClick={() => setShowPassword((v) => !v)}
                  className={styles.eyeButton}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              }
            />
            <PasswordStrengthBar password={password} />
          </div>
          <FormField
            id="forgot-password-confirm"
            label="Confirm new password"
            type={showPassword ? 'text' : 'password'}
            value={confirmPassword}
            onChange={(e) => { setConfirmPassword(e.target.value); setFieldError(null); }}
            autoComplete="new-password"
            placeholder="Repeat your new password"
            error={fieldError ?? undefined}
            disabled={busy}
          />
          <AuthButton type="submit" isLoading={busy} disabled={busy}>
            Save new password
          </AuthButton>
        </form>
      )}

      <p className={styles.switchLink}>
        <Link to="/login" className={styles.link}>
          ← Back to sign in
        </Link>
      </p>
    </div>
  );
}
