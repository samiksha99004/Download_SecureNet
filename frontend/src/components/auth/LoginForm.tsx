/**
 * SecureNet — LoginForm
 *
 * Two-step sign-in:
 *  1. Email + password (show/hide toggle, validation, lockout messages)
 *  2. The 6-digit code emailed to the account (valid 5 minutes; resend once
 *     a minute; "use a different account" goes back to step 1)
 * Nothing is signed in until the code is accepted.
 */

import { useEffect, useState, type FormEvent } from 'react';
import { Eye, EyeOff } from 'lucide-react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { isValidEmail, isValidOtp, isNonEmpty } from '../../utils/validation';
import * as authService from '../../services/authService';
import { FormField } from './FormField';
import { AuthButton } from './AuthButton';
import styles from './LoginForm.module.css';
import local from './ForgotPasswordForm.module.css';

const RESEND_COOLDOWN_SECONDS = 60;

interface FormErrors {
  email?: string;
  password?: string;
  form?: string;
}

export function LoginForm() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, verifyLogin, status } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState<FormErrors>({});
  const [formError, setFormError] = useState<string | null>(null);

  const isLoading = status === 'loading';

  // Step 2: the emailed sign-in code
  const [challenge, setChallenge] = useState<{ token: string; message: string } | null>(null);
  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  // Message handed over by another page (e.g. "password changed")
  const notice = (location.state as { notice?: string } | null)?.notice ?? null;

  // Where to redirect after login
  const from =
    (location.state as { from?: { pathname: string } })?.from?.pathname ??
    '/dashboard';

  function validate(): boolean {
    const next: FormErrors = {};
    if (!isNonEmpty(email)) {
      next.email = 'Email is required.';
    } else if (!isValidEmail(email)) {
      next.email = 'Please enter a valid email address.';
    }
    if (!isNonEmpty(password)) {
      next.password = 'Password is required.';
    }
    setErrors(next);
    return Object.keys(next).length === 0;
  }

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError(null);

    if (!validate()) return;

    try {
      const started = await login({ email: email.trim(), password });
      setChallenge({ token: started.loginToken, message: started.message });
      setCode('');
      setCodeError(null);
      setCooldown(RESEND_COOLDOWN_SECONDS);
    } catch (err) {
      setFormError(
        err instanceof Error && err.message
          ? err.message
          : 'Login failed. Please check your credentials.'
      );
    }
  }

  async function handleCode(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!challenge) return;
    if (!isValidOtp(code)) { setCodeError('Enter the 6-digit code from the email.'); return; }
    setBusy(true);
    setFormError(null);
    try {
      await verifyLogin(challenge.token, code);
      navigate(from, { replace: true });
    } catch (err) {
      setFormError(err instanceof Error && err.message ? err.message : 'Could not sign you in. Please try again.');
    } finally {
      setBusy(false);
    }
  }

  async function resend() {
    if (!challenge) return;
    setBusy(true);
    setFormError(null);
    try {
      const response = await authService.resendLoginCode(challenge.token);
      setChallenge({ ...challenge, message: response.message });
      setCooldown(RESEND_COOLDOWN_SECONDS);
    } catch (err) {
      setFormError(err instanceof Error && err.message ? err.message : 'Could not send a new code.');
    } finally {
      setBusy(false);
    }
  }

  function startOver() {
    setChallenge(null);
    setCode('');
    setCodeError(null);
    setFormError(null);
    setPassword('');
  }

  if (challenge) {
    return (
      <div className={styles.container}>
        <div className={styles.header}>
          <h1 className={styles.title}>Check your email</h1>
          <p className={styles.subtitle}>One more step to keep your account safe.</p>
        </div>

        {!formError && (
          <div className={styles.notice} role="status">{challenge.message}</div>
        )}
        {formError && (
          <div className={styles.formError} role="alert">{formError}</div>
        )}

        <form onSubmit={handleCode} className={styles.form} noValidate>
          <FormField
            id="login-code"
            label="Sign-in code"
            type="text"
            inputMode="numeric"
            maxLength={6}
            value={code}
            onChange={(e) => { setCode(e.target.value.replace(/\D/g, '').slice(0, 6)); setCodeError(null); }}
            autoComplete="one-time-code"
            placeholder="6-digit code"
            hint="The code works for 5 minutes."
            error={codeError ?? undefined}
            disabled={busy}
          />
          <AuthButton type="submit" isLoading={busy} disabled={busy || code.length < 6}>
            Verify and sign in
          </AuthButton>
          <p className={local.resendRow}>
            {cooldown > 0 ? (
              <>Resend available in <span className={local.countdown}>{cooldown}s</span></>
            ) : (
              <>
                Didn&apos;t receive a code?{' '}
                <button type="button" className={local.textButton} onClick={() => void resend()} disabled={busy}>
                  Resend code
                </button>
              </>
            )}
            {' · '}
            <button type="button" className={local.textButton} onClick={startOver} disabled={busy}>
              Use a different account
            </button>
          </p>
        </form>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h1 className={styles.title}>Welcome back</h1>
        <p className={styles.subtitle}>Sign in to your SecureNet account.</p>
      </div>

      {notice && !formError && (
        <div className={styles.notice} role="status">
          {notice}
        </div>
      )}

      {/* ── Global form error ── */}
      {formError && (
        <div className={styles.formError} role="alert">
          {formError}
        </div>
      )}

      <form onSubmit={handleSubmit} className={styles.form} noValidate>
        <FormField
          id="login-email"
          label="Email address"
          type="email"
          value={email}
          onChange={(e) => {
            setEmail(e.target.value);
            if (errors.email) setErrors((prev) => ({ ...prev, email: undefined }));
          }}
          autoComplete="email"
          placeholder="you@example.com"
          error={errors.email}
          disabled={isLoading}
        />

        <FormField
          id="login-password"
          label="Password"
          type={showPassword ? 'text' : 'password'}
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
            if (errors.password) setErrors((prev) => ({ ...prev, password: undefined }));
          }}
          autoComplete="current-password"
          placeholder="Enter your password"
          error={errors.password}
          disabled={isLoading}
          rightElement={
            <button
              type="button"
              aria-label={showPassword ? 'Hide password' : 'Show password'}
              onClick={() => setShowPassword((v) => !v)}
              className={styles.eyeButton}
              tabIndex={0}
            >
              {showPassword
                ? <EyeOff size={16} />
                : <Eye size={16} />}
            </button>
          }
        />

        <p className={styles.forgotRow}>
          <Link to="/forgot-password" className={styles.forgotLink}>
            Forgot password?
          </Link>
        </p>

        <AuthButton type="submit" isLoading={isLoading} disabled={isLoading}>
          Sign in
        </AuthButton>
      </form>

      <p className={styles.switchLink}>
        Don&apos;t have an account?{' '}
        <Link to="/signup" className={styles.link}>
          Create account
        </Link>
      </p>
    </div>
  );
}
