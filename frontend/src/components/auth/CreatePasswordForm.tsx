/**
 * SecureNet — CreatePasswordForm (registration step 3 of 3)
 *
 * Shown after the emailed code was verified. Choosing the password creates
 * the account and signs the user in; afterwards they sign in with email +
 * password. The short-lived setup token comes from the code step.
 */

import { useState, type FormEvent } from 'react';
import { Eye, EyeOff } from 'lucide-react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import * as authService from '../../services/authService';
import { useAuth } from '../../contexts/AuthContext';
import { isValidPassword, isNonEmpty } from '../../utils/validation';
import { FormField } from './FormField';
import { AuthButton } from './AuthButton';
import { PasswordStrengthBar } from './PasswordStrengthBar';
import styles from './SignupForm.module.css';

interface FormErrors {
  password?: string;
  confirmPassword?: string;
}

export function CreatePasswordForm() {
  const navigate = useNavigate();
  const location = useLocation();
  const { completeLogin } = useAuth();

  const state = location.state as { email?: string; setupToken?: string } | null;
  const email = state?.email ?? authService.getPendingEmail();
  const setupToken = state?.setupToken ?? authService.getSetupToken();

  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [errors, setErrors] = useState<FormErrors>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  function validate(): boolean {
    const next: FormErrors = {};
    if (!isNonEmpty(password)) {
      next.password = 'Password is required.';
    } else if (!isValidPassword(password)) {
      next.password = 'Password must be at least 8 characters and include a letter and a number.';
    }
    if (!isNonEmpty(confirmPassword)) {
      next.confirmPassword = 'Please confirm your password.';
    } else if (password !== confirmPassword) {
      next.confirmPassword = 'Passwords do not match.';
    }
    setErrors(next);
    return Object.keys(next).length === 0;
  }

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError(null);
    if (!validate()) return;

    setIsSaving(true);
    try {
      const auth = await authService.completeSignup({ setupToken, password, confirmPassword });
      completeLogin(auth.user);
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Could not create the account. Please try again.');
    } finally {
      setIsSaving(false);
    }
  }

  if (!setupToken) {
    return (
      <div className={styles.container}>
        <div className={styles.header}>
          <h1 className={styles.title}>Create password</h1>
          <p className={styles.subtitle}>
            Verify your email first — start the registration to receive a code.
          </p>
        </div>
        <p className={styles.switchLink}>
          <Link to="/signup" className={styles.link}>Create account</Link>
          {' · '}
          <Link to="/login" className={styles.link}>Sign in</Link>
        </p>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h1 className={styles.title}>Create your password</h1>
        <p className={styles.subtitle}>
          Step 3 of 3 — {email ? <>email <strong>{email}</strong> verified.</> : 'email verified.'}{' '}
          You will sign in with this email and password.
        </p>
      </div>

      {formError && (
        <div className={styles.formError} role="alert">
          {formError}
        </div>
      )}

      <form onSubmit={handleSubmit} className={styles.form} noValidate>
        {/* Lets password managers save the email together with the new password */}
        <input type="email" name="email" autoComplete="username" value={email} readOnly hidden />

        <div>
          <FormField
            id="create-password"
            label="Password"
            type={showPassword ? 'text' : 'password'}
            value={password}
            onChange={(e) => { setPassword(e.target.value); setErrors((p) => ({ ...p, password: undefined })); }}
            autoComplete="new-password"
            placeholder="Choose a strong password"
            error={errors.password}
            disabled={isSaving}
            hint={!errors.password ? 'At least 8 characters with a letter and a number.' : undefined}
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
          id="create-password-confirm"
          label="Confirm password"
          type={showConfirm ? 'text' : 'password'}
          value={confirmPassword}
          onChange={(e) => { setConfirmPassword(e.target.value); setErrors((p) => ({ ...p, confirmPassword: undefined })); }}
          autoComplete="new-password"
          placeholder="Repeat your password"
          error={errors.confirmPassword}
          disabled={isSaving}
          rightElement={
            <button
              type="button"
              aria-label={showConfirm ? 'Hide confirm password' : 'Show confirm password'}
              onClick={() => setShowConfirm((v) => !v)}
              className={styles.eyeButton}
            >
              {showConfirm ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          }
        />

        <AuthButton type="submit" isLoading={isSaving} disabled={isSaving}>
          Create account
        </AuthButton>
      </form>
    </div>
  );
}
