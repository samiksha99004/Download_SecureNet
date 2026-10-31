/**
 * SecureNet — SignupForm (registration step 1 of 3)
 *
 *  1. Full name, email, phone number → a verification code is emailed
 *  2. OtpForm: enter the code
 *  3. CreatePasswordForm: choose the password → account created + signed in
 *
 * Full client-side validation (same phone rule as the backend), loading and
 * error states. On success it opens the code page for that email.
 */

import { useState, type FormEvent } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { isValidEmail, isValidPhone, isNonEmpty, minLength } from '../../utils/validation';
import { FormField } from './FormField';
import { AuthButton } from './AuthButton';
import styles from './SignupForm.module.css';

interface FormErrors {
  fullName?: string;
  email?: string;
  phoneNumber?: string;
}

export function SignupForm() {
  const navigate = useNavigate();
  const { signup, status } = useAuth();

  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [errors, setErrors] = useState<FormErrors>({});
  const [formError, setFormError] = useState<string | null>(null);

  const isLoading = status === 'loading';

  function clearField(field: keyof FormErrors) {
    setErrors((prev) => ({ ...prev, [field]: undefined }));
  }

  function validate(): boolean {
    const next: FormErrors = {};

    if (!isNonEmpty(fullName)) {
      next.fullName = 'Full name is required.';
    } else if (!minLength(fullName.trim(), 2)) {
      next.fullName = 'Full name must be at least 2 characters.';
    }

    if (!isNonEmpty(email)) {
      next.email = 'Email is required.';
    } else if (!isValidEmail(email)) {
      next.email = 'Please enter a valid email address.';
    }

    if (!isNonEmpty(phoneNumber)) {
      next.phoneNumber = 'Phone number is required.';
    } else if (!isValidPhone(phoneNumber)) {
      next.phoneNumber = 'Enter a valid phone number (7–15 digits, e.g. +91 98765 43210).';
    }

    setErrors(next);
    return Object.keys(next).length === 0;
  }

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError(null);

    if (!validate()) return;

    try {
      await signup({
        fullName: fullName.trim(),
        email: email.trim(),
        phoneNumber: phoneNumber.trim(),
      });
      navigate('/otp-verify', { state: { email: email.trim() } });
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : 'Could not send the verification code. Please try again.'
      );
    }
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h1 className={styles.title}>Create account</h1>
        <p className={styles.subtitle}>
          Step 1 of 3 — we&apos;ll email you a verification code.
        </p>
      </div>

      {formError && (
        <div className={styles.formError} role="alert">
          {formError}
        </div>
      )}

      <form onSubmit={handleSubmit} className={styles.form} noValidate>
        <FormField
          id="signup-name"
          label="Full name"
          type="text"
          value={fullName}
          onChange={(e) => { setFullName(e.target.value); clearField('fullName'); }}
          autoComplete="name"
          placeholder="Your full name"
          error={errors.fullName}
          disabled={isLoading}
        />

        <FormField
          id="signup-email"
          label="Email address"
          type="email"
          value={email}
          onChange={(e) => { setEmail(e.target.value); clearField('email'); }}
          autoComplete="email"
          placeholder="you@gmail.com"
          error={errors.email}
          disabled={isLoading}
          hint={!errors.email ? 'The verification code is sent here.' : undefined}
        />

        <FormField
          id="signup-phone"
          label="Phone number"
          type="tel"
          value={phoneNumber}
          onChange={(e) => { setPhoneNumber(e.target.value); clearField('phoneNumber'); }}
          autoComplete="tel"
          inputMode="tel"
          placeholder="+91 98765 43210"
          error={errors.phoneNumber}
          disabled={isLoading}
        />

        <AuthButton type="submit" isLoading={isLoading} disabled={isLoading}>
          Send verification code
        </AuthButton>
      </form>

      <p className={styles.switchLink}>
        Already have an account?{' '}
        <Link to="/login" className={styles.link}>
          Sign in
        </Link>
      </p>
    </div>
  );
}
