/**
 * SecureNet — OtpForm
 *
 * 6-digit OTP verification with:
 *  - Individual digit input boxes (keyboard navigable)
 *  - Paste support for the full 6-digit code
 *  - Resend OTP with countdown cooldown
 *  - Loading + error states
 *  - On success: opens step 3 (create password) — registration step 2 of 3
 */

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type ClipboardEvent,
} from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import * as authService from '../../services/authService';
import { isValidOtp } from '../../utils/validation';
import { AuthButton } from './AuthButton';
import { Spinner } from '../common/LoadingState';
import styles from './OtpForm.module.css';

const OTP_LENGTH = 6;
const RESEND_COOLDOWN_SECONDS = 60;

export function OtpForm() {
  const navigate = useNavigate();
  const location = useLocation();

  // Email passed from signup/login via router state (sessionStorage survives a refresh)
  const email =
    (location.state as { email?: string } | null)?.email ?? authService.getPendingEmail();

  const [digits, setDigits] = useState<string[]>(Array(OTP_LENGTH).fill(''));
  const [isVerifying, setIsVerifying] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resendMessage, setResendMessage] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(0);

  const inputRefs = useRef<Array<HTMLInputElement | null>>(
    Array(OTP_LENGTH).fill(null)
  );

  // Countdown timer for resend cooldown
  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  // Focus first input on mount
  useEffect(() => {
    inputRefs.current[0]?.focus();
  }, []);

  const otpValue = digits.join('');

  // ── Input handlers ──────────────────────────────────────────────────────────

  function handleDigitChange(index: number, value: string) {
    // Accept only a single digit
    const digit = value.replace(/\D/g, '').slice(-1);
    const next = [...digits];
    next[index] = digit;
    setDigits(next);
    setError(null);

    if (digit && index < OTP_LENGTH - 1) {
      inputRefs.current[index + 1]?.focus();
    }
  }

  function handleKeyDown(index: number, e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Backspace') {
      if (digits[index]) {
        const next = [...digits];
        next[index] = '';
        setDigits(next);
      } else if (index > 0) {
        inputRefs.current[index - 1]?.focus();
      }
    } else if (e.key === 'ArrowLeft' && index > 0) {
      inputRefs.current[index - 1]?.focus();
    } else if (e.key === 'ArrowRight' && index < OTP_LENGTH - 1) {
      inputRefs.current[index + 1]?.focus();
    }
  }

  function handlePaste(e: ClipboardEvent<HTMLInputElement>) {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, OTP_LENGTH);
    if (!pasted) return;
    const next = Array(OTP_LENGTH).fill('');
    pasted.split('').forEach((char, i) => { next[i] = char; });
    setDigits(next);
    // Focus the next empty slot or the last slot
    const nextFocus = Math.min(pasted.length, OTP_LENGTH - 1);
    inputRefs.current[nextFocus]?.focus();
  }

  // ── Submit ──────────────────────────────────────────────────────────────────

  async function handleVerify() {
    setError(null);
    if (!isValidOtp(otpValue)) {
      setError('Please enter all 6 digits.');
      return;
    }
    if (!email) {
      setError('No email address found. Please return to signup.');
      return;
    }

    setIsVerifying(true);
    try {
      const result = await authService.verifyOtp({ email, otp: otpValue });
      if (result.verified) {
        navigate('/create-password', { replace: true, state: { email: result.email, setupToken: result.setupToken } });
      } else {
        setError('Verification failed. Please check the code and try again.');
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Verification failed. Please try again.'
      );
    } finally {
      setIsVerifying(false);
    }
  }

  // ── Resend ──────────────────────────────────────────────────────────────────

  const handleResend = useCallback(async () => {
    if (cooldown > 0 || isResending) return;
    if (!email) {
      setError('No email address found. Please return to signup.');
      return;
    }

    setResendMessage(null);
    setError(null);
    setIsResending(true);

    try {
      const response = await authService.resendOtp({ email });
      setResendMessage(response.message);
      setCooldown(RESEND_COOLDOWN_SECONDS);
      setDigits(Array(OTP_LENGTH).fill(''));
      inputRefs.current[0]?.focus();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Failed to resend code.'
      );
    } finally {
      setIsResending(false);
    }
  }, [email, cooldown, isResending]);

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h1 className={styles.title}>Verify your email</h1>
        <p className={styles.subtitle}>
          {email
            ? <>Step 2 of 3 — enter the 6-digit code sent to <strong>{email}</strong>.</>
            : 'Step 2 of 3 — enter the 6-digit verification code sent to your email.'}
        </p>
      </div>

      {error && (
        <div className={styles.errorBanner} role="alert">
          {error}
        </div>
      )}

      {resendMessage && (
        <div className={styles.successBanner} role="status">
          {resendMessage}
        </div>
      )}

      {/* ── OTP input boxes ── */}
      <div
        className={styles.otpRow}
        role="group"
        aria-label="Enter 6-digit verification code"
      >
        {digits.map((digit, i) => (
          <input
            key={i}
            ref={(el) => { inputRefs.current[i] = el; }}
            type="text"
            inputMode="numeric"
            pattern="\d"
            maxLength={1}
            value={digit}
            onChange={(e) => handleDigitChange(i, e.target.value)}
            onKeyDown={(e) => handleKeyDown(i, e)}
            onPaste={i === 0 ? handlePaste : undefined}
            className={styles.otpInput}
            aria-label={`Digit ${i + 1} of ${OTP_LENGTH}`}
            disabled={isVerifying}
            autoComplete={i === 0 ? 'one-time-code' : 'off'}
          />
        ))}
      </div>

      <AuthButton
        type="button"
        onClick={handleVerify}
        isLoading={isVerifying}
        disabled={isVerifying || otpValue.length < OTP_LENGTH}
      >
        Verify code
      </AuthButton>

      {/* ── Resend ── */}
      <div className={styles.resendRow}>
        {isResending ? (
          <span className={styles.resendText}>
            <Spinner size="sm" /> Sending new code…
          </span>
        ) : cooldown > 0 ? (
          <span className={styles.resendText}>
            Resend available in{' '}
            <span className={styles.countdown}>{cooldown}s</span>
          </span>
        ) : (
          <span className={styles.resendText}>
            Didn&apos;t receive a code?{' '}
            <button
              type="button"
              className={styles.resendButton}
              onClick={handleResend}
            >
              Resend code
            </button>
          </span>
        )}
      </div>

      <p className={styles.backLink}>
        <Link to="/signup" className={styles.link}>
          ← Wrong email? Start again
        </Link>
      </p>
    </div>
  );
}
