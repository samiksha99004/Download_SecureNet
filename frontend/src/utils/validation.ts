/**
 * SecureNet — Form Validation Utilities
 */

export function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

export function isValidPassword(password: string): boolean {
  // Minimum 8 chars, at least one letter and one number
  return password.length >= 8 && /[A-Za-z]/.test(password) && /\d/.test(password);
}

export interface PasswordStrength {
  score: number;       // 0–4
  label: 'Very Weak' | 'Weak' | 'Fair' | 'Strong' | 'Very Strong';
  color: string;       // CSS color
}

export function getPasswordStrength(password: string): PasswordStrength {
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  score = Math.min(score, 4);

  const map: PasswordStrength[] = [
    { score: 0, label: 'Very Weak', color: 'var(--color-severity-high)' },
    { score: 1, label: 'Weak', color: 'var(--color-severity-high)' },
    { score: 2, label: 'Fair', color: 'var(--color-severity-medium)' },
    { score: 3, label: 'Strong', color: 'var(--color-severity-low)' },
    { score: 4, label: 'Very Strong', color: 'var(--color-severity-low)' },
  ];

  return map[score];
}

export function isValidOtp(otp: string): boolean {
  return /^\d{6}$/.test(otp.trim());
}

/** 7-15 digits, optional leading +; spaces, dashes, dots and brackets are ignored (same rule as the backend). */
export function isValidPhone(phone: string): boolean {
  return /^\+?\d{7,15}$/.test(phone.trim().replace(/[\s().-]/g, ''));
}

export function isValidIpAddress(ip: string): boolean {
  // IPv4
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  // IPv4 CIDR
  const cidr = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
  return ipv4.test(ip) || cidr.test(ip);
}

export function isNonEmpty(value: string): boolean {
  return value.trim().length > 0;
}

export function minLength(value: string, min: number): boolean {
  return value.trim().length >= min;
}

export function maxLength(value: string, max: number): boolean {
  return value.trim().length <= max;
}
