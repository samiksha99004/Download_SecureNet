/**
 * SecureNet — Authentication Types
 *
 * These interfaces define the shape of auth-related data.
 * All fields reflect what the backend will eventually provide.
 */

// ── User ──────────────────────────────────────────────────────────────────────

export type AuthProvider = 'local' | 'google';

export type AccountStatus = 'active' | 'suspended' | 'pending_verification';

export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface User {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
  accountStatus: AccountStatus;
  authProvider: AuthProvider;
  createdAt: string;      // ISO 8601
  lastLoginAt: string | null;
  avatarUrl: string | null;
  phoneNumber: string | null;
  /** attack alert emails on/off for this account */
  emailAlerts: boolean;
}

// ── Auth Requests ─────────────────────────────────────────────────────────────

export interface LoginRequest {
  email: string;
  password: string;
}

/** Right email + password: a sign-in code was emailed; send it back with `loginToken`. */
export interface LoginChallenge {
  loginToken: string;
  sentTo: string;
  message: string;
}

/** Registration step 1 — a verification code is emailed to `email`. */
export interface SignupRequest {
  fullName: string;
  email: string;
  phoneNumber: string;
}

/** Registration step 3 — choose the password (after the code was verified). */
export interface CompleteSignupRequest {
  setupToken: string;
  password: string;
  confirmPassword: string;
}

export interface OtpVerifyRequest {
  email: string;
  otp: string;
}

/** Forgot password step 2 — `resetToken` allows choosing a new password once. */
export interface PasswordResetVerifyResponse {
  verified: boolean;
  email: string;
  resetToken: string;
}

/** Forgot password step 3. */
export interface ResetPasswordRequest {
  resetToken: string;
  password: string;
  confirmPassword: string;
}

export interface OtpResendRequest {
  email: string;
}

/** Change your own details; only fields that differ are changed. */
export interface ProfileChangeRequest {
  fullName?: string;
  phoneNumber?: string;
  email?: string;
}

/** A code was emailed (to the new address if the email changes). */
export interface ProfileChangeStarted {
  changeToken: string;
  sentTo: string;
  message: string;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
  confirmNewPassword: string;
}

/** Step 2 of a password change: the emailed code + the same new password. */
export interface ChangePasswordConfirm {
  changeToken: string;
  otp: string;
  newPassword: string;
}



// ── Auth Responses ────────────────────────────────────────────────────────────

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number; // seconds
}

export interface AuthResponse {
  user: User;
  tokens: AuthTokens;
}

/** Registration step 2 — `setupToken` allows setting the password for a few minutes. */
export interface OtpVerifyResponse {
  verified: boolean;
  email: string;
  setupToken: string;
}

// ── Auth State ────────────────────────────────────────────────────────────────

export type AuthStatus =
  | 'idle'
  | 'loading'
  | 'authenticated'
  | 'unauthenticated'
  | 'error';

export interface AuthState {
  status: AuthStatus;
  user: User | null;
  error: string | null;
}
