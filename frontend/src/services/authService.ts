/**
 * SecureNet — Authentication Service
 *
 * All auth interactions go through this service. Token storage is handled
 * here (via apiClient.tokenStore) so components never touch localStorage.
 * The backend returns camelCase JSON matching src/types/auth.types.ts.
 */

import { apiClient, tokenStore } from './apiClient';
import type {
  LoginChallenge,
  LoginRequest,
  SignupRequest,
  OtpVerifyRequest,
  OtpResendRequest,
  OtpVerifyResponse,
  AuthResponse,
  ChangePasswordConfirm,
  ChangePasswordRequest,
  CompleteSignupRequest,
  PasswordResetVerifyResponse,
  ProfileChangeRequest,
  ProfileChangeStarted,
  ResetPasswordRequest,
  User,
} from '../types/auth.types';
import type { MessageResponse } from '../types/api.types';
import { storageGet, storageGetJson, storageRemove, storageSet } from '../utils/storage';

const USER_KEY = 'sn_user';
const PENDING_EMAIL_KEY = 'sn_pending_email';
const SETUP_TOKEN_KEY = 'sn_setup_token';

// ── Session Helpers ───────────────────────────────────────────────────────────

export function storeSession(auth: AuthResponse): void {
  tokenStore.set(auth.tokens.accessToken, auth.tokens.refreshToken);
  storeUser(auth.user);
}

export function clearTokens(): void {
  tokenStore.clear();
}

export function getAccessToken(): string | null {
  return tokenStore.getAccess();
}

export function storeUser(user: User): void {
  storageSet(USER_KEY, JSON.stringify(user));
}

/**
 * Stored profile, validated. Anything malformed (e.g. a snake_case profile
 * saved by an older build) is normalised or discarded — never trusted as-is,
 * because the UI dereferences these fields while rendering.
 */
export function getStoredUser(): User | null {
  const raw = storageGetJson<Record<string, unknown> | null>(USER_KEY, null);
  const user = raw && typeof raw === 'object' ? normaliseUser(raw) : null;
  if (!user) storageRemove(USER_KEY);
  return user;
}

function normaliseUser(raw: Record<string, unknown>): User | null {
  const str = (...keys: string[]): string | null => {
    for (const key of keys) {
      const value = raw[key];
      if (typeof value === 'string' && value) return value;
    }
    return null;
  };
  const id = str('id');
  const email = str('email');
  if (!id || !email) return null;
  const role = str('role');
  return {
    id,
    email,
    fullName: str('fullName', 'full_name') ?? email,
    role: role === 'admin' || role === 'analyst' ? role : 'viewer',
    accountStatus: (str('accountStatus', 'account_status') ?? 'active') as User['accountStatus'],
    authProvider: (str('authProvider', 'auth_provider') ?? 'local') as User['authProvider'],
    createdAt: str('createdAt', 'created_at') ?? '',
    lastLoginAt: str('lastLoginAt', 'last_login_at'),
    avatarUrl: str('avatarUrl', 'avatar_url'),
    phoneNumber: str('phoneNumber', 'phone_number'),
    emailAlerts: (raw.emailAlerts ?? raw.email_alerts) !== false,
  };
}

/** Email waiting for OTP verification (survives a page refresh). */
export function setPendingEmail(email: string | null): void {
  if (email) storageSet(PENDING_EMAIL_KEY, email, 'session');
  else storageRemove(PENDING_EMAIL_KEY, 'session');
}

export function getPendingEmail(): string {
  return storageGet(PENDING_EMAIL_KEY, 'session') ?? '';
}

/** Token from a verified code, kept for this tab only (survives a refresh). */
export function getSetupToken(): string {
  return storageGet(SETUP_TOKEN_KEY, 'session') ?? '';
}

// ── Auth API Calls ────────────────────────────────────────────────────────────

/** POST /auth/login */
/** POST /auth/login — step 1: email + password; a sign-in code is emailed (no session yet). */
export async function login(request: LoginRequest): Promise<LoginChallenge> {
  return apiClient.post<LoginChallenge>('/auth/login', request, { skipAuth: true });
}

/** POST /auth/login/verify — step 2: the emailed code; stores the session. */
export async function verifyLogin(loginToken: string, otp: string): Promise<AuthResponse> {
  const response = await apiClient.post<AuthResponse>('/auth/login/verify', { loginToken, otp }, { skipAuth: true });
  storeSession(response);
  return response;
}

/** POST /auth/login/resend — a new sign-in code (at most one per minute). */
export async function resendLoginCode(loginToken: string): Promise<MessageResponse> {
  return apiClient.post<MessageResponse>('/auth/login/resend', { loginToken }, { skipAuth: true });
}

/** POST /auth/signup — step 1: sends a verification code to the email address. */
export async function signup(request: SignupRequest): Promise<MessageResponse> {
  const response = await apiClient.post<MessageResponse>('/auth/signup', request, { skipAuth: true });
  setPendingEmail(request.email);
  return response;
}

/** POST /auth/otp/verify — step 2: a correct code allows choosing the password. */
export async function verifyOtp(request: OtpVerifyRequest): Promise<OtpVerifyResponse> {
  const response = await apiClient.post<OtpVerifyResponse>('/auth/otp/verify', request, { skipAuth: true });
  storageSet(SETUP_TOKEN_KEY, response.setupToken, 'session');
  return response;
}

/** POST /auth/signup/complete — step 3: sets the password; the new account is signed in. */
export async function completeSignup(request: CompleteSignupRequest): Promise<AuthResponse> {
  const response = await apiClient.post<AuthResponse>('/auth/signup/complete', request, { skipAuth: true });
  storeSession(response);
  setPendingEmail(null);
  storageRemove(SETUP_TOKEN_KEY, 'session');
  return response;
}

/** POST /auth/otp/resend */
export async function resendOtp(request: OtpResendRequest): Promise<MessageResponse> {
  return apiClient.post<MessageResponse>('/auth/otp/resend', request, { skipAuth: true });
}

/** POST /auth/password/forgot — step 1: emails a reset code (generic answer). */
export async function forgotPassword(email: string): Promise<MessageResponse> {
  return apiClient.post<MessageResponse>('/auth/password/forgot', { email }, { skipAuth: true });
}

/** POST /auth/password/verify — step 2: a correct code allows choosing a new password. */
export async function verifyPasswordReset(request: OtpVerifyRequest): Promise<PasswordResetVerifyResponse> {
  return apiClient.post<PasswordResetVerifyResponse>('/auth/password/verify', request, { skipAuth: true });
}

/** POST /auth/password/reset — step 3: sets the new password. */
export async function resetPassword(request: ResetPasswordRequest): Promise<MessageResponse> {
  return apiClient.post<MessageResponse>('/auth/password/reset', request, { skipAuth: true });
}

/** POST /auth/logout — always clears local tokens. */
export async function logout(): Promise<void> {
  try {
    await apiClient.post<MessageResponse>('/auth/logout', {});
  } catch {
    // Always clear local state even if the server call fails
  } finally {
    clearTokens();
  }
}

/** GET /auth/me */
export async function getCurrentUser(): Promise<User> {
  const user = await apiClient.get<User>('/auth/me');
  storeUser(user);
  return user;
}

/** POST /auth/profile/change — step 1: emails a code confirming the change. */
export async function requestProfileChange(request: ProfileChangeRequest): Promise<ProfileChangeStarted> {
  return apiClient.post<ProfileChangeStarted>('/auth/profile/change', request);
}

/** POST /auth/profile/confirm — step 2: the code applies the change; returns the updated profile. */
export async function confirmProfileChange(changeToken: string, otp: string): Promise<User> {
  const user = await apiClient.post<User>('/auth/profile/confirm', { changeToken, otp });
  storeUser(user);
  return user;
}

/** PUT /auth/profile — verify and update name / phone / email directly (no emailed code). */
export async function updateProfile(request: ProfileChangeRequest): Promise<User> {
  const user = await apiClient.put<User>('/auth/profile', request);
  storeUser(user);
  return user;
}

/** PUT /auth/me/preferences — attack alert emails on/off; returns the updated profile. */
export async function updatePreferences(emailAlerts: boolean): Promise<User> {
  const user = await apiClient.put<User>('/auth/me/preferences', { emailAlerts });
  storeUser(user);
  return user;
}

/** POST /auth/change-password — step 1: checks the passwords and emails a code to the registered address. */
export async function changePassword(request: ChangePasswordRequest): Promise<ProfileChangeStarted> {
  return apiClient.post<ProfileChangeStarted>('/auth/change-password', request);
}

/** POST /auth/change-password/confirm — step 2: the code sets the new password. */
export async function confirmPasswordChange(request: ChangePasswordConfirm): Promise<MessageResponse> {
  return apiClient.post<MessageResponse>('/auth/change-password/confirm', request);
}
