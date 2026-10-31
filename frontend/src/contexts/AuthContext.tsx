/**
 * SecureNet — Authentication Context
 *
 * Provides authentication state and actions throughout the app.
 * Components use the useAuth() hook — never import the context directly.
 *
 *   AuthProvider (this file) → useAuth() → authService.ts → backend
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useReducer,
  type ReactNode,
} from 'react';
import * as authService from '../services/authService';
import { SESSION_EXPIRED_EVENT } from '../services/apiClient';
import type { User, AuthState, LoginChallenge, LoginRequest, SignupRequest } from '../types/auth.types';
import type { MessageResponse } from '../types/api.types';
import { isAdminRole } from '../utils/roles';

// ── State & Reducer ───────────────────────────────────────────────────────────

interface State extends AuthState {
  sessionExpired: boolean;
}

type AuthAction =
  | { type: 'LOADING' }
  | { type: 'AUTHENTICATED'; user: User }
  | { type: 'UNAUTHENTICATED'; expired?: boolean }
  | { type: 'ERROR'; error: string }
  | { type: 'CLEAR_ERROR' };

function authReducer(state: State, action: AuthAction): State {
  switch (action.type) {
    case 'LOADING':
      return { ...state, status: 'loading', error: null };
    case 'AUTHENTICATED':
      return { status: 'authenticated', user: action.user, error: null, sessionExpired: false };
    case 'UNAUTHENTICATED':
      return { status: 'unauthenticated', user: null, error: null, sessionExpired: !!action.expired };
    case 'ERROR':
      // A failed login attempt leaves the user signed out (not in a limbo state)
      return { ...state, status: 'unauthenticated', user: null, error: action.error };
    case 'CLEAR_ERROR':
      return { ...state, error: null, sessionExpired: false };
    default:
      return state;
  }
}

function initialState(): State {
  const user = authService.getStoredUser();
  const token = authService.getAccessToken();
  // Half a session (token without a usable profile, or vice versa) is discarded
  if (!user || !token) authService.clearTokens();
  return user && token
    ? { status: 'authenticated', user, error: null, sessionExpired: false }
    : { status: 'unauthenticated', user: null, error: null, sessionExpired: false };
}

// ── Context Shape ─────────────────────────────────────────────────────────────

interface AuthContextValue extends State {
  /** Step 1: email + password → a sign-in code is emailed (still signed out). */
  login: (request: LoginRequest) => Promise<LoginChallenge>;
  /** Step 2: the emailed code → signed in. */
  verifyLogin: (loginToken: string, otp: string) => Promise<void>;
  signup: (request: SignupRequest) => Promise<MessageResponse>;
  /** Sign in with a user already authenticated elsewhere (e.g. OTP verification). */
  completeLogin: (user: User) => void;
  logout: () => Promise<void>;
  clearError: () => void;
  isAuthenticated: boolean;
  /** only the Admin may change IDS settings, the model and incidents */
  isAdmin: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// ── Provider ──────────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(authReducer, undefined, initialState);

  // Refresh the stored profile (role may have changed) and react to expiry
  useEffect(() => {
    const onExpired = () => dispatch({ type: 'UNAUTHENTICATED', expired: true });
    window.addEventListener(SESSION_EXPIRED_EVENT, onExpired);
    if (authService.getAccessToken()) {
      authService.getCurrentUser()
        .then((user) => dispatch({ type: 'AUTHENTICATED', user }))
        .catch(() => { /* network errors keep the cached session; 401 fires the event */ });
    }
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, onExpired);
  }, []);

  const login = useCallback(async (request: LoginRequest): Promise<LoginChallenge> => {
    dispatch({ type: 'LOADING' });
    try {
      const challenge = await authService.login(request);
      dispatch({ type: 'UNAUTHENTICATED' }); // not signed in until the emailed code is entered
      return challenge;
    } catch (err) {
      dispatch({ type: 'ERROR', error: err instanceof Error ? err.message : 'Login failed.' });
      throw err;
    }
  }, []);

  const verifyLogin = useCallback(async (loginToken: string, otp: string): Promise<void> => {
    const response = await authService.verifyLogin(loginToken, otp);
    dispatch({ type: 'AUTHENTICATED', user: response.user });
  }, []);

  const signup = useCallback(async (request: SignupRequest): Promise<MessageResponse> => {
    dispatch({ type: 'LOADING' });
    try {
      const response = await authService.signup(request);
      dispatch({ type: 'UNAUTHENTICATED' }); // Not yet authenticated until OTP
      return response;
    } catch (err) {
      dispatch({ type: 'ERROR', error: err instanceof Error ? err.message : 'Signup failed.' });
      throw err;
    }
  }, []);

  const completeLogin = useCallback((user: User) => {
    dispatch({ type: 'AUTHENTICATED', user });
  }, []);

  const logout = useCallback(async (): Promise<void> => {
    try {
      await authService.logout();
    } finally {
      dispatch({ type: 'UNAUTHENTICATED' });
    }
  }, []);

  const clearError = useCallback((): void => {
    dispatch({ type: 'CLEAR_ERROR' });
  }, []);

  const value: AuthContextValue = {
    ...state,
    login,
    verifyLogin,
    signup,
    completeLogin,
    logout,
    clearError,
    isAuthenticated: state.status === 'authenticated',
    isAdmin: isAdminRole(state.user?.role),
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// ── Hook ──────────────────────────────────────────────────────────────────────

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
