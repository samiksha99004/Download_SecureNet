/**
 * SecureNet — ProtectedRoute
 *
 * Wraps protected pages. Redirects unauthenticated users to /login.
 * Renders a loading state while the auth status is being determined.
 */

import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { LoadingState } from '../common/LoadingState';

export function ProtectedRoute() {
  const { status } = useAuth();
  const location = useLocation();

  // Auth status is being initialised (checking localStorage)
  if (status === 'idle' || status === 'loading') {
    return <LoadingState message="Verifying session…" />;
  }

  // Not authenticated — redirect to login, preserving the intended destination
  if (status === 'unauthenticated' || status === 'error') {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Authenticated — render the child route
  return <Outlet />;
}
