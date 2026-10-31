/**
 * SecureNet — Login Page
 */

import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthLayout } from '../components/auth/AuthLayout';
import { LoginForm } from '../components/auth/LoginForm';
import { useAuth } from '../contexts/AuthContext';
import styles from './LoginPage.module.css';

export function LoginPage() {
  const { isAuthenticated, sessionExpired } = useAuth();
  const navigate = useNavigate();

  // Redirect already-authenticated users away from login
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  return (
    <AuthLayout>
      {sessionExpired && (
        <div className={styles.notice} role="status">
          Your session has expired. Please sign in again.
        </div>
      )}
      <LoginForm />
    </AuthLayout>
  );
}
