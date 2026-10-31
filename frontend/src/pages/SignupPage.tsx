/**
 * SecureNet — Signup Page
 */

import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthLayout } from '../components/auth/AuthLayout';
import { SignupForm } from '../components/auth/SignupForm';
import { useAuth } from '../contexts/AuthContext';

export function SignupPage() {
  const { isAuthenticated, status } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (status === 'authenticated' && isAuthenticated) {
      navigate('/dashboard', { replace: true });
    }
  }, [isAuthenticated, status, navigate]);

  return (
    <AuthLayout>
      <SignupForm />
    </AuthLayout>
  );
}
