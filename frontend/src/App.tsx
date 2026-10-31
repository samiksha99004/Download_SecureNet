/**
 * SecureNet — Application Root
 */

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import { ToastProvider } from './components/common/Toast';
import { ProtectedRoute } from './components/auth/ProtectedRoute';
import { NotificationProvider } from './contexts/NotificationContext';

import { LoginPage }           from './pages/LoginPage';
import { SignupPage }          from './pages/SignupPage';
import { OtpVerificationPage } from './pages/OtpVerificationPage';
import { CreatePasswordPage }  from './pages/CreatePasswordPage';
import { ForgotPasswordPage }  from './pages/ForgotPasswordPage';
import { DashboardPage }       from './pages/DashboardPage';
import { HistoryPage }         from './pages/HistoryPage';
import { ReportsPage }         from './pages/ReportsPage';
import { SettingsPage }        from './pages/SettingsPage';
import { AccountPage }         from './pages/AccountPage';
import { SupportPage }         from './pages/SupportPage';
import { NotFoundPage }        from './pages/NotFoundPage';

export default function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <BrowserRouter>
          <NotificationProvider>
            <Routes>
              {/* ── Public ── */}
              <Route path="/login"      element={<LoginPage />} />
              <Route path="/signup"     element={<SignupPage />} />
              <Route path="/otp-verify" element={<OtpVerificationPage />} />
              <Route path="/create-password" element={<CreatePasswordPage />} />
              <Route path="/forgot-password" element={<ForgotPasswordPage />} />

              {/* ── Protected ── */}
              <Route element={<ProtectedRoute />}>
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/history"   element={<HistoryPage />} />
                <Route path="/reports"   element={<ReportsPage />} />
                <Route path="/settings"  element={<SettingsPage />} />
                <Route path="/account"   element={<AccountPage />} />
                <Route path="/support"   element={<SupportPage />} />
              </Route>

              <Route path="/"  element={<Navigate to="/dashboard" replace />} />
              <Route path="*"  element={<NotFoundPage />} />
            </Routes>
          </NotificationProvider>
        </BrowserRouter>
      </ToastProvider>
    </AuthProvider>
  );
}
