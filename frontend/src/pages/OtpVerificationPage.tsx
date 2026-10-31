/**
 * SecureNet — OTP Verification Page
 */

import { AuthLayout } from '../components/auth/AuthLayout';
import { OtpForm } from '../components/auth/OtpForm';

export function OtpVerificationPage() {
  return (
    <AuthLayout>
      <OtpForm />
    </AuthLayout>
  );
}
