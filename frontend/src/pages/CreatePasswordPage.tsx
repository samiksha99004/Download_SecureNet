/**
 * SecureNet — Create Password Page (registration step 3)
 */

import { AuthLayout } from '../components/auth/AuthLayout';
import { CreatePasswordForm } from '../components/auth/CreatePasswordForm';

export function CreatePasswordPage() {
  return (
    <AuthLayout>
      <CreatePasswordForm />
    </AuthLayout>
  );
}
