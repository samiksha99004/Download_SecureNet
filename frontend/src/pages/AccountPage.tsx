/**
 * SecureNet — Account Page
 *
 * Displays the authenticated user's profile and account metadata, lets them
 * edit their name / phone / email (each change confirmed by an emailed code)
 * and change their password.
 *
 * All data comes from AuthContext — no fabricated values.
 * Password change is hidden for Google OAuth users.
 */

import { MainLayout } from '../components/layout/MainLayout';
import { PageHeader } from '../components/common/PageHeader';
import { ProfileCard } from '../components/account/ProfileCard';
import { AccountInfoCard } from '../components/account/AccountInfoCard';
import { ChangePasswordCard } from '../components/account/ChangePasswordCard';
import { EditProfileCard } from '../components/account/EditProfileCard';
import { useAuth } from '../contexts/AuthContext';
import { LoadingState } from '../components/common/LoadingState';
import styles from './AccountPage.module.css';

export function AccountPage() {
  const { user, status } = useAuth();

  if (status === 'loading' || status === 'idle') {
    return (
      <MainLayout title="Account">
        <LoadingState message="Loading account…" />
      </MainLayout>
    );
  }

  if (!user) {
    return (
      <MainLayout title="Account">
        <div className={styles.page}>
          <PageHeader title="Account" />
          <p className={styles.unavailable}>Account information not available.</p>
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout title="Account">
      <div className={styles.page}>
        <PageHeader
          title="Account"
          description="Your profile, your details and your password."
        />

        {/* Profile summary */}
        <ProfileCard user={user} />

        {/* Two-column grid on wide screens */}
        <div className={styles.grid}>
          <EditProfileCard key={`${user.email}|${user.fullName}|${user.phoneNumber ?? ''}`} user={user} />
          <ChangePasswordCard user={user} />
          <AccountInfoCard user={user} />
        </div>
      </div>
    </MainLayout>
  );
}
