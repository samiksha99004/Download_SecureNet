/**
 * SecureNet — AccountInfoCard
 *
 * Read-only display of account metadata: ID, auth provider,
 * role, status, created date, last login.
 * All values come from the authenticated User object.
 */

import type { User } from '../../types/auth.types';
import { Card } from '../common/Card';
import { formatTimestamp } from '../../utils/format';
import styles from './AccountInfoCard.module.css';
import { roleLabel } from '../../utils/roles';

const PROVIDER_LABELS: Record<string, string> = {
  local:  'Email & Password',
  google: 'Google OAuth',
};

const STATUS_LABELS: Record<string, string> = {
  active:               'Active',
  suspended:            'Suspended',
  pending_verification: 'Pending Verification',
};

interface InfoRowProps {
  label: string;
  value: string;
  mono?: boolean;
}

function InfoRow({ label, value, mono }: InfoRowProps) {
  return (
    <div className={styles.row}>
      <dt className={styles.label}>{label}</dt>
      <dd className={mono ? styles.valueMono : styles.value}>{value}</dd>
    </div>
  );
}

interface AccountInfoCardProps {
  user: User;
}

export function AccountInfoCard({ user }: AccountInfoCardProps) {
  return (
    <Card padding="lg">
      <h3 className={styles.heading}>Account Information</h3>
      <dl className={styles.list}>
        <InfoRow label="User ID"             value={user.id}                                      mono />
        <InfoRow label="Full Name"           value={user.fullName} />
        <InfoRow label="Email"               value={user.email}                                   mono />
        <InfoRow label="Role"                value={roleLabel(user.role)} />
        <InfoRow label="Account Status"      value={STATUS_LABELS[user.accountStatus] ?? user.accountStatus} />
        <InfoRow label="Authentication"      value={PROVIDER_LABELS[user.authProvider] ?? user.authProvider} />
        <InfoRow label="Account Created"     value={formatTimestamp(user.createdAt)} />
        <InfoRow
          label="Last Login"
          value={user.lastLoginAt ? formatTimestamp(user.lastLoginAt) : 'Not available'}
        />
      </dl>
    </Card>
  );
}
