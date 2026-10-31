/**
 * SecureNet — ProfileCard
 *
 * Displays the user's avatar (initials), full name, email, role, and
 * account status. All data comes from AuthContext — never fabricated.
 */

import type { User } from '../../types/auth.types';
import { Card } from '../common/Card';
import styles from './ProfileCard.module.css';
import { roleLabel } from '../../utils/roles';

const STATUS_LABELS: Record<string, string> = {
  active:                'Active',
  suspended:             'Suspended',
  pending_verification:  'Pending Verification',
};

const STATUS_CLASS: Record<string, string> = {
  active:               'statusActive',
  suspended:            'statusSuspended',
  pending_verification: 'statusPending',
};

function Initials({ name }: { name: string }) {
  const parts = name.trim().split(' ');
  const letters = parts.length >= 2
    ? (parts[0][0] + parts[parts.length - 1][0]).toUpperCase()
    : name.slice(0, 2).toUpperCase();
  return <span aria-hidden="true">{letters}</span>;
}

interface ProfileCardProps {
  user: User;
}

export function ProfileCard({ user }: ProfileCardProps) {
  return (
    <Card padding="lg" className={styles.card}>
      {/* Avatar */}
      <div className={styles.avatarWrap} aria-hidden="true">
        {user.avatarUrl ? (
          <img src={user.avatarUrl} alt="" className={styles.avatarImg} />
        ) : (
          <div className={styles.avatarInitials}>
            <Initials name={user.fullName} />
          </div>
        )}
      </div>

      {/* Info */}
      <div className={styles.info}>
        <h3 className={styles.name}>{user.fullName}</h3>
        <p className={styles.email}>{user.email}</p>
        {user.phoneNumber && <p className={styles.email}>{user.phoneNumber}</p>}

        <div className={styles.badges}>
          <span className={styles.roleBadge}>
            {roleLabel(user.role)}
          </span>
          <span className={`${styles.statusBadge} ${styles[STATUS_CLASS[user.accountStatus] ?? '']}`}>
            {STATUS_LABELS[user.accountStatus] ?? user.accountStatus}
          </span>
        </div>
      </div>
    </Card>
  );
}
