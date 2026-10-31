/**
 * SecureNet — IdsOffNote
 *
 * Shown inside dashboard cards while the IDS is OFF: the dashboard shows no
 * live values then. Past events stay available in History and Reports.
 */

import { Link } from 'react-router-dom';
import { PowerOff } from 'lucide-react';
import { EmptyState } from '../common/EmptyState';
import styles from './IdsOffNote.module.css';

export function IdsOffNote({ what = 'values' }: { what?: string }) {
  return (
    <EmptyState
      icon={<PowerOff size={20} />}
      title="IDS is off"
      description={`No live ${what} while the IDS is off. Press ON above to start monitoring.`}
      action={
        <span className={styles.links}>
          Past events: <Link to="/history" className={styles.link}>History</Link>
          {' · '}
          <Link to="/reports" className={styles.link}>Reports</Link>
        </span>
      }
    />
  );
}
