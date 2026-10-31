/**
 * SecureNet — AlertPopups
 *
 * Pop-up cards (top-right) shown the moment the IDS detects an attack.
 * High-severity cards stay longest; every card links to the incident.
 */

import { AlertTriangle, ShieldAlert, ShieldCheck, ShieldX, X } from 'lucide-react';
import { useNotifications } from '../../contexts/NotificationContext';
import { guessOf, titleOf } from '../../utils/notifications';
import { formatTime } from '../../utils/format';
import styles from './AlertPopups.module.css';

export function AlertPopups() {
  const { popups, dismissPopup, dismissAllPopups, openEvent } = useNotifications();
  if (popups.length === 0) return null;

  return (
    <div className={styles.stack} role="region" aria-label="Security alerts" aria-live="assertive">
      {popups.map((alert) => {
        // Protection outcome notice (success / still-active) — its own card wording.
        if (alert.verdict === 'protection') {
          const ok = alert.success === true;
          const PIcon = ok ? ShieldCheck : ShieldX;
          return (
            <div key={alert.eventId} className={`${styles.card} ${styles[alert.severity]}`} role="alert">
              <div className={styles.icon} aria-hidden="true"><PIcon size={20} /></div>
              <div className={styles.body}>
                <div className={styles.header}>
                  <span className={styles.heading}>{ok ? 'Protection successful' : 'Protection — attack active'}</span>
                  <span className={styles.time}>{formatTime(alert.timestamp)}</span>
                </div>
                <p className={styles.title}>{alert.message}</p>
                <div className={styles.actions}>
                  <button type="button" className={styles.view} onClick={() => openEvent(alert.eventId)}>
                    View what SecureNet did
                  </button>
                  <button type="button" className={styles.dismissText} onClick={() => dismissPopup(alert.eventId)}>
                    Dismiss
                  </button>
                </div>
              </div>
              <button type="button" className={styles.close} onClick={() => dismissPopup(alert.eventId)}
                      aria-label="Dismiss alert"><X size={14} /></button>
            </div>
          );
        }
        const blocked = alert.actionTaken === 'blocked';
        const Icon = blocked ? ShieldX : alert.severity === 'high' ? ShieldAlert : AlertTriangle;
        return (
          <div key={alert.eventId} className={`${styles.card} ${styles[alert.severity]}`} role="alert">
            <div className={styles.icon} aria-hidden="true">
              <Icon size={20} />
            </div>
            <div className={styles.body}>
              <div className={styles.header}>
                <span className={styles.badge}>{alert.severity}</span>
                <span className={styles.heading}>Abnormal traffic</span>
                <span className={styles.time}>{formatTime(alert.timestamp)}</span>
              </div>
              <p className={styles.title}>{titleOf(alert)}</p>
              <p className={styles.flow}>Possible attack: {guessOf(alert)}</p>
              <p className={styles.flow}>
                {alert.sourceIp}:{alert.sourcePort} → {alert.destinationIp}:{alert.destinationPort}{' '}
                <span className={styles.proto}>{alert.protocol}</span>
              </p>
              <p className={styles.meta}>
                <span className={blocked ? styles.blocked : undefined}>
                  {blocked ? 'Source IP blocked' : alert.actionTaken}
                </span>
              </p>
              <div className={styles.actions}>
                <button type="button" className={styles.view} onClick={() => openEvent(alert.eventId)}>
                  View incident
                </button>
                <button type="button" className={styles.dismissText} onClick={() => dismissPopup(alert.eventId)}>
                  Dismiss
                </button>
              </div>
            </div>
            <button
              type="button"
              className={styles.close}
              onClick={() => dismissPopup(alert.eventId)}
              aria-label="Dismiss alert"
            >
              <X size={14} />
            </button>
          </div>
        );
      })}
      {popups.length > 1 && (
        <button type="button" className={styles.dismissAll} onClick={dismissAllPopups}>
          Dismiss all ({popups.length})
        </button>
      )}
    </div>
  );
}
