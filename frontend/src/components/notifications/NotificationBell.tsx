/**
 * SecureNet — NotificationBell
 *
 * Top-bar bell with an unread badge and a dropdown feed of recent alerts,
 * plus quick toggles for pop-ups, sound and desktop notifications.
 */

import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, BellRing, CheckCheck, Monitor, Volume2, VolumeX, MessageSquareWarning } from 'lucide-react';
import { useNotifications } from '../../contexts/NotificationContext';
import { guessOf, titleOf } from '../../utils/notifications';
import { formatTimestamp } from '../../utils/format';
import styles from './NotificationBell.module.css';
import { storageSet } from '../../utils/storage';

export function NotificationBell() {
  const {
    items,
    unreadCount,
    isUnread,
    markAllRead,
    openEvent,
    prefs,
    setPrefs,
    desktopPermission,
    enableDesktopNotifications,
  } = useNotifications();
  const [open, setOpen] = useState(false);
  // Alerts that were unread when the panel was opened stay highlighted while it is open
  const [highlighted, setHighlighted] = useState<Set<string>>(new Set());

  function togglePanel() {
    if (!open) {
      setHighlighted(new Set(items.filter(isUnread).map((i) => i.eventId)));
      markAllRead();
    }
    setOpen((v) => !v);
  }
  const wrapperRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  // Close on outside click / Escape
  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', onClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const BellIcon = unreadCount > 0 ? BellRing : Bell;

  return (
    <div className={styles.wrapper} ref={wrapperRef}>
      <button
        type="button"
        className={`${styles.bell} ${unreadCount > 0 ? styles.bellActive : ''}`}
        onClick={togglePanel}
        aria-label={`Notifications${unreadCount ? ` (${unreadCount} unread)` : ''}`}
        aria-haspopup="dialog"
        aria-expanded={open}
      >
        <BellIcon size={18} />
        {unreadCount > 0 && (
          <span className={styles.badge} aria-hidden="true">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className={styles.panel} role="dialog" aria-label="Notifications">
          <div className={styles.panelHeader}>
            <span className={styles.panelTitle}>Notifications</span>
            <button
              type="button"
              className={styles.linkButton}
              onClick={() => {
                markAllRead();
                setHighlighted(new Set());
              }}
              disabled={unreadCount === 0 && highlighted.size === 0}
            >
              <CheckCheck size={14} aria-hidden="true" /> Mark all read
            </button>
          </div>

          <div className={styles.toggles}>
            <button
              type="button"
              className={`${styles.chip} ${prefs.popups ? styles.chipOn : ''}`}
              onClick={() => setPrefs({ popups: !prefs.popups })}
              aria-pressed={prefs.popups}
            >
              <MessageSquareWarning size={13} aria-hidden="true" /> Pop-ups
            </button>
            <button
              type="button"
              className={`${styles.chip} ${prefs.sound ? styles.chipOn : ''}`}
              onClick={() => setPrefs({ sound: !prefs.sound })}
              aria-pressed={prefs.sound}
            >
              {prefs.sound ? <Volume2 size={13} aria-hidden="true" /> : <VolumeX size={13} aria-hidden="true" />} Sound
            </button>
            {desktopPermission === 'granted' ? (
              <span className={`${styles.chip} ${styles.chipOn}`}>
                <Monitor size={13} aria-hidden="true" /> Desktop on
              </span>
            ) : desktopPermission === 'default' ? (
              <button type="button" className={styles.chip} onClick={() => void enableDesktopNotifications()}>
                <Monitor size={13} aria-hidden="true" /> Enable desktop
              </button>
            ) : (
              <span className={styles.chip} title="Allow notifications for this site in your browser settings">
                <Monitor size={13} aria-hidden="true" /> Desktop blocked
              </span>
            )}
          </div>

          {items.length === 0 ? (
            <p className={styles.empty}>No alerts yet. You will be notified here when an attack is detected.</p>
          ) : (
            <ul className={styles.list}>
              {items.slice(0, 20).map((item) => (
                <li key={item.eventId}>
                  <button
                    type="button"
                    className={`${styles.item} ${highlighted.has(item.eventId) || isUnread(item) ? styles.unread : ''}`}
                    onClick={() => {
                      setOpen(false);
                      openEvent(item.eventId);
                    }}
                  >
                    <span className={`${styles.dot} ${styles[item.severity]}`} aria-hidden="true" />
                    <span className={styles.itemBody}>
                      <span className={styles.itemTitle}>
                        {titleOf(item)}
                        {item.actionTaken === 'blocked' && <span className={styles.blockedTag}>blocked</span>}
                      </span>
                      <span className={styles.itemMeta}>
                        Possible attack: {guessOf(item)} · {item.severity.toUpperCase()} · {item.sourceIp} → {item.destinationIp}:{item.destinationPort}
                      </span>
                      <span className={styles.itemTime}>{formatTimestamp(item.timestamp)}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}

          <div className={styles.panelFooter}>
            <button
              type="button"
              className={styles.linkButton}
              onClick={() => {
                setOpen(false);
                navigate('/history');
              }}
            >
              View all events
            </button>
            <button
              type="button"
              className={styles.linkButton}
              onClick={() => {
                setOpen(false);
                storageSet('sn_settings_tab', JSON.stringify('preferences'));
                navigate('/settings');
              }}
            >
              Notification settings
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
