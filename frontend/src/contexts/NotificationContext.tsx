/**
 * SecureNet — Notification Context
 *
 * Central notification system for signed-in users. For every attack the IDS
 * detects (WebSocket `alert` message) it:
 *   1. shows an in-app pop-up card (AlertPopups),
 *   2. adds it to the notification bell feed with an unread badge,
 *   3. shows a desktop (OS) notification when the SecureNet tab is not focused,
 *   4. plays a short alert sound (optional).
 * Alert e-mails are sent by the backend (services/notifier.py).
 *
 * The feed is loaded from GET /api/notifications on sign-in; "read" state is
 * kept per user in localStorage.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from './AuthContext';
import { useWebSocketMessage } from '../hooks/useLiveMonitoring';
import { wsService } from '../services/websocketService';
import { getNotifications } from '../services/notificationsService';
import { storageGet, storageGetJson, storageSet } from '../utils/storage';
import {
  desktopPermission,
  playAlertSound,
  requestDesktopNotifications,
  type DesktopPermission,
} from '../utils/alertChannels';
import type { NotificationItem } from '../types/notifications.types';
import type { WebSocketMessage } from '../types/websocket.types';

const MAX_ITEMS = 50;
const MAX_POPUPS = 4;
const POPUP_TIMEOUT_MS: Record<string, number> = { high: 20_000, medium: 12_000, low: 8_000 };
const PREFS_KEY = 'sn_notification_prefs';

interface NotificationPrefs {
  popups: boolean;
  sound: boolean;
  /** desktop (OS) notifications while SecureNet is in the background — user's own switch */
  desktop: boolean;
}

interface NotificationContextValue {
  items: NotificationItem[];
  unreadCount: number;
  isUnread: (item: NotificationItem) => boolean;
  popups: NotificationItem[];
  prefs: NotificationPrefs;
  desktopPermission: DesktopPermission;
  markAllRead: () => void;
  dismissPopup: (eventId: string) => void;
  dismissAllPopups: () => void;
  openEvent: (eventId: string) => void;
  setPrefs: (prefs: Partial<NotificationPrefs>) => void;
  enableDesktopNotifications: () => Promise<void>;
  reload: () => void;
}

const NotificationContext = createContext<NotificationContextValue | null>(null);

function loadPrefs(): NotificationPrefs {
  const stored = storageGetJson<Partial<NotificationPrefs> | null>(PREFS_KEY, null);
  return { popups: true, sound: true, desktop: true, ...(stored && typeof stored === 'object' ? stored : {}) };
}

export function NotificationProvider({ children }: { children: ReactNode }) {
  const { isAuthenticated, user } = useAuth();
  const navigate = useNavigate();

  const [items, setItems] = useState<NotificationItem[]>([]);
  const [popups, setPopups] = useState<NotificationItem[]>([]);
  const [lastReadAt, setLastReadAt] = useState<string | null>(null);
  const [prefs, setPrefsState] = useState<NotificationPrefs>(loadPrefs);
  const [permission, setPermission] = useState<DesktopPermission>(desktopPermission);
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());

  const readKey = user ? `sn_notifications_read_${user.id}` : null;

  // ── Load feed + (re)connect the live socket whenever the session changes ──
  const reload = useCallback(() => {
    if (!isAuthenticated) return;
    getNotifications(MAX_ITEMS)
      .then((feed) => {
        setItems(feed);
        if (readKey) {
          const stored = storageGet(readKey);
          if (stored) {
            setLastReadAt(stored);
          } else {
            // First visit: existing history counts as read
            const newest = feed[0]?.timestamp ?? new Date().toISOString();
            storageSet(readKey, newest);
            setLastReadAt(newest);
          }
        }
      })
      .catch(() => { /* feed is best-effort; live alerts still arrive */ });
  }, [isAuthenticated, readKey]);

  useEffect(() => {
    if (isAuthenticated) {
      reload();
      wsService.reconnect(); // attach the (new) access token
    } else {
      wsService.disconnect();
    }
  }, [isAuthenticated, reload]);

  useEffect(() => {
    const pending = timers.current;
    return () => pending.forEach(clearTimeout);
  }, []);

  // ── Popups ──────────────────────────────────────────────────────────────────
  const dismissPopup = useCallback((eventId: string) => {
    setPopups((prev) => prev.filter((p) => p.eventId !== eventId));
    const timer = timers.current.get(eventId);
    if (timer) clearTimeout(timer);
    timers.current.delete(eventId);
  }, []);

  const dismissAllPopups = useCallback(() => {
    timers.current.forEach(clearTimeout);
    timers.current.clear();
    setPopups([]);
  }, []);

  const openEvent = useCallback(
    (eventId: string) => {
      dismissPopup(eventId);
      navigate(`/history?event=${encodeURIComponent(eventId)}`);
    },
    [dismissPopup, navigate]
  );

  // ── Live alerts ─────────────────────────────────────────────────────────────
  const prefsRef = useRef(prefs);
  useEffect(() => {
    prefsRef.current = prefs;
  }, [prefs]);

  const onAlert = useCallback(
    (message: WebSocketMessage<NotificationItem>) => {
      const alert = message.payload;
      setItems((prev) => [alert, ...prev.filter((i) => i.eventId !== alert.eventId)].slice(0, MAX_ITEMS));

      const { popups: popupsOn, sound } = prefsRef.current;
      // Only the abnormal-state scheduler's alerts (desktopPop, every 3 min) pop an in-app card and
      // play a sound; per-flow alerts just update the feed+bell silently (no flood). The OS desktop
      // toast is sent by the BACKEND (app/utils/desktop.py), so it works even when SecureNet is closed.
      if (popupsOn && alert.desktopPop) {
        setPopups((prev) => [alert, ...prev].slice(0, MAX_POPUPS));
        const timer = setTimeout(() => dismissPopup(alert.eventId), POPUP_TIMEOUT_MS[alert.severity] ?? 10_000);
        timers.current.set(alert.eventId, timer);
      }
      if (sound && alert.desktopPop && alert.severity !== 'low') playAlertSound(alert.severity);
    },
    [dismissPopup, openEvent]
  );
  useWebSocketMessage<NotificationItem>('alert', onAlert);

  // ── Read state ──────────────────────────────────────────────────────────────
  const isUnread = useCallback(
    (item: NotificationItem) => lastReadAt !== null && Date.parse(item.timestamp) > Date.parse(lastReadAt),
    [lastReadAt]
  );
  const unreadCount = useMemo(() => items.filter(isUnread).length, [items, isUnread]);

  const markAllRead = useCallback(() => {
    const newest = items[0]?.timestamp ?? new Date().toISOString();
    if (readKey) storageSet(readKey, newest);
    setLastReadAt(newest);
  }, [items, readKey]);

  const setPrefs = useCallback((update: Partial<NotificationPrefs>) => {
    setPrefsState((prev) => {
      const next = { ...prev, ...update };
      try {
        storageSet(PREFS_KEY, JSON.stringify(next));
      } catch {
        /* storage unavailable */
      }
      return next;
    });
  }, []);

  const enableDesktopNotifications = useCallback(async () => {
    const result = await requestDesktopNotifications();
    setPermission(result);
    setPrefs({ desktop: result === 'granted' });
  }, [setPrefs]);

  // Signed-out users see nothing (stale state is replaced on the next sign-in)
  const value: NotificationContextValue = {
    items: isAuthenticated ? items : [],
    unreadCount: isAuthenticated ? unreadCount : 0,
    isUnread,
    popups: isAuthenticated ? popups : [],
    prefs,
    desktopPermission: permission,
    markAllRead,
    dismissPopup,
    dismissAllPopups,
    openEvent,
    setPrefs,
    enableDesktopNotifications,
    reload,
  };

  return <NotificationContext.Provider value={value}>{children}</NotificationContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useNotifications(): NotificationContextValue {
  const ctx = useContext(NotificationContext);
  if (!ctx) throw new Error('useNotifications must be used within a NotificationProvider');
  return ctx;
}
