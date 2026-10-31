/**
 * SecureNet — Toast notification system
 *
 * Simple toast with auto-dismiss, variants, and a context-based API.
 *
 * Usage:
 *   const { showToast } = useToast();
 *   showToast({ message: 'Saved', variant: 'success' });
 */

import {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { X, CheckCircle, AlertTriangle, Info, XCircle } from 'lucide-react';
import { cn } from '../../utils/cn';
import styles from './Toast.module.css';

// ── Types ─────────────────────────────────────────────────────────────────────

export type ToastVariant = 'success' | 'error' | 'warning' | 'info';

interface ToastItem {
  id: string;
  message: string;
  variant: ToastVariant;
}

interface ToastContextValue {
  showToast: (opts: { message: string; variant?: ToastVariant }) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const ICONS: Record<ToastVariant, ReactNode> = {
  success: <CheckCircle   size={16} />,
  error:   <XCircle       size={16} />,
  warning: <AlertTriangle size={16} />,
  info:    <Info          size={16} />,
};

// ── Provider ──────────────────────────────────────────────────────────────────

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextId = useRef(0);

  const showToast = useCallback(
    ({ message, variant = 'info' }: { message: string; variant?: ToastVariant }) => {
      const id = String(++nextId.current);
      setToasts((prev) => [...prev, { id, message, variant }]);
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 4000);
    },
    []
  );

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      {/* Toast container */}
      <div
        className={styles.container}
        aria-live="polite"
        aria-label="Notifications"
        role="region"
      >
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={cn(styles.toast, styles[toast.variant])}
            role="alert"
          >
            <span className={styles.toastIcon} aria-hidden="true">
              {ICONS[toast.variant]}
            </span>
            <span className={styles.toastMessage}>{toast.message}</span>
            <button
              className={styles.toastClose}
              onClick={() => dismiss(toast.id)}
              aria-label="Dismiss notification"
            >
              <X size={13} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
}
