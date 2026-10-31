/**
 * SecureNet — Error Boundary
 *
 * Catches render errors anywhere below it so the app shows what went wrong
 * (and a way out) instead of an empty page.
 */

import { Component, type ErrorInfo, type ReactNode } from 'react';
import { storageRemove } from '../../utils/storage';
import styles from './ErrorBoundary.module.css';

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

const SESSION_KEYS = ['sn_access_token', 'sn_refresh_token', 'sn_user'];

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('[SecureNet] UI crashed:', error, info.componentStack);
  }

  private reload = (): void => {
    window.location.reload();
  };

  private resetSession = (): void => {
    SESSION_KEYS.forEach((key) => storageRemove(key));
    window.location.assign('/login');
  };

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <main className={styles.page} role="alert">
        <div className={styles.card}>
          <h1 className={styles.title}>Something went wrong</h1>
          <p className={styles.text}>
            The dashboard hit an unexpected error and could not be displayed.
            Reloading usually fixes it; if it keeps happening, sign in again.
          </p>
          <pre className={styles.detail}>{error.message || String(error)}</pre>
          <div className={styles.actions}>
            <button type="button" className={styles.primary} onClick={this.reload}>
              Reload page
            </button>
            <button type="button" className={styles.secondary} onClick={this.resetSession}>
              Sign out &amp; start fresh
            </button>
          </div>
        </div>
      </main>
    );
  }
}
