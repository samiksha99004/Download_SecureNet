/**
 * SecureNet — AuthLayout
 *
 * Shared two-column layout used by Login, Signup, and OTP pages.
 * Left panel: branding + tagline + "Visit our website" — the website the admin
 * set in Settings → System → Contact details (fallback: VITE_WEBSITE_URL).
 * Right panel: the form content (children).
 */

import { useEffect, useState, type ReactNode } from 'react';
import { ShieldCheck } from 'lucide-react';
import { getContactInfo } from '../../services/supportService';
import styles from './AuthLayout.module.css';

const ENV_WEBSITE_URL: string = import.meta.env.VITE_WEBSITE_URL ?? '';

/** Website link: the admin's Contact details first, then the build-time fallback. */
function useWebsiteUrl(): string {
  const [url, setUrl] = useState(ENV_WEBSITE_URL);
  useEffect(() => {
    let active = true;
    getContactInfo()
      .then((info) => { if (active && info.website) setUrl(info.website); })
      .catch(() => { /* link simply stays as it is */ });
    return () => { active = false; };
  }, []);
  return url;
}

interface AuthLayoutProps {
  children: ReactNode;
}

export function AuthLayout({ children }: AuthLayoutProps) {
  const websiteUrl = useWebsiteUrl();
  return (
    <div className={styles.root}>
      {/* ── Left branding panel ── */}
      <aside className={styles.brand}>
        <div className={styles.brandInner} aria-hidden="true">
          <div className={styles.logo}>
            <ShieldCheck size={36} strokeWidth={1.75} />
            <span className={styles.logoText}>SecureNet</span>
          </div>
          <p className={styles.tagline}>
            Network security monitoring and behavioural intrusion detection.
          </p>
          <ul className={styles.featureList}>
            <li>Watches your network while the IDS is on</li>
            <li>Instant alerts when an attack is detected</li>
            <li>Email alerts with the incident report</li>
            <li>Daily reports you can download</li>
          </ul>
        </div>
        <p className={styles.brandFooter}>
          {websiteUrl ? (
            <a href={websiteUrl} target="_blank" rel="noopener noreferrer" className={styles.websiteLink}>
              Visit our website
            </a>
          ) : (
            <span className={styles.websiteLink} title="Website link coming soon">
              Visit our website
            </span>
          )}
        </p>
      </aside>

      {/* ── Right form panel ── */}
      <main className={styles.formPanel}>
        <div className={styles.formInner}>{children}</div>
      </main>
    </div>
  );
}
