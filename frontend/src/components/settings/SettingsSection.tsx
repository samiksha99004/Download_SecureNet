/**
 * SecureNet — SettingsSection
 *
 * Reusable card-like section wrapper used within settings tabs.
 */

import type { ReactNode } from 'react';
import styles from './SettingsSection.module.css';

interface SettingsSectionProps {
  title: string;
  description?: string;
  children: ReactNode;
}

export function SettingsSection({ title, description, children }: SettingsSectionProps) {
  return (
    <section className={styles.section}>
      <div className={styles.heading}>
        <h3 className={styles.title}>{title}</h3>
        {description && <p className={styles.description}>{description}</p>}
      </div>
      <div className={styles.body}>{children}</div>
    </section>
  );
}
