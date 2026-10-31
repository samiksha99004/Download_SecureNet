/**
 * SecureNet — SettingsLayout
 *
 * Tab bar + content shell reused by SettingsPage.
 */

import type { ReactNode } from 'react';
import { cn } from '../../utils/cn';
import styles from './SettingsLayout.module.css';

export interface SettingsTab {
  id: string;
  label: string;
  icon: ReactNode;
}

interface SettingsLayoutProps {
  tabs: SettingsTab[];
  activeTab: string;
  onTabChange: (id: string) => void;
  children: ReactNode;
}

export function SettingsLayout({
  tabs,
  activeTab,
  onTabChange,
  children,
}: SettingsLayoutProps) {
  return (
    <div className={styles.container}>
      {/* Tab bar */}
      <nav className={styles.tabBar} aria-label="Settings sections" role="tablist">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            role="tab"
            aria-selected={activeTab === tab.id}
            aria-controls={`tab-panel-${tab.id}`}
            id={`tab-${tab.id}`}
            className={cn(styles.tabBtn, activeTab === tab.id && styles.tabBtnActive)}
            onClick={() => onTabChange(tab.id)}
          >
            <span className={styles.tabIcon} aria-hidden="true">{tab.icon}</span>
            <span className={styles.tabLabel}>{tab.label}</span>
          </button>
        ))}
      </nav>

      {/* Content */}
      <div
        className={styles.panel}
        role="tabpanel"
        id={`tab-panel-${activeTab}`}
        aria-labelledby={`tab-${activeTab}`}
      >
        {children}
      </div>
    </div>
  );
}
