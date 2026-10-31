/**
 * SecureNet — MainLayout
 *
 * Wraps all protected pages.
 *
 * Structure:
 *   ┌─────────────────────────────────────┐
 *   │  Sidebar │  TopBar                  │
 *   │          ├─────────────────────────┤
 *   │          │  <children>             │
 *   └──────────┴─────────────────────────┘
 *
 * Usage in page components:
 *   <MainLayout title="Dashboard">
 *     <DashboardContent />
 *   </MainLayout>
 */

import { type ReactNode, useState } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { useLocalStorage } from '../../hooks/useLocalStorage';
import { AlertPopups } from '../notifications/AlertPopups';
import styles from './MainLayout.module.css';

interface MainLayoutProps {
  title: string;
  /** show "Good morning / afternoon / evening, <name>" in the top bar */
  greet?: boolean;
  children: ReactNode;
}

export function MainLayout({ title, greet = false, children }: MainLayoutProps) {
  // Persist collapse state across sessions
  const [sidebarCollapsed, setSidebarCollapsed] = useLocalStorage(
    'sn_sidebar_collapsed',
    false
  );
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className={styles.root}>
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed((v) => !v)}
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
      />

      <div className={styles.body}>
        <TopBar
          title={title}
          greet={greet}
          onMenuClick={() => setMobileOpen((v) => !v)}
        />
        <main className={styles.content} id="main-content">
          {children}
        </main>
        <AlertPopups />
      </div>
    </div>
  );
}
