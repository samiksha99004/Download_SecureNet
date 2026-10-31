/**
 * SecureNet — Sidebar
 *
 * Vertical navigation with:
 *  - SecureNet logo + wordmark
 *  - Nav links: Dashboard, History, Reports, Settings, Account, Support
 *  - Active state derived from current route
 *  - Collapse toggle (icon-only mode on desktop)
 *  - Mobile overlay drawer
 *  - Logout button at bottom
 */

import { useCallback } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  Clock,
  FileText,
  Settings,
  User,
  HelpCircle,
  ShieldCheck,
  LogOut,
  ChevronLeft,
  ChevronRight,
  X,
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { cn } from '../../utils/cn';
import styles from './Sidebar.module.css';
import { roleLabel } from '../../utils/roles';

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
}

const NAV_ITEMS: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard',   icon: <LayoutDashboard size={18} /> },
  { to: '/history',   label: 'History',     icon: <Clock           size={18} /> },
  { to: '/reports',   label: 'Reports',     icon: <FileText        size={18} /> },
  { to: '/settings',  label: 'Settings',    icon: <Settings        size={18} /> },
  { to: '/account',   label: 'Account',     icon: <User            size={18} /> },
  { to: '/support',   label: 'Support',     icon: <HelpCircle      size={18} /> },
];

interface SidebarProps {
  collapsed: boolean;
  onToggleCollapse: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

export function Sidebar({
  collapsed,
  onToggleCollapse,
  mobileOpen,
  onCloseMobile,
}: SidebarProps) {
  const { logout, user } = useAuth();
  const navigate = useNavigate();

  const handleLogout = useCallback(async () => {
    await logout();
    navigate('/login', { replace: true });
  }, [logout, navigate]);

  const sidebarContent = (
    <div
      className={cn(styles.sidebar, collapsed && styles.collapsed)}
      aria-label="Main navigation"
    >
      {/* ── Logo ── */}
      <div className={styles.logoRow}>
        <div className={styles.logo} aria-label="SecureNet">
          <ShieldCheck size={22} strokeWidth={1.75} className={styles.logoIcon} />
          {!collapsed && (
            <span className={styles.logoText}>SecureNet</span>
          )}
        </div>

        {/* Desktop collapse toggle */}
        <button
          className={styles.collapseButton}
          onClick={onToggleCollapse}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed
            ? <ChevronRight size={15} />
            : <ChevronLeft  size={15} />}
        </button>

        {/* Mobile close */}
        <button
          className={styles.mobileClose}
          onClick={onCloseMobile}
          aria-label="Close navigation"
        >
          <X size={18} />
        </button>
      </div>

      {/* ── Nav links ── */}
      <nav className={styles.nav} role="navigation" aria-label="Primary">
        <ul className={styles.navList} role="list">
          {NAV_ITEMS.map(({ to, label, icon }) => (
            <li key={to} role="listitem">
              <NavLink
                to={to}
                className={({ isActive }) =>
                  cn(styles.navLink, isActive && styles.navLinkActive)
                }
                onClick={onCloseMobile}
                title={collapsed ? label : undefined}
                aria-label={collapsed ? label : undefined}
              >
                <span className={styles.navIcon} aria-hidden="true">{icon}</span>
                {!collapsed && (
                  <span className={styles.navLabel}>{label}</span>
                )}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      {/* ── Bottom section ── */}
      <div className={styles.bottom}>
        {/* User summary (not collapsed) */}
        {!collapsed && user && (
          <div className={styles.userSummary}>
            <div className={styles.userAvatar} aria-hidden="true">
              {(user.fullName || user.email || 'U').charAt(0).toUpperCase()}
            </div>
            <div className={styles.userInfo}>
              <span className={styles.userName}>{user.fullName || user.email}</span>
              <span className={styles.userRole}>{roleLabel(user.role)}</span>
            </div>
          </div>
        )}

        <button
          className={styles.logoutButton}
          onClick={handleLogout}
          title={collapsed ? 'Sign out' : undefined}
          aria-label="Sign out"
        >
          <LogOut size={16} className={styles.logoutIcon} aria-hidden="true" />
          {!collapsed && <span>Sign out</span>}
        </button>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop sidebar */}
      <aside className={styles.desktopWrapper}>{sidebarContent}</aside>

      {/* Mobile overlay */}
      {mobileOpen && (
        <>
          <div
            className={styles.overlay}
            onClick={onCloseMobile}
            aria-hidden="true"
          />
          <aside className={cn(styles.mobileDrawer, mobileOpen && styles.mobileDrawerOpen)}>
            {sidebarContent}
          </aside>
        </>
      )}
    </>
  );
}
