/**
 * SecureNet — Settings Page
 *
 * Everyone:
 *   Preferences   — theme (dark / light), notifications on/off, notification sound
 * Admin only (IDS configuration):
 *   Detection     — anomaly threshold θ and XGBoost stage-2 options
 *   Email Alerts  — which attacks are emailed to registered users, test email
 *   Whitelist     — trusted IP / CIDR / port / protocol entries
 *   Model         — ML model status + reload
 *   System        — data retention, timezone, debug
 *
 * The IDS itself is turned on/off from the Dashboard.
 */

import { Activity, Bell, List, Cpu, Server, SlidersHorizontal, ShieldCheck } from 'lucide-react';
import { MainLayout } from '../components/layout/MainLayout';
import { PageHeader } from '../components/common/PageHeader';
import { SettingsLayout, type SettingsTab } from '../components/settings/SettingsLayout';
import { PreferencesTab }   from '../components/settings/PreferencesTab';
import { DetectionTab }     from '../components/settings/DetectionTab';
import { AdvancedProtectionTab } from '../components/settings/AdvancedProtectionTab';
import { NotificationsTab } from '../components/settings/NotificationsTab';
import { WhitelistTab }     from '../components/settings/WhitelistTab';
import { ModelTab }         from '../components/settings/ModelTab';
import { SystemTab }        from '../components/settings/SystemTab';
import { useLocalStorage } from '../hooks/useLocalStorage';
import { useAuth } from '../contexts/AuthContext';
import styles from './SettingsPage.module.css';

const USER_TABS: SettingsTab[] = [
  { id: 'preferences', label: 'Preferences', icon: <SlidersHorizontal size={15} /> },
  { id: 'protection',  label: 'Advanced Protection', icon: <ShieldCheck size={15} /> },
];

const ADMIN_TABS: SettingsTab[] = [
  { id: 'detection',     label: 'Detection',    icon: <Activity size={15} /> },
  { id: 'notifications', label: 'Email Alerts', icon: <Bell     size={15} /> },
  { id: 'whitelist',     label: 'Whitelist',    icon: <List     size={15} /> },
  { id: 'model',         label: 'Model',        icon: <Cpu      size={15} /> },
  { id: 'system',        label: 'System',       icon: <Server   size={15} /> },
];

export function SettingsPage() {
  const [storedTab, setActiveTab] = useLocalStorage<string>('sn_settings_tab', 'preferences');
  const { isAdmin } = useAuth();

  const tabs = isAdmin ? [...USER_TABS, ...ADMIN_TABS] : USER_TABS;
  const activeTab = tabs.some((t) => t.id === storedTab) ? storedTab : 'preferences';

  function renderTab() {
    switch (activeTab) {
      case 'detection':     return <DetectionTab />;
      case 'protection':    return <AdvancedProtectionTab />;
      case 'notifications': return <NotificationsTab />;
      case 'whitelist':     return <WhitelistTab />;
      case 'model':         return <ModelTab />;
      case 'system':        return <SystemTab />;
      default:              return <PreferencesTab />;
    }
  }

  return (
    <MainLayout title="Settings">
      <div className={styles.page}>
        <PageHeader
          title="Settings"
          description={
            isAdmin
              ? 'Your preferences, plus IDS configuration for administrators. Turn the IDS on/off from the Dashboard.'
              : 'Theme and notification preferences for this device.'
          }
        />

        <SettingsLayout tabs={tabs} activeTab={activeTab} onTabChange={setActiveTab}>
          {renderTab()}
        </SettingsLayout>
      </div>
    </MainLayout>
  );
}
