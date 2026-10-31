/**
 * SecureNet — SystemTab
 *
 * Settings tab for system-level configuration (retention, timezone, debug).
 */

import { useCallback, useEffect, useState } from 'react';
import { useAsyncData } from '../../hooks/useAsyncData';
import { useToast } from '../common/Toast';
import { getSystemSettings, updateSystemSettings } from '../../services/settingsService';
import type { SystemSettings } from '../../types/settings.types';
import { SettingsSection } from './SettingsSection';
import { SettingsField } from './SettingsField';
import { SaveBar } from './SaveBar';
import { LoadingState } from '../common/LoadingState';
import { ErrorState } from '../common/ErrorState';
import styles from './TabShared.module.css';
import { errorMessage } from '../../utils/errors';

export function SystemTab() {
  const { showToast } = useToast();
  const { data, isLoading, isError, refetch } = useAsyncData(
    useCallback(() => getSystemSettings(), [])
  );

  const [local, setLocal] = useState<SystemSettings | null>(null);
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    if (data) {
      setLocal(data);
      setIsDirty(false);
    }
  }, [data]);

  function update<K extends keyof SystemSettings>(key: K, value: SystemSettings[K]) {
    setLocal((prev) => prev ? { ...prev, [key]: value } : prev);
    setIsDirty(true);
  }

  async function handleSave() {
    if (!local) return;
    setIsSaving(true);
    try {
      await updateSystemSettings(local);
      setIsDirty(false);
      showToast({ message: 'System settings saved.', variant: 'success' });
      void refetch();
    } catch (err) {
      showToast({ message: errorMessage(err, 'Could not save.'), variant: 'error' });
    } finally {
      setIsSaving(false);
    }
  }

  function handleDiscard() {
    if (data) {
      setLocal(data);
      setIsDirty(false);
    }
  }

  if (isLoading) return <LoadingState message="Loading system settings…" />;
  if (isError || !local) {
    return (
      <ErrorState
        title="Settings unavailable"
        message="System settings could not be loaded. Please try again."
        onRetry={refetch}
      />
    );
  }

  return (
    <div className={styles.tabContent}>
      <SettingsSection
        title="Data Retention"
        description="Control how long security events are stored."
      >
        <SettingsField
          id="sys-retention"
          label="Log Retention (days)"
          hint="Events older than this many days will be automatically deleted."
          type="number"
          value={local.logRetentionDays}
          onChange={(v) => update('logRetentionDays', parseInt(v, 10) || 30)}
          min={1}
          max={3650}
        />
        <SettingsField
          id="sys-max-events"
          label="Max Stored Events"
          hint="Hard cap on the total number of events kept in the database."
          type="number"
          value={local.maxStoredEvents}
          onChange={(v) => update('maxStoredEvents', parseInt(v, 10) || 0)}
          min={100}
          step={1000}
        />
      </SettingsSection>

      <SettingsSection
        title="Localisation"
        description="Configure time and date display preferences."
      >
        <SettingsField
          id="sys-timezone"
          label="Timezone"
          hint="IANA timezone string used for displaying event timestamps."
          type="text"
          value={local.timezone}
          onChange={(v) => update('timezone', v)}
          placeholder="UTC"
        />
        <SettingsField
          id="sys-dateformat"
          label="Date Format"
          hint="Format string used in reports and exports."
          type="text"
          value={local.dateFormat}
          onChange={(v) => update('dateFormat', v)}
          placeholder="DD MMM YYYY"
        />
      </SettingsSection>

      <SettingsSection
        title="Contact Details"
        description="Shown to every user under Support → Contact us. Leave a field empty to hide it."
      >
        <SettingsField
          id="sys-contact-website"
          label="Website"
          hint="Your organisation's website."
          type="text"
          value={local.contactWebsite ?? ''}
          onChange={(v) => update('contactWebsite', v)}
          placeholder="www.example.com"
        />
        <SettingsField
          id="sys-contact-phone"
          label="Phone Number"
          hint="Number users can call for help."
          type="text"
          value={local.contactPhone ?? ''}
          onChange={(v) => update('contactPhone', v)}
          placeholder="+91 …"
        />
        <SettingsField
          id="sys-contact-email"
          label="Email"
          hint="If empty, the admin's email is shown."
          type="email"
          value={local.contactEmail ?? ''}
          onChange={(v) => update('contactEmail', v)}
          placeholder="support@…"
        />
        <SettingsField
          id="sys-contact-address"
          label="Admin Office Location"
          hint="Address of the admin office."
          type="text"
          value={local.contactAddress ?? ''}
          onChange={(v) => update('contactAddress', v)}
          placeholder="Building, street, city"
        />
      </SettingsSection>

      <SettingsSection
        title="Developer"
        description="Advanced options for debugging and development."
      >
        <SettingsField
          id="sys-debug"
          label="Debug Mode"
          hint="Write detailed logs for troubleshooting. Leave off normally."
          type="toggle"
          checked={local.debugMode}
          onChange={(v) => update('debugMode', v)}
        />
      </SettingsSection>

      <SaveBar
        isDirty={isDirty}
        isSaving={isSaving}
        onSave={handleSave}
        onDiscard={handleDiscard}
      />
    </div>
  );
}
