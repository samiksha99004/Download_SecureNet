/**
 * SecureNet — NotificationsTab
 *
 * Alert delivery settings:
 *  - Email alerts from the admin's Gmail to every SecureNet user (+ optional extra address; never the admin),
 *    filtered by severity / block action, batched by the backend, optional digest
 *  - Email delivery status from the server and a "send test email" button
 *  (pop-ups, sound and theme are per-user in the Preferences tab)
 */

import { useCallback, useEffect, useState } from 'react';
import { Mail, CheckCircle2, AlertTriangle, Send } from 'lucide-react';
import { useAsyncData } from '../../hooks/useAsyncData';
import { useToast } from '../common/Toast';
import { useAuth } from '../../contexts/AuthContext';
import { getNotificationSettings, updateNotificationSettings } from '../../services/settingsService';
import { getNotificationStatus, sendTestEmail } from '../../services/notificationsService';
import type { NotificationSettings } from '../../types/settings.types';
import { SettingsSection } from './SettingsSection';
import { SettingsField } from './SettingsField';
import { SaveBar } from './SaveBar';
import { LoadingState } from '../common/LoadingState';
import { ErrorState } from '../common/ErrorState';
import styles from './TabShared.module.css';
import local from './NotificationsTab.module.css';
import { errorMessage } from '../../utils/errors';

export function NotificationsTab() {
  const { showToast } = useToast();
  const { user } = useAuth();

  const { data, isLoading, isError, refetch } = useAsyncData(
    useCallback(() => getNotificationSettings(), [])
  );
  const status = useAsyncData(useCallback(() => getNotificationStatus(), []));

  const [form, setForm] = useState<NotificationSettings | null>(null);
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isTesting, setIsTesting] = useState(false);

  useEffect(() => {
    if (data) {
      setForm(data);
      setIsDirty(false);
    }
  }, [data]);

  function update<K extends keyof NotificationSettings>(key: K, value: NotificationSettings[K]) {
    setForm((prev) => (prev ? { ...prev, [key]: value } : prev));
    setIsDirty(true);
  }

  async function handleSave() {
    if (!form) return;
    setIsSaving(true);
    try {
      await updateNotificationSettings(form);
      setIsDirty(false);
      showToast({ message: 'Notification settings saved.', variant: 'success' });
      void refetch();
      void status.refetch();
    } catch (err) {
      showToast({ message: errorMessage(err, 'Could not save.'), variant: 'error' });
    } finally {
      setIsSaving(false);
    }
  }

  function handleDiscard() {
    if (data) {
      setForm(data);
      setIsDirty(false);
    }
  }

  async function handleTestEmail() {
    setIsTesting(true);
    try {
      const res = await sendTestEmail();
      showToast({ message: res.message, variant: 'success' });
    } catch (err) {
      showToast({ message: errorMessage(err, 'Test email failed.'), variant: 'error' });
    } finally {
      setIsTesting(false);
      void status.refetch();
    }
  }

  if (isLoading) return <LoadingState message="Loading notification settings…" />;
  if (isError || !form) {
    return (
      <ErrorState
        title="Settings unavailable"
        message="Email alert settings could not be loaded. Please try again."
        onRetry={refetch}
      />
    );
  }

  const s = status.data;
  const deliveryOk = s?.emailDelivery === 'enabled';

  return (
    <div className={styles.tabContent}>
      {/* ── Server email status ─────────────────────────────────────────── */}
      <div className={`${local.statusBox} ${deliveryOk ? local.ok : local.warn}`} role="status">
        {deliveryOk ? <CheckCircle2 size={18} aria-hidden="true" /> : <AlertTriangle size={18} aria-hidden="true" />}
        <div className={local.statusText}>
          {!s ? (
            <span>Checking email delivery…</span>
          ) : deliveryOk ? (
            <>
              <strong>Email delivery is configured on the server.</strong>
              <span>
                Alerts are sent from the admin email to {s.recipientCount} SecureNet user
                address{s.recipientCount === 1 ? '' : 'es'} (never to the admin): one email when the network turns
                from normal to abnormal, then at most one summary every{' '}
                {Math.round((s.intervalSeconds ?? 300) / 60)} minutes while it stays abnormal. Pop-ups and desktop
                alerts still show every alert.
                {s.lastError && <> Last error: {s.lastError}</>}
              </span>
            </>
          ) : (
            <>
              <strong>
                {s.emailDelivery === 'disabled'
                  ? 'Email delivery is turned off on the server.'
                  : 'SMTP credentials on the server are missing or placeholders.'}
              </strong>
              <span>
                In <code>backend/.env</code> set <code>EMAIL_ENABLED=true</code>, <code>SMTP_USER</code> and{' '}
                <code>SMTP_PASSWORD</code> (for Gmail create an App Password), then restart the backend.
                Until then no emails are sent (alerts still appear in the dashboard) and new accounts cannot sign up.
              </span>
            </>
          )}
        </div>
        <button
          type="button"
          className={local.testButton}
          onClick={() => void handleTestEmail()}
          disabled={isTesting}
          title={`Send a sample alert to ${user?.email ?? 'your email'}`}
        >
          <Send size={14} aria-hidden="true" /> {isTesting ? 'Sending…' : 'Send test email'}
        </button>
      </div>

      {/* ── Email alerts ────────────────────────────────────────────────── */}
      <SettingsSection
        title="Email Alerts"
        description="When abnormal traffic is detected, the admin email sends an alert to every active SecureNet user. The admin does not receive attack emails."
      >
        <SettingsField
          id="notif-email-enabled"
          label="Send Email Alerts"
          hint="Email all SecureNet users when the IDS detects abnormal traffic."
          type="toggle"
          checked={form.emailEnabled}
          onChange={(v) => update('emailEnabled', v)}
        />
        <SettingsField
          id="notif-email-address"
          label="Additional Recipient (optional)"
          hint="An extra address (e.g. a SOC mailbox) that also receives every alert (an admin address is ignored)."
          type="email"
          value={form.emailAddress ?? ''}
          onChange={(v) => update('emailAddress', v || null)}
          disabled={!form.emailEnabled}
          placeholder="soc-team@example.com"
        />
        {s && s.recipients.length > 0 && (
          <div className={local.recipients}>
            <Mail size={14} aria-hidden="true" />
            <span>Recipients: {s.recipients.join(', ')}</span>
          </div>
        )}
        {s && s.recipients.length === 0 && (
          <div className={local.recipients}>
            <Mail size={14} aria-hidden="true" />
            <span>No SecureNet users to email yet — alerts are sent once users register.</span>
          </div>
        )}
      </SettingsSection>

      <SettingsSection
        title="Alert Triggers"
        description="Which detections send an email. Low-severity events appear in the app only unless they were blocked."
      >
        <SettingsField
          id="notif-high"
          label="High Severity"
          hint="Email for every high-severity detection."
          type="toggle"
          checked={form.alertOnHigh}
          onChange={(v) => update('alertOnHigh', v)}
          disabled={!form.emailEnabled}
        />
        <SettingsField
          id="notif-medium"
          label="Medium Severity"
          hint="Email for every medium-severity detection."
          type="toggle"
          checked={form.alertOnMedium}
          onChange={(v) => update('alertOnMedium', v)}
          disabled={!form.emailEnabled}
        />
        <SettingsField
          id="notif-low"
          label="Low Severity"
          hint="Email for every low-severity detection (borderline anomalies)."
          type="toggle"
          checked={form.alertOnLow}
          onChange={(v) => update('alertOnLow', v)}
          disabled={!form.emailEnabled}
        />
      </SettingsSection>

      <SettingsSection
        title="Digest"
        description="A periodic summary email of all security events, in addition to instant alerts."
      >
        <SettingsField
          id="notif-digest"
          label="Enable Digest"
          hint="Send a summary of recent security activity to all recipients."
          type="toggle"
          checked={form.digestEnabled}
          onChange={(v) => update('digestEnabled', v)}
          disabled={!form.emailEnabled}
        />
        <SettingsField
          id="notif-digest-interval"
          label="Digest Interval (hours)"
          hint="How often the digest email is sent."
          type="number"
          value={form.digestIntervalHours}
          onChange={(v) => update('digestIntervalHours', parseInt(v, 10) || 24)}
          min={1}
          max={168}
          disabled={!form.digestEnabled || !form.emailEnabled}
        />
      </SettingsSection>

      <SaveBar isDirty={isDirty} isSaving={isSaving} onSave={handleSave} onDiscard={handleDiscard} />
    </div>
  );
}
