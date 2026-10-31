/**
 * SecureNet — Preferences tab (every user)
 *
 * Personal app settings, saved on this device immediately:
 *   theme (dark / light), notifications on/off, notification sound,
 *   desktop notifications on/off (asks the browser for permission when needed).
 * Attack alert emails on/off is stored with the account (PUT /auth/me/preferences).
 */

import { useState } from 'react';
import { Moon, Sun } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { useNotifications } from '../../contexts/NotificationContext';
import { updatePreferences } from '../../services/authService';
import { useToast } from '../common/Toast';
import { errorMessage } from '../../utils/errors';
import { playAlertSound } from '../../utils/alertChannels';
import { useTheme, type Theme } from '../../utils/theme';
import { SettingsSection } from './SettingsSection';
import { SettingsField } from './SettingsField';
import styles from './TabShared.module.css';
import local from './PreferencesTab.module.css';

const THEMES: { id: Theme; label: string; icon: typeof Moon }[] = [
  { id: 'dark', label: 'Dark', icon: Moon },
  { id: 'light', label: 'Peach', icon: Sun },
];

export function PreferencesTab() {
  const { user, completeLogin, isAdmin } = useAuth();
  const [theme, setTheme] = useTheme();
  const { prefs, setPrefs, desktopPermission, enableDesktopNotifications } = useNotifications();
  const { showToast } = useToast();
  const [savingEmail, setSavingEmail] = useState(false);

  async function saveEmailAlerts(on: boolean) {
    setSavingEmail(true);
    try {
      completeLogin(await updatePreferences(on));
      showToast({ message: on ? 'Attack alert emails are on.' : 'Attack alert emails are off.', variant: 'success' });
    } catch (err) {
      showToast({ message: errorMessage(err, 'Could not save this setting.'), variant: 'error' });
    } finally {
      setSavingEmail(false);
    }
  }

  return (
    <div className={styles.tabContent}>
      <SettingsSection title="Appearance" description="Choose how SecureNet looks on this device.">
        <SettingsField id="pref-theme" label="Theme" hint="Dark, or the light peach theme." type="custom">
          <div className={local.themeGroup} role="radiogroup" aria-label="Theme">
            {THEMES.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                type="button"
                role="radio"
                aria-checked={theme === id}
                className={`${local.themeButton} ${theme === id ? local.themeActive : ''}`}
                onClick={() => setTheme(id)}
              >
                <Icon size={15} aria-hidden="true" />
                {label}
              </button>
            ))}
          </div>
        </SettingsField>
      </SettingsSection>

      <SettingsSection
        title="Notifications"
        description="How attack alerts reach you while SecureNet is open. Saved on this device."
      >
        <SettingsField
          id="pref-notifications"
          label="Notifications"
          hint="Show an alert on screen (and on the desktop when SecureNet is in the background) when an attack is detected."
          type="toggle"
          checked={prefs.popups}
          onChange={(v) => setPrefs({ popups: v })}
        />
        <SettingsField
          id="pref-sound"
          label="Notification Sound"
          hint="Play a tone for medium and high severity attacks."
          type="toggle"
          checked={prefs.sound}
          onChange={(v) => setPrefs({ sound: v })}
        />
        <SettingsField id="pref-sound-test" label="Test Sound" hint="Hear the alert tone." type="custom">
          <button type="button" className={local.button} onClick={() => playAlertSound('high')} disabled={!prefs.sound}>
            Play
          </button>
        </SettingsField>
        <SettingsField
          id="pref-desktop"
          label="Desktop Notifications"
          hint={
            desktopPermission === 'denied'
              ? 'Blocked by the browser. Allow notifications for this site in the browser’s site settings (the icon left of the address), then switch this on.'
              : desktopPermission === 'unsupported'
              ? 'This browser does not support desktop notifications.'
              : 'Show attack alerts on your desktop while SecureNet is in the background.'
          }
          type="toggle"
          checked={prefs.desktop && desktopPermission === 'granted'}
          disabled={desktopPermission === 'denied' || desktopPermission === 'unsupported'}
          onChange={(on) => {
            if (on && desktopPermission !== 'granted') void enableDesktopNotifications();
            else setPrefs({ desktop: on });
          }}
        />
      </SettingsSection>

      {isAdmin ? (
        <SettingsSection
          title="Email Alerts"
          description="As the admin you send the attack alert emails (from the SecureNet Gmail) to every SecureNet user — you don't receive them yourself. Sign-in and confirmation codes are still emailed to you."
        >
          <></>
        </SettingsSection>
      ) : (
      <SettingsSection
        title="Email Alerts"
        description="An email with the incident report when an attack is detected. Sign-in and confirmation codes are always emailed."
      >
        <SettingsField
          id="pref-email-alerts"
          label="Attack Alert Emails"
          hint={user?.emailAlerts === false
            ? `Off — no attack emails are sent to ${user?.email ?? 'you'}.`
            : `On — sent to ${user?.email ?? 'your email'}.`}
          type="toggle"
          checked={user?.emailAlerts !== false}
          disabled={savingEmail}
          onChange={(on) => void saveEmailAlerts(on)}
        />
      </SettingsSection>
      )}
    </div>
  );
}
