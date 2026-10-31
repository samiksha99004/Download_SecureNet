/**
 * SecureNet — AdvancedProtectionTab
 *
 * One switch. OFF = normal IDS (detect + alert only).
 * ON  = detect AND protect: once the network turns abnormal it blocks the
 *       attacker's IP at the Windows Firewall and writes every block to the report.
 *
 * Turning it ON needs email confirmation: a 6-digit code is emailed to the admin
 * and must be entered here. Turning it OFF is immediate. Admin only.
 */

import { useCallback, useEffect, useState } from 'react';
import { useAsyncData } from '../../hooks/useAsyncData';
import { useToast } from '../common/Toast';
import {
  getAdvancedProtection,
  updateAdvancedProtection,
  requestAdvancedProtectionCode,
  confirmAdvancedProtection,
  type AdvancedProtectionChallenge,
} from '../../services/settingsService';
import { SettingsSection } from './SettingsSection';
import { SettingsField } from './SettingsField';
import { LoadingState } from '../common/LoadingState';
import { ErrorState } from '../common/ErrorState';
import styles from './TabShared.module.css';
import { errorMessage } from '../../utils/errors';

export function AdvancedProtectionTab() {
  const { showToast } = useToast();
  const { data, isLoading, isError, refetch } = useAsyncData(
    useCallback(() => getAdvancedProtection(), [])
  );

  const [enabled, setEnabled] = useState(false);
  const [isBusy, setIsBusy] = useState(false);
  const [challenge, setChallenge] = useState<AdvancedProtectionChallenge | null>(null);
  const [target, setTarget] = useState(false);     // the on/off state we're confirming
  const [otp, setOtp] = useState('');

  useEffect(() => {
    if (data) setEnabled(data.enabled);
  }, [data]);

  // Turning ON is instant (no code — more security needs no gate). Turning OFF needs an emailed
  // code so an attacker who got in can't just switch protection off.
  async function handleToggle(next: boolean) {
    setIsBusy(true);
    try {
      if (next) {
        const res = await updateAdvancedProtection(true);
        setEnabled(res.enabled);
        showToast({ message: 'Advanced Protection is ON — attackers will be blocked.', variant: 'success' });
      } else {
        const c = await requestAdvancedProtectionCode(false);
        setTarget(false);
        setChallenge(c);
        setOtp('');
        showToast({ message: `Confirmation code sent to ${c.sentTo}.`, variant: 'success' });
      }
    } catch (err) {
      showToast({ message: errorMessage(err, 'Could not change Advanced Protection.'), variant: 'error' });
    } finally {
      setIsBusy(false);
    }
  }

  async function handleConfirm() {
    if (!challenge || otp.trim().length < 4) return;
    setIsBusy(true);
    try {
      const res = await confirmAdvancedProtection(challenge.confirmToken, otp.trim());
      setEnabled(res.enabled);
      setChallenge(null);
      setOtp('');
      showToast({
        message: res.enabled
          ? 'Advanced Protection is ON — attackers will be blocked.'
          : 'Advanced Protection is OFF — detection only.',
        variant: 'success',
      });
    } catch (err) {
      showToast({ message: errorMessage(err, 'That code was not accepted.'), variant: 'error' });
    } finally {
      setIsBusy(false);
    }
  }

  function handleCancel() {
    setChallenge(null);
    setOtp('');
  }

  async function handleResend() {
    setIsBusy(true);
    try {
      const c = await requestAdvancedProtectionCode(target);
      setChallenge(c);
      setOtp('');
      showToast({ message: `New code sent to ${c.sentTo}.`, variant: 'success' });
    } catch (err) {
      showToast({ message: errorMessage(err, 'Could not resend the code.'), variant: 'error' });
    } finally {
      setIsBusy(false);
    }
  }

  if (isLoading) return <LoadingState message="Loading protection settings…" />;
  if (isError || !data) {
    return (
      <ErrorState
        title="Settings unavailable"
        message="Advanced Protection could not be loaded. Please try again."
        onRetry={refetch}
      />
    );
  }

  return (
    <div className={styles.tabContent}>
      <SettingsSection
        title="Advanced Protection"
        description={
          'When OFF, SecureNet watches the network and alerts you — it only detects. '
          + 'When ON, it also acts: once an attack takes over the traffic it blocks the attacker at your firewall, and every block is added to the report. Turning it on is instant; turning it off needs a code emailed to you, so an attacker can’t disable protection.'
        }
      >
        <SettingsField
          id="advanced-protection"
          label={enabled ? 'Protection is ON' : 'Protection is OFF'}
          hint="Turn this on to let SecureNet block attackers automatically. Leave it off to run as a detection-only IDS."
          type="toggle"
          checked={enabled}
          onChange={handleToggle}
          disabled={isBusy || challenge !== null}
        />
      </SettingsSection>

      {challenge && (
        <SettingsSection
          title="Confirm by email"
          description={`We emailed a 6-digit code to ${challenge.sentTo}. Enter it to turn Advanced Protection ${target ? 'on' : 'off'}.`}
        >
          <SettingsField
            id="advanced-protection-code"
            label="Confirmation code"
            hint="Check the admin inbox for the SecureNet Advanced Protection code."
            type="text"
            value={otp}
            onChange={(v) => setOtp(v.replace(/\D/g, '').slice(0, 10))}
            placeholder="123456"
          />
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 4 }}>
            <button
              type="button"
              onClick={handleConfirm}
              disabled={isBusy || otp.trim().length < 4}
              style={{
                padding: '8px 16px', borderRadius: 8, border: 'none', cursor: 'pointer',
                background: 'var(--color-peach-dark, #c2410c)', color: 'var(--color-on-accent, #fff)',
                fontWeight: 600, opacity: isBusy || otp.trim().length < 4 ? 0.6 : 1,
              }}
            >
              {target ? 'Turn protection on' : 'Turn protection off'}
            </button>
            <button
              type="button"
              onClick={handleResend}
              disabled={isBusy}
              style={{
                padding: '8px 16px', borderRadius: 8, cursor: 'pointer',
                background: 'transparent', border: '1px solid var(--color-border, #d6c4b4)',
                color: 'inherit', fontWeight: 500,
              }}
            >
              Resend code
            </button>
            <button
              type="button"
              onClick={handleCancel}
              disabled={isBusy}
              style={{
                padding: '8px 16px', borderRadius: 8, cursor: 'pointer',
                background: 'transparent', border: '1px solid var(--color-border, #d6c4b4)',
                color: 'inherit', fontWeight: 500,
              }}
            >
              Cancel
            </button>
          </div>
        </SettingsSection>
      )}
    </div>
  );
}
