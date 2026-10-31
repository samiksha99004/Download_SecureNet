/**
 * IDS Control Widget
 *
 * ON / OFF control plus live IDS status:
 *  - power toggle (every signed-in user). ON = capture, detect, alert + email.
 *  - capture + detector state (clearly says when no model is loaded)
 *  - current status: IDS IS OFF while stopped; when running NORMAL or ABNORMAL TRAFFIC
 *    DETECTED, with a "What kind of attack could it be?" chance table right under it
 *  - plain words only: no model names anywhere on the dashboard
 *  - live counters from the backend
 */

import { useState } from 'react';
import { Power, Shield, ShieldOff, AlertTriangle, Info } from 'lucide-react';
import { useToast } from '../common/Toast';
import { useAuth } from '../../contexts/AuthContext';
import { useNotifications } from '../../contexts/NotificationContext';
import {
  startIDS,
  stopIDS,
  type IDSStatus,
} from '../../services/idsService';
import { requestDesktopNotifications } from '../../utils/alertChannels';
import { formatTimestamp, formatDuration } from '../../utils/format';
import type { SecurityEvent } from '../../types/security.types';
import { plainReason, possibleAttack } from '../../utils/verdict';
import styles from './IDSControlWidget.module.css';

interface IDSControlWidgetProps {
  idsStatus: IDSStatus | null;
  latestEvent: SecurityEvent | null;
  isLoading: boolean;
  onStatusChange: () => void;
}

export function IDSControlWidget({
  idsStatus,
  latestEvent,
  isLoading,
  onStatusChange,
}: IDSControlWidgetProps) {
  const { showToast } = useToast();
  const { isAdmin } = useAuth();
  const { prefs } = useNotifications();
  const [isBusy, setIsBusy] = useState(false);

  const isEnabled = idsStatus?.enabled ?? false;

  async function run(action: () => Promise<unknown>, success: string) {
    setIsBusy(true);
    try {
      await action();
      showToast({ message: success, variant: 'success' });
      onStatusChange();
    } catch (err) {
      showToast({
        message: err instanceof Error && err.message ? err.message : 'The IDS request failed.',
        variant: 'error',
      });
    } finally {
      setIsBusy(false);
    }
  }

  function handleToggle() {
    if (isEnabled) {
      void run(stopIDS, 'IDS stopped');
    } else {
      if (prefs.desktop) void requestDesktopNotifications();   // only asks the browser once
      // no mode => the backend uses the saved Advanced Protection choice (Settings → Advanced Protection)
      void run(() => startIDS(), 'IDS started');
    }
  }

  // Advanced Protection on/off (read-only here; the switch lives in Settings → Advanced Protection)
  const protectionOn = idsStatus?.mode === 'protect';

  // Live verdict from the rolling window (what the CLI printed each refresh) — not sticky.
  const isOff = !isEnabled;
  const recentRows = idsStatus?.verdicts?.recent ?? [];
  const recentTotal = idsStatus?.verdicts?.recentTotal ?? 0;
  const recentAbnormalPct = idsStatus?.verdicts?.recentAbnormalPct ?? 0;
  // ABNORMAL only when attacks make up more than 30% of recent traffic; below that stays NORMAL
  // (green) while the breakdown below still lists every attack class, even 0.1%.
  const ABNORMAL_THRESHOLD = 30;
  const liveAbnormal = isEnabled && recentTotal > 0 && recentAbnormalPct > ABNORMAL_THRESHOLD;
  const attackRows = recentRows.filter((r) => !isBenignLabel(r.label));
  // Has ANY flow been scored since the IDS was turned on? `scored` only grows during a session
  // (reset to 0 on each ON). We show "WAITING FOR TRAFFIC" ONLY before that first flow — once the
  // IDS has seen any traffic, a momentary lull (empty 90s window) is just quiet NORMAL, never a
  // flip back to "waiting". That mid-session flip was the reported bug.
  const seenTraffic = (idsStatus?.verdicts?.scored ?? 0) > 0;
  const statusLabel = !idsStatus
    ? (isLoading ? 'CHECKING…' : 'STATUS UNKNOWN')
    : isOff
      ? 'IDS IS OFF'
      : (recentTotal === 0 && !seenTraffic)
        ? 'WAITING FOR TRAFFIC…'
        : liveAbnormal
          ? 'ABNORMAL TRAFFIC DETECTED'
          : 'NORMAL TRAFFIC';
  const cardStyle = isOff ? styles.statusOff : liveAbnormal ? styles.statusAbnormal : styles.statusNormal;

  function isBenignLabel(l: string) {
    return ['benign', 'normal'].includes(l.toLowerCase());
  }

  return (
    <div className={styles.widget}>
      {/* ── Power ─────────────────────────────────────────────────────── */}
      <div className={styles.powerSection}>
        <div className={styles.powerHeader}>
          <div>
            <h2 className={styles.title}>Intrusion Detection System</h2>
            <p className={styles.subtitle}>
              {isEnabled
                ? 'Running'
                  + (idsStatus?.uptimeSeconds ? ` · up ${formatDuration(idsStatus.uptimeSeconds)}` : '')
                  + (protectionOn ? ' · Advanced Protection ON' : ' · Advanced Protection off')
                : 'Stopped'}
            </p>
          </div>

          <div className={styles.controls}>
            <button
              type="button"
              className={`${styles.powerButton} ${isEnabled ? styles.powerOn : styles.powerOff}`}
              onClick={handleToggle}
              disabled={isBusy || isLoading}
              aria-label={isEnabled ? 'Stop IDS' : 'Start IDS'}
            >
              <Power size={18} aria-hidden="true" />
              <span className={styles.powerLabel}>{isEnabled ? 'ON' : 'OFF'}</span>
            </button>
          </div>
        </div>

        {idsStatus?.captureError && (
          <p className={`${styles.notice} ${styles.noticeError}`} role="alert">
            <AlertTriangle size={14} aria-hidden="true" /> {idsStatus.captureError}
          </p>
        )}
        {idsStatus && !idsStatus.mlLoaded && (
          <p className={styles.notice}>
            <Info size={14} aria-hidden="true" />{' '}
            {isAdmin
              ? 'Attack detection is not set up yet — traffic is counted but not checked. Load the detection model in Settings → Model.'
              : 'Attack detection is not set up yet — your SecureNet admin needs to finish the setup. Traffic is still counted while the IDS is on.'}
          </p>
        )}
      </div>

      {/* ── Current status ────────────────────────────────────────────────── */}
      <div className={styles.statusSection}>
        <div className={`${styles.statusCard} ${cardStyle}`}>
          <div className={styles.statusIcon}>
            {isOff ? <ShieldOff size={22} /> : liveAbnormal ? <AlertTriangle size={22} /> : <Shield size={22} />}
          </div>
          <div className={styles.statusContent}>
            <span className={styles.statusLabel}>Current Status</span>
            <span className={styles.statusValue}>{statusLabel}</span>
            {idsStatus && isOff && (
              <span className={styles.statusHint}>Your network is not being watched. Press ON to start monitoring.</span>
            )}
          </div>
          <div className={styles.detectorInfo}>
            <span className={styles.statusLabel}>Detection</span>
            <span className={styles.detectorValue}>{idsStatus?.mlLoaded ? 'Active' : 'Not set up yet'}</span>
          </div>
        </div>

        {/* CLI-style live breakdown: share of each class over the last 90s (normal + attacks) */}
        {!isOff && recentTotal > 0 && (
          <div style={{ marginTop: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
              <span style={{ fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.04em', opacity: 0.7 }}>
                Live traffic breakdown
                {attackRows.length > 0 && (
                  <span style={{ marginLeft: 8, color: liveAbnormal ? '#ef4444' : '#f59e0b', fontWeight: 600 }}>
                    · attacks {recentAbnormalPct.toFixed(1)}%
                  </span>
                )}
              </span>
              <span style={{ fontSize: 12, opacity: 0.6 }}>last 90s · {recentTotal} flows</span>
            </div>
            {recentRows.filter((r) => r.pct >= 0.1).map((r) => {
              const color = isBenignLabel(r.label) ? '#22c55e' : '#ef4444';
              return (
                <div key={r.label} style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '5px 0' }}>
                  <span style={{ flex: '0 0 44%', fontSize: 13, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {r.label}
                  </span>
                  <div style={{ flex: 1, height: 8, borderRadius: 4, background: 'rgba(148,163,184,0.18)', overflow: 'hidden' }}>
                    <div style={{ width: `${r.pct}%`, height: '100%', background: color, borderRadius: 4 }} />
                  </div>
                  <span style={{ flex: '0 0 52px', textAlign: 'right', fontSize: 13, fontVariantNumeric: 'tabular-nums' }}>
                    {r.pct.toFixed(1)}%
                  </span>
                </div>
              );
            })}
          </div>
        )}

        {/* incident details only during a LIVE attack (not stale) */}
        {!isOff && liveAbnormal && latestEvent && (
          <div className={styles.incidentDetails}>
            <h3 className={styles.incidentTitle}>Latest Unresolved Incident</h3>
            <div className={styles.incidentGrid}>
              <DetailRow label="Verdict" value="Abnormal traffic" highlight />
              <DetailRow label="Possible attack" value={possibleAttack(latestEvent)} />
              <DetailRow label="Severity" value={latestEvent.severity.toUpperCase()} />
              <DetailRow label="Source" value={`${latestEvent.sourceIp}:${latestEvent.sourcePort}`} />
              <DetailRow label="Destination" value={`${latestEvent.destinationIp}:${latestEvent.destinationPort}`} />
              <DetailRow label="Protocol" value={latestEvent.protocol} />
              <DetailRow label="Time" value={formatTimestamp(latestEvent.timestamp)} />
              <DetailRow
                label="Action"
                value={latestEvent.actionTaken.toUpperCase()}
                highlight={latestEvent.actionTaken === 'blocked'}
              />
            </div>
            {latestEvent.detectionReason && (
              <div className={styles.reasonBox}>
                <span className={styles.reasonLabel}>Detection Reason</span>
                <p className={styles.reasonText}>{plainReason(latestEvent.detectionReason)}</p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Live counters (only while the IDS runs) ─────────────────────────── */}
      {idsStatus && !isOff && (
        <div className={styles.statsRow}>
          <Stat label="Packets" value={idsStatus.packetsProcessed} />
          <Stat label="Flows Analyzed" value={idsStatus.flowsAnalyzed} />
          <Stat label="Active Flows" value={idsStatus.activeFlows} />
          <Stat label="Normal Traffic" value={idsStatus.verdicts?.finalNormal ?? 0} />
          <Stat label="Abnormal Traffic" value={idsStatus.verdicts?.finalAbnormal ?? idsStatus.anomaliesDetected} />
        </div>
      )}
    </div>
  );
}

function DetailRow({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div className={styles.detailRow}>
      <span className={styles.detailLabel}>{label}</span>
      <span className={`${styles.detailValue} ${highlight ? styles.detailHighlight : ''}`}>{value}</span>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className={styles.stat}>
      <span className={styles.statValue}>{value.toLocaleString()}</span>
      <span className={styles.statLabel}>{label}</span>
    </div>
  );
}
