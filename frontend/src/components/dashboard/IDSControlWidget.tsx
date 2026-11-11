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
import { plainReason, possibleAttack, prettyLabel } from '../../utils/verdict';
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
  // The "Latest Unresolved Incident" analysis always names the MAJORITY attack of the live
  // window — `recent` is sorted by share, so attackRows[0] is the dominant class — shown with
  // its breakdown %. This keeps the Possible Attack consistent with the LIVE TRAFFIC BREAKDOWN
  // and never surfaces a stale or secondary class (e.g. a one-off Bot flow) while FTP is the
  // real majority. Falls back to the stored event's own guess only if the window has no attack.
  const topAttack = attackRows[0] ?? null;
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

  // ── Recommended actions ──────────────────────────────────────────────────
  // When the network is abnormal, show the SAFETY STEPS for the detected attack(s).
  // For a combination (e.g. DoS + SQL Injection) the steps are the UNION of both,
  // de-duplicated into one bullet list, so the IDS tells the user what to actually do.
  function attackCategory(label: string): string {
    const l = label.toLowerCase();
    if (l.includes('dos') || l.includes('ddos') || l.includes('hulk') || l.includes('goldeneye')
      || l.includes('slowloris') || l.includes('slowhttp') || l.includes('loic') || l.includes('hoic')) return 'dos';
    if (l.includes('sql')) return 'sqli';
    if (l.includes('xss')) return 'xss';
    if (l.includes('ftp') || l.includes('ssh') || (l.includes('brute') && l.includes('web')) || l.includes('bruteforce')) return 'brute';
    if (l.includes('bot')) return 'bot';
    if (l.includes('infilt') || l.includes('recon') || l.includes('scan')) return 'recon';
    return 'generic';
  }
  const CATEGORY_STEPS: Record<string, string[]> = {
    dos: [
      'Block the attacking source IP at the firewall.',
      'Rate-limit connections and requests per IP on the server.',
      'Enable connection timeouts and SYN/flood protection.',
      'Place the service behind a reverse proxy or WAF to absorb the flood.',
      'For a heavy volumetric flood, contact your ISP or hosting provider.',
    ],
    brute: [
      'Block the attacking source IP at the firewall.',
      'Lock accounts after repeated failed logins and enforce strong passwords.',
      'Enable multi-factor authentication (MFA) on exposed services.',
      'Rate-limit login attempts (e.g. a fail2ban-style tool).',
      'Restrict remote access (SSH/FTP) to trusted IP addresses only.',
    ],
    sqli: [
      'Use parameterized queries / prepared statements in the application.',
      'Validate and sanitize all user input.',
      'Run the database with a least-privilege account.',
      'Deploy a Web Application Firewall (WAF) to filter malicious queries.',
      'Patch and update the vulnerable web application.',
    ],
    xss: [
      'Escape and encode all user input shown on web pages (output encoding).',
      'Set a strict Content-Security-Policy (CSP) header.',
      'Validate and sanitize input on the server side.',
      'Deploy a Web Application Firewall (WAF).',
    ],
    bot: [
      'Isolate the affected host from the network.',
      'Identify and block the beacon / command-and-control destination.',
      'Run a full antivirus / EDR scan on the host.',
      'Change any credentials that may have been exposed.',
    ],
    recon: [
      'Block the scanning source IP at the firewall.',
      'Close or firewall unused ports and services.',
      'Watch closely for follow-up exploitation attempts.',
    ],
    generic: [
      'Block the attacking source IP at the firewall.',
      'Isolate the affected host and review the logs in History.',
    ],
  };
  // attacks currently visible in the breakdown (any share shown, even 0.1%), named for the user
  const activeAttacks = recentRows.filter((r) => !isBenignLabel(r.label) && r.pct >= 0.1);
  const activeCats = Array.from(new Set(activeAttacks.map((r) => attackCategory(r.label))));
  const actionSteps: string[] = [];
  activeCats.forEach((c) => (CATEGORY_STEPS[c] ?? CATEGORY_STEPS.generic).forEach((s) => {
    if (!actionSteps.includes(s)) actionSteps.push(s);
  }));

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
                    {prettyLabel(r.label)}
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
              <DetailRow
                label="Possible attack"
                value={topAttack ? `${prettyLabel(topAttack.label)} (${topAttack.pct.toFixed(1)}%)` : possibleAttack(latestEvent)}
              />
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
            {(topAttack || latestEvent.detectionReason) && (
              <div className={styles.reasonBox}>
                <span className={styles.reasonLabel}>Detection Reason</span>
                {/* Reason follows the LIVE majority too, so it never names a stale/secondary
                    class (e.g. "Bot") while the real dominant attack is something else. */}
                <p className={styles.reasonText}>
                  {topAttack
                    ? `Matches the pattern of ${prettyLabel(topAttack.label)} — ${topAttack.pct.toFixed(1)}% of recent traffic.`
                    : plainReason(latestEvent.detectionReason)}
                </p>
              </div>
            )}
          </div>
        )}

        {/* Recommended safety steps for the detected attack(s) — shown whenever an attack
            appears in the breakdown (not only above the 30% abnormal headline). Union for a combination. */}
        {!isOff && activeAttacks.length > 0 && actionSteps.length > 0 && (
          <div style={{
            marginTop: 14, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.35)',
            borderRadius: 12, padding: '14px 18px',
          }}>
            <div style={{
              fontSize: 12, fontWeight: 700, color: '#ef4444', textTransform: 'uppercase',
              letterSpacing: '0.05em', marginBottom: 4,
            }}>
              Recommended Actions
            </div>
            <div style={{ fontSize: 13, color: '#cbd5e1', marginBottom: 10 }}>
              Detected {activeAttacks.length > 1 ? 'attacks' : 'attack'}:{' '}
              <b style={{ color: '#f87171' }}>{activeAttacks.map((a) => prettyLabel(a.label)).join(', ')}</b>
              {activeAttacks.length > 1 && ' — steps for all are combined below.'}
            </div>
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {actionSteps.map((s, i) => (
                <li key={i} style={{ fontSize: 13.5, lineHeight: 1.6, color: '#e2e8f0' }}>{s}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* ── Live counters (only while the IDS runs) ─────────────────────────── */}
      {idsStatus && !isOff && (
        <div className={styles.statsRow}>
          <Stat label="Packets" value={idsStatus.packetsProcessed} />
          <Stat label="Flows Analyzed" value={idsStatus.flowsAnalyzed} />
          <Stat label="Normal Traffic" value={idsStatus.verdicts?.finalNormal ?? 0} />
          <Stat label="Abnormal Traffic" value={idsStatus.verdicts?.finalAbnormal ?? idsStatus.anomaliesDetected} />
          <Stat label="Incidents Today" value={idsStatus.abnormalEventsToday ?? 0} />
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
