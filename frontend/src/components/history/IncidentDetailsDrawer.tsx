/**
 * SecureNet — IncidentDetailsDrawer
 *
 * Slide-in side drawer showing full details for a selected security event.
 *
 * Sections:
 *  - Event metadata (ID, timestamp, protocol)
 *  - Network endpoints (source/destination IP:port)
 *  - Detection result (score, severity, attack type, confidence)
 *  - Detection reason + contributing features
 *  - Flow statistics
 *  - Actions (Resolve, Mark as False Positive)
 *
 * Resolve / false-positive actions are shown to the admin only.
 * Accessible: focus-traps on open, closes on Escape, role="dialog".
 */

import { useEffect, useRef, useCallback } from 'react';
import { X } from 'lucide-react';
import type { SecurityEvent } from '../../types/security.types';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import {
  formatTimestamp,
  formatScore,
  formatPercent,
  formatBytes,
  formatNumber,
  toTitleCase,
} from '../../utils/format';
import styles from './IncidentDetailsDrawer.module.css';
import { ABNORMAL_TRAFFIC, MIN_SHOWN_CHANCE, guessesOf, guessLabel, percent, plainReason, possibleAttack } from '../../utils/verdict';

interface IncidentDetailsDrawerProps {
  event: SecurityEvent | null;
  isOpen: boolean;
  onClose: () => void;
  onResolve?: (id: string) => void;
  onMarkFalsePositive?: (id: string) => void;
}

interface FieldRowProps {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}

function FieldRow({ label, value, mono = false }: FieldRowProps) {
  return (
    <div className={styles.fieldRow}>
      <dt className={styles.fieldLabel}>{label}</dt>
      <dd className={mono ? styles.fieldValueMono : styles.fieldValue}>{value}</dd>
    </div>
  );
}

function SectionHeading({ children }: { children: React.ReactNode }) {
  return <h3 className={styles.sectionHeading}>{children}</h3>;
}

export function IncidentDetailsDrawer({
  event,
  isOpen,
  onClose,
  onResolve,
  onMarkFalsePositive,
}: IncidentDetailsDrawerProps) {
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const drawerRef = useRef<HTMLDivElement>(null);

  // Focus close button when drawer opens
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => closeButtonRef.current?.focus(), 50);
    }
  }, [isOpen, event]);

  // Close on Escape
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [isOpen, onClose]);

  const handleResolve = useCallback(() => {
    if (event) onResolve?.(event.id);
  }, [event, onResolve]);

  const handleFalsePositive = useCallback(() => {
    if (event) onMarkFalsePositive?.(event.id);
  }, [event, onMarkFalsePositive]);

  if (!isOpen) return null;

  return (
    <>
      {/* Overlay */}
      <div
        className={styles.overlay}
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer */}
      <aside
        ref={drawerRef}
        className={styles.drawer}
        role="dialog"
        aria-modal="true"
        aria-label="Incident details"
        aria-labelledby="drawer-title"
      >
        {/* Header */}
        <div className={styles.drawerHeader}>
          <div className={styles.drawerTitleRow}>
            <h2 id="drawer-title" className={styles.drawerTitle}>
              Incident Details
            </h2>
            {event && (
              <span className={styles.eventId}>
                #{event.id.slice(0, 8).toUpperCase()}
              </span>
            )}
          </div>
          <button
            ref={closeButtonRef}
            className={styles.closeButton}
            onClick={onClose}
            aria-label="Close incident details"
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className={styles.drawerBody}>
          {!event ? (
            <p className={styles.noEvent}>No event selected.</p>
          ) : (
            <>
              {/* ── Severity + State badges ────────────────────────────── */}
              <div className={styles.badgeRow}>
                <SeverityBadge severity={event.severity} />
                <StatusBadge
                  status={
                    event.state as
                      | 'active'
                      | 'investigating'
                      | 'resolved'
                      | 'false_positive'
                  }
                />
              </div>

              {/* ── Section: Event metadata ────────────────────────────── */}
              <section aria-label="Event metadata">
                <SectionHeading>Event Information</SectionHeading>
                <dl className={styles.fieldList}>
                  <FieldRow label="Event ID"   value={event.id}                    mono />
                  <FieldRow label="Timestamp"  value={formatTimestamp(event.timestamp)} mono />
                  <FieldRow label="Protocol"   value={event.protocol}              mono />
                  <FieldRow
                    label="Action Taken"
                    value={toTitleCase(event.actionTaken)}
                  />
                </dl>
              </section>

              {/* ── Section: Network endpoints ─────────────────────────── */}
              <section aria-label="Network endpoints">
                <SectionHeading>Network</SectionHeading>
                <dl className={styles.fieldList}>
                  <FieldRow
                    label="Source"
                    value={`${event.sourceIp}:${event.sourcePort}`}
                    mono
                  />
                  <FieldRow
                    label="Destination"
                    value={`${event.destinationIp}:${event.destinationPort}`}
                    mono
                  />
                </dl>
              </section>

              {/* ── Section: Detection result ──────────────────────────── */}
              <section aria-label="Detection result">
                <SectionHeading>Detection Result</SectionHeading>
                <dl className={styles.fieldList}>
                  <FieldRow
                    label="Anomaly Score"
                    value={formatScore(event.anomalyScore, 6)}
                    mono
                  />
                  <FieldRow
                    label="Severity"
                    value={<SeverityBadge severity={event.severity} />}
                  />
                  <FieldRow label="Verdict" value={ABNORMAL_TRAFFIC} />
                  <FieldRow label="Possible Attack" value={possibleAttack(event)} />
                  {event.confidence !== null && (
                    <FieldRow
                      label="Confidence"
                      value={formatPercent(event.confidence)}
                      mono
                    />
                  )}
                </dl>
              </section>

              {/* ── Section: Detection reason ──────────────────────────── */}
              {guessesOf(event).some((g) => g.probability >= MIN_SHOWN_CHANCE) && (
                <section aria-label="Which attack might it be">
                  <SectionHeading>Which attack might it be?</SectionHeading>
                  <div className={styles.featuresWrapper}>
                    <p className={styles.featuresLabel}>
                      SecureNet’s best guesses for this abnormal traffic (most likely first)
                    </p>
                    <table className={styles.featuresTable}>
                      <thead>
                        <tr>
                          <th scope="col" className={styles.fth}>Possible attack</th>
                          <th scope="col" className={styles.fth}>Chance</th>
                        </tr>
                      </thead>
                      <tbody>
                        {guessesOf(event).filter((g) => g.probability >= MIN_SHOWN_CHANCE).map((g) => (
                          <tr key={g.label}>
                            <td className={styles.ftd}>{guessLabel(g.label)}</td>
                            <td className={styles.ftdMono}>{percent(g.probability)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}

              {(event.detectionReason || event.contributingFeatures.length > 0) && (
                <section aria-label="Detection reason">
                  <SectionHeading>Why was this detected?</SectionHeading>

                  {event.detectionReason && (
                    <p className={styles.reason}>{plainReason(event.detectionReason)}</p>
                  )}

                  {event.contributingFeatures.length > 0 && (
                    <div className={styles.featuresWrapper}>
                      <p className={styles.featuresLabel}>
                        Top contributing features
                      </p>
                      <table className={styles.featuresTable}>
                        <thead>
                          <tr>
                            <th scope="col" className={styles.fth}>Feature</th>
                            <th scope="col" className={styles.fth}>Value</th>
                            <th scope="col" className={styles.fth}>Contribution</th>
                          </tr>
                        </thead>
                        <tbody>
                          {event.contributingFeatures.map((f, i) => (
                            <tr key={i} className={styles.ftr}>
                              <td className={styles.ftd}>{f.name}</td>
                              <td className={styles.ftdMono}>
                                {typeof f.value === 'number'
                                  ? f.value.toFixed(4)
                                  : String(f.value)}
                              </td>
                              <td className={styles.ftdMono}>
                                <span
                                  style={{
                                    color:
                                      f.contribution > 0
                                        ? 'var(--color-severity-high)'
                                        : 'var(--color-severity-info)',
                                  }}
                                >
                                  {f.contribution > 0 ? '+' : ''}
                                  {f.contribution.toFixed(3)}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </section>
              )}

              {/* ── Section: Flow statistics ───────────────────────────── */}
              {(event.bytesSent !== null ||
                event.bytesReceived !== null ||
                event.packetsSent !== null ||
                event.packetsReceived !== null ||
                event.flowDurationMs !== null) && (
                <section aria-label="Flow statistics">
                  <SectionHeading>Flow Statistics</SectionHeading>
                  <dl className={styles.fieldList}>
                    {event.bytesSent !== null && (
                      <FieldRow label="Bytes Sent"     value={formatBytes(event.bytesSent)}         mono />
                    )}
                    {event.bytesReceived !== null && (
                      <FieldRow label="Bytes Received" value={formatBytes(event.bytesReceived)}     mono />
                    )}
                    {event.packetsSent !== null && (
                      <FieldRow label="Packets Sent"   value={formatNumber(event.packetsSent)}      mono />
                    )}
                    {event.packetsReceived !== null && (
                      <FieldRow label="Packets Recv"   value={formatNumber(event.packetsReceived)}  mono />
                    )}
                    {event.flowDurationMs !== null && (
                      <FieldRow label="Flow Duration"  value={`${event.flowDurationMs} ms`}         mono />
                    )}
                  </dl>
                </section>
              )}

              {/* ── Actions (admin only; hidden for SecureNet users) ───── */}
              {(onResolve || onMarkFalsePositive) && (
                <section aria-label="Event actions" className={styles.actionsSection}>
                  <SectionHeading>Actions</SectionHeading>
                  <div className={styles.actionButtons}>
                    <button
                      className={styles.resolveButton}
                      onClick={handleResolve}
                      disabled={event.state === 'resolved' || !onResolve}
                      aria-label="Mark event as resolved"
                    >
                      Mark Resolved
                    </button>
                    <button
                      className={styles.fpButton}
                      onClick={handleFalsePositive}
                      disabled={event.state === 'false_positive' || !onMarkFalsePositive}
                      aria-label="Mark event as false positive"
                    >
                      False Positive
                    </button>
                  </div>
                </section>
              )}
            </>
          )}
        </div>
      </aside>
    </>
  );
}
