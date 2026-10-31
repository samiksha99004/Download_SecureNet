/**
 * SecureNet — Dashboard Page
 *
 * Primary monitoring screen.
 *
 * Layout:
 *   Row 1: IDS Control Widget (ON/OFF, monitoring status, incident details)
 *   Row 2: 5 KPI cards
 *   Row 3: Host Status | Security Summary | Protocol Distribution
 *   Row 4: Live Anomaly Chart (full width)
 *   Row 5: Detection Reason | Top Sources
 *   Row 6: Recent Events table (full width)
 *
 * All data fetched from services — no hardcoded values.
 * Components show loading/empty/error states appropriately.
 *
 * While the IDS is OFF the dashboard shows no values at all (every card says
 * "IDS is off" and only the IDS status is polled); past events stay in
 * History and Reports. Turning it ON loads everything again.
 */

import { useCallback, useEffect, useRef } from 'react';
import {
  Activity,
  AlertTriangle,
  ShieldAlert,
} from 'lucide-react';
import { MainLayout } from '../components/layout/MainLayout';
import { IDSControlWidget } from '../components/dashboard/IDSControlWidget';
import { KPICard } from '../components/common/KPICard';
import { HostStatusCard } from '../components/dashboard/HostStatusCard';
import { DetectionReasonCard } from '../components/dashboard/DetectionReasonCard';
import { ProtocolDistributionCard } from '../components/dashboard/ProtocolDistributionCard';
import { TopSourcesCard } from '../components/dashboard/TopSourcesCard';
import { TrafficVerdictCard } from '../components/dashboard/TrafficVerdictCard';
import { RecentEventsTable } from '../components/dashboard/RecentEventsTable';
import { AttackTrendCard } from '../components/dashboard/AttackTrendCard';
import { SessionStatsCard } from '../components/dashboard/SessionStatsCard';
import { useAsyncData } from '../hooks/useAsyncData';
import { useWebSocketMessage } from '../hooks/useLiveMonitoring';
import {
  getDashboardSummary,
  getHostStatus,
  getProtocolDistribution,
  getTopSources,
} from '../services/dashboardService';
import { getIDSStatus } from '../services/idsService';
import { formatNumber } from '../utils/format';
import styles from './DashboardPage.module.css';

const POLL_INTERVAL_MS = 15_000;

export function DashboardPage() {
  // ── Data fetching ───────────────────────────────────────────────────────────
  const summary = useAsyncData(useCallback(() => getDashboardSummary(), []));
  const host = useAsyncData(useCallback(() => getHostStatus(), []));
  const protocol = useAsyncData(useCallback(() => getProtocolDistribution(), []));
  const sources = useAsyncData(useCallback(() => getTopSources(5), []));
  const idsStatus = useAsyncData(useCallback(() => getIDSStatus(), []));

  // IDS OFF (known) → no live values anywhere on the dashboard
  const idsOff = idsStatus.data !== null && !idsStatus.data.enabled;
  const idsPending = idsStatus.data === null && idsStatus.isLoading;

  // Latest "refresh everything" callback, kept in a ref for timers / socket events
  const refetchAll = useRef<() => void>(() => {});
  useEffect(() => {
    refetchAll.current = () => {
      void idsStatus.refetch();
      if (idsOff) return; // nothing else is shown while the IDS is off
      void summary.refetch();
      void host.refetch();
      void protocol.refetch();
      void sources.refetch();
    };
  });

  // IDS just turned ON: load fresh values straight away
  const wasOff = useRef(idsOff);
  useEffect(() => {
    if (wasOff.current && !idsOff) refetchAll.current();
    wasOff.current = idsOff;
  }, [idsOff]);

  // Periodic refresh (keeps host metrics and counters current)
  useEffect(() => {
    const interval = setInterval(() => refetchAll.current(), POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, []);

  // Refresh immediately when the backend reports a new alert / status change
  // (debounced so an attack burst does not flood the API).
  const debounceTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const scheduleRefresh = useCallback(() => {
    if (debounceTimer.current) return;
    debounceTimer.current = setTimeout(() => {
      debounceTimer.current = null;
      refetchAll.current();
    }, 1000);
  }, []);
  useEffect(() => () => {
    if (debounceTimer.current) clearTimeout(debounceTimer.current);
  }, []);
  useWebSocketMessage('alert', scheduleRefresh);
  const refetchIds = idsStatus.refetch;
  useWebSocketMessage('system_status', useCallback(() => void refetchIds(), [refetchIds]));

  const s = idsOff ? null : summary.data;
  const kpiLoading = idsPending || (!idsOff && summary.isLoading);
  const kpiValue = (v: string | null) => (idsOff ? '—' : v);

  // The highest-scoring recent event drives the Detection Reason card.
  const topRecentEvent = s?.recentEvents.length
    ? s.recentEvents.reduce((best, e) => (e.anomalyScore > best.anomalyScore ? e : best))
    : null;

  // Latest unresolved medium/high event for the IDS widget
  const latestAbnormalEvent =
    s?.recentEvents.find((e) => e.state === 'active') ?? null;

  return (
    <MainLayout title="Dashboard" greet>
      <div className={styles.page}>

        {/* ── IDS Control Widget ──────────────────────────────────────────── */}
        <IDSControlWidget
          idsStatus={idsStatus.data}
          latestEvent={latestAbnormalEvent}
          isLoading={idsStatus.isLoading}
          onStatusChange={() => refetchAll.current()}
        />

        {/* ── Verdict tables: normal vs abnormal + the model's attack guesses ── */}
        <section aria-label="Traffic verdict">
          <TrafficVerdictCard
            verdicts={idsStatus.data?.verdicts}
            mlLoaded={idsStatus.data?.mlLoaded ?? false}
            idsOff={idsOff}
          />
        </section>

        {/* ── Attack trend over time ───────────────────────────────────────── */}
        <section aria-label="Attack trend">
          <AttackTrendCard trend={idsStatus.data?.verdicts?.trend} idsOff={idsOff} />
        </section>

        {/* ── Monitoring session summary ───────────────────────────────────── */}
        <section aria-label="Monitoring session">
          <SessionStatsCard idsStatus={idsStatus.data ?? null} idsOff={idsOff} />
        </section>

        {/* ── Row 1: KPI Cards ─────────────────────────────────────────────── */}
        <section
          className={styles.kpiGrid}
          aria-label="Key security metrics"
        >
          <KPICard
            title="Active Flows"
            value={kpiValue(s ? formatNumber(s.activeFlows) : null)}
            icon={<Activity size={16} />}
            accent="info"
            isLoading={kpiLoading}
          />
          <KPICard
            title="Anomalies — Last 1 Hour"
            value={kpiValue(s ? formatNumber(s.anomaliesLastHour) : null)}
            icon={<AlertTriangle size={16} />}
            accent="medium"
            isLoading={kpiLoading}
          />
          <KPICard
            title="High Severity"
            value={kpiValue(s ? formatNumber(s.highSeverityCount) : null)}
            icon={<ShieldAlert size={16} />}
            accent="high"
            isLoading={kpiLoading}
          />
        </section>

        {/* ── Row 2: Status cards ──────────────────────────────────────────── */}
        <section className={styles.statusGrid} aria-label="System status">
          <HostStatusCard
            data={host.data}
            isLoading={idsPending || host.isLoading}
            isError={host.isError}
            onRetry={host.refetch}
            idsOff={idsOff}
          />
          <ProtocolDistributionCard
            data={protocol.data}
            isLoading={idsPending || protocol.isLoading}
            isError={protocol.isError}
            onRetry={protocol.refetch}
            idsOff={idsOff}
          />
        </section>

        {/* ── Row 3: Detection reason + Top sources ────────────────────────── */}
        <section className={styles.detailGrid} aria-label="Detection details">
          <DetectionReasonCard
            reason={topRecentEvent?.detectionReason ?? null}
            features={topRecentEvent?.contributingFeatures ?? []}
            attackType={topRecentEvent?.attackType ?? null}
            confidence={topRecentEvent?.confidence ?? null}
            idsOff={idsOff}
          />
          <TopSourcesCard
            data={sources.data ?? []}
            isLoading={idsPending || sources.isLoading}
            isError={sources.isError}
            onRetry={sources.refetch}
            idsOff={idsOff}
          />
        </section>

        {/* ── Row 5: Recent events ─────────────────────────────────────────── */}
        <section aria-label="Recent security events">
          <RecentEventsTable
            events={s?.recentEvents ?? []}
            isLoading={idsPending || summary.isLoading}
            idsOff={idsOff}
          />
        </section>

      </div>
    </MainLayout>
  );
}
