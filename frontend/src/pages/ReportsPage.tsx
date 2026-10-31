/**
 * SecureNet — Reports Page
 *
 * Empty until an attack is detected. Then one box per day with attacks,
 * each with a download of that day's report (.txt or .pdf). The list
 * refreshes by itself when a new attack arrives over the live connection.
 */

import { useCallback } from 'react';
import { ShieldCheck } from 'lucide-react';
import { MainLayout } from '../components/layout/MainLayout';
import { PageHeader } from '../components/common/PageHeader';
import { LoadingState } from '../components/common/LoadingState';
import { ErrorState } from '../components/common/ErrorState';
import { EmptyState } from '../components/common/EmptyState';
import { DailyReportCard } from '../components/reports/DailyReportCard';
import { useAsyncData } from '../hooks/useAsyncData';
import { useWebSocketMessage } from '../hooks/useLiveMonitoring';
import { getDailyReports } from '../services/reportsService';
import { errorMessage } from '../utils/errors';
import styles from './ReportsPage.module.css';

export function ReportsPage() {
  const reports = useAsyncData(getDailyReports);
  const { refetch } = reports;
  const onAlert = useCallback(() => { void refetch(); }, [refetch]);
  useWebSocketMessage('alert', onAlert);

  return (
    <MainLayout title="Reports">
      <div className={styles.page}>
        <PageHeader
          title="Reports"
          description="A report is created automatically for every day an attack is detected. Download it as .txt or .pdf."
        />

        {reports.isLoading && <LoadingState message="Loading reports…" />}

        {reports.isError && (
          <ErrorState
            title="Unable to load reports"
            message={errorMessage(reports.error, 'Could not load reports. Please try again.')}
            onRetry={refetch}
          />
        )}

        {reports.data && reports.data.length === 0 && (
          <div className={styles.emptyCard}>
            <EmptyState
              icon={<ShieldCheck size={28} />}
              title="No attacks detected"
              description="Nothing has happened yet. When an attack is detected, that day's report appears here."
            />
          </div>
        )}

        {reports.data && reports.data.length > 0 && (
          <section className={styles.grid} aria-label="Daily reports">
            {reports.data.map((report) => (
              <DailyReportCard key={report.date} report={report} />
            ))}
          </section>
        )}
      </div>
    </MainLayout>
  );
}
