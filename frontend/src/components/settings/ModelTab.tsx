/**
 * SecureNet — ModelTab
 *
 * Displays ML model information for both stages:
 *   Stage 1 — Isolation Forest (anomaly detection)
 *   Stage 2 — XGBoost (attack classification)
 *
 * Shows metrics only when the backend provides them.
 * Displays "Not available" for all null/missing values.
 * Never fabricates accuracy, confidence, or model metadata.
 */

import { useCallback, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { useAsyncData } from '../../hooks/useAsyncData';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../common/Toast';
import { errorMessage } from '../../utils/errors';
import { getModelInfo, reloadModels } from '../../services/modelService';
import type { IsolationForestInfo, XGBoostInfo, ModelStatus } from '../../types/model.types';
import { LoadingState } from '../common/LoadingState';
import { ErrorState } from '../common/ErrorState';
import { SettingsSection } from './SettingsSection';
import { formatDate, formatPercent, formatScore } from '../../utils/format';
import styles from './ModelTab.module.css';
import tabStyles from './TabShared.module.css';

// ── Helpers ───────────────────────────────────────────────────────────────────

function na(value: string | number | null | undefined): string {
  if (value === null || value === undefined) return 'Not available';
  if (typeof value === 'number') return String(value);
  return value;
}

function StatusPill({ status }: { status: ModelStatus }) {
  const map: Record<ModelStatus, { label: string; cls: string }> = {
    loaded:     { label: 'Loaded',     cls: styles.statusLoaded     },
    loading:    { label: 'Loading…',   cls: styles.statusLoading    },
    error:      { label: 'Error',      cls: styles.statusError      },
    not_loaded: { label: 'Not loaded', cls: styles.statusNotLoaded  },
  };
  const { label, cls } = map[status] ?? { label: status, cls: '' };
  return <span className={`${styles.statusPill} ${cls}`}>{label}</span>;
}

interface InfoRowProps {
  label: string;
  value: string | number | null | undefined;
  mono?: boolean;
}

function InfoRow({ label, value, mono }: InfoRowProps) {
  const display = value === null || value === undefined ? 'Not available' : String(value);
  return (
    <div className={styles.infoRow}>
      <dt className={styles.infoLabel}>{label}</dt>
      <dd className={mono ? styles.infoValueMono : styles.infoValue}>{display}</dd>
    </div>
  );
}

// ── Stage 1 ───────────────────────────────────────────────────────────────────

function IsolationForestCard({ info }: { info: IsolationForestInfo }) {
  return (
    <div className={styles.stageCard}>
      <div className={styles.stageHeader}>
        <div>
          <h3 className={styles.stageTitle}>Stage 1 — Isolation Forest</h3>
          <p className={styles.stageSubtitle}>Unsupervised anomaly detection</p>
        </div>
        <StatusPill status={info.status} />
      </div>

      <p className={styles.featureStatement}>
        {info.featureCount !== null
          ? `${info.featureCount} CICIDS2018 flow features`
          : 'CICIDS2018 flow features'} — scores how isolated each network flow is from normal traffic.
      </p>

      <dl className={styles.infoGrid}>
        <InfoRow label="Version"       value={info.version} mono />
        <InfoRow label="N Estimators"  value={na(info.nEstimators)} mono />
        <InfoRow label="Max Samples"   value={na(info.maxSamples)} mono />
        <InfoRow label="Contamination" value={info.contamination !== null ? formatScore(info.contamination, 4) : null} mono />
        <InfoRow label="Threshold in use" value={info.threshold !== null ? formatScore(info.threshold, 4) : null} mono />
        {info.testedThreshold !== null && (
          <InfoRow label="Tested threshold" value={formatScore(info.testedThreshold, 4)} mono />
        )}
        <InfoRow label="Trained At"    value={formatDate(info.trainedAt)} />
      </dl>

      {info.metrics ? (
        <div className={styles.metricsBlock}>
          <h4 className={styles.metricsTitle}>Performance Metrics</h4>
          <dl className={styles.infoGrid}>
            {info.metrics.rocAuc    !== null && <InfoRow label="ROC-AUC"   value={formatPercent(info.metrics.rocAuc)} mono />}
            {info.metrics.precision !== null && <InfoRow label="Precision" value={formatPercent(info.metrics.precision)} mono />}
            {info.metrics.recall    !== null && <InfoRow label="Recall"    value={formatPercent(info.metrics.recall)} mono />}
            {info.metrics.f1Score   !== null && <InfoRow label="F1 Score"  value={formatPercent(info.metrics.f1Score)} mono />}
          </dl>
        </div>
      ) : (
        <p className={styles.metricsUnavailable}>
          Evaluation metrics are not stored with the model files.
        </p>
      )}
    </div>
  );
}

// ── Stage 2 ───────────────────────────────────────────────────────────────────

function XGBoostCard({ info }: { info: XGBoostInfo }) {
  return (
    <div className={styles.stageCard}>
      <div className={styles.stageHeader}>
        <div>
          <h3 className={styles.stageTitle}>Stage 2 — XGBoost</h3>
          <p className={styles.stageSubtitle}>Attack-type classification</p>
        </div>
        <StatusPill status={info.status} />
      </div>

      <p className={styles.featureStatement}>
        {info.featureCount !== null
          ? `${info.featureCount}-feature model`
          : 'CICIDS2018 flow features'} — classifies flagged flows into specific attack categories.
      </p>

      <dl className={styles.infoGrid}>
        <InfoRow label="Version"       value={info.version} mono />
        <InfoRow label="N Estimators"  value={na(info.nEstimators)} mono />
        <InfoRow label="Max Depth"     value={na(info.maxDepth)} mono />
        <InfoRow label="Learning Rate" value={info.learningRate !== null ? formatScore(info.learningRate, 4) : null} mono />
        <InfoRow label="Trained At"    value={formatDate(info.trainedAt)} />
      </dl>

      {info.supportedAttackClasses.length > 0 && (
        <div className={styles.classesBlock}>
          <h4 className={styles.metricsTitle}>Supported Attack Classes</h4>
          <div className={styles.classPills}>
            {info.supportedAttackClasses.map((cls) => (
              <span key={cls} className={styles.classPill}>{cls}</span>
            ))}
          </div>
        </div>
      )}

      {info.metrics ? (
        <div className={styles.metricsBlock}>
          <h4 className={styles.metricsTitle}>Overall Performance (tested)</h4>
          {info.metrics.evaluation && <p className={styles.featureStatement}>{info.metrics.evaluation}.</p>}
          <dl className={styles.infoGrid}>
            <InfoRow label="Accuracy"    value={info.metrics.accuracy   !== null ? formatPercent(info.metrics.accuracy) : null} mono />
            <InfoRow label="Macro F1"    value={info.metrics.macroF1    !== null ? formatPercent(info.metrics.macroF1) : null} mono />
            <InfoRow label="Weighted F1" value={info.metrics.weightedF1 !== null ? formatPercent(info.metrics.weightedF1) : null} mono />
          </dl>

          {info.metrics.perClassMetrics.length > 0 && (
            <>
              <h4 className={`${styles.metricsTitle} ${styles.metricsTitleSpaced}`}>
                Per-Class Metrics
              </h4>
              <div className={styles.tableWrapper}>
                <table className={styles.perClassTable}>
                  <thead>
                    <tr>
                      <th className={styles.pth}>Class</th>
                      <th className={styles.pth}>Precision</th>
                      <th className={styles.pth}>Recall</th>
                      <th className={styles.pth}>F1</th>
                      <th className={styles.pth}>Support</th>
                    </tr>
                  </thead>
                  <tbody>
                    {info.metrics.perClassMetrics.map((m) => (
                      <tr key={m.className} className={styles.ptr}>
                        <td className={styles.ptd}>{m.className}</td>
                        <td className={styles.ptdNum}>{m.precision !== null ? formatPercent(m.precision) : 'N/A'}</td>
                        <td className={styles.ptdNum}>{m.recall    !== null ? formatPercent(m.recall) : 'N/A'}</td>
                        <td className={styles.ptdNum}>{m.f1Score   !== null ? formatPercent(m.f1Score) : 'N/A'}</td>
                        <td className={styles.ptdNum}>{m.support   !== null ? m.support.toLocaleString() : 'N/A'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      ) : (
        <p className={styles.metricsUnavailable}>
          Evaluation metrics are not stored with the model files.
        </p>
      )}
    </div>
  );
}

// ── Main export ───────────────────────────────────────────────────────────────

export function ModelTab() {
  const { data, isLoading, isError, refetch } = useAsyncData(
    useCallback(() => getModelInfo(), [])
  );
  const { user } = useAuth();
  const { showToast } = useToast();
  const [reloading, setReloading] = useState(false);

  async function handleReload() {
    setReloading(true);
    try {
      await reloadModels();
      showToast({ message: 'Models loaded.', variant: 'success' });
    } catch (err) {
      showToast({ message: errorMessage(err, 'Could not load models.'), variant: 'error' });
    } finally {
      setReloading(false);
      void refetch();
    }
  }

  if (isLoading) return <LoadingState message="Loading model information…" />;
  if (isError || !data) {
    return (
      <ErrorState
        title="Model information unavailable"
        message="Model information could not be loaded. Please try again."
        onRetry={refetch}
      />
    );
  }

  return (
    <div className={tabStyles.tabContent}>
      <SettingsSection
        title="ML Detection Pipeline"
        description="Two-stage pipeline: unsupervised anomaly detection (Stage 1) followed by supervised attack classification (Stage 2). Either stage — or both — can be used."
      >
        <p className={styles.pipelineNote}>
          Live TCP/UDP/ICMP flows are converted into CICIDS2018 flow features. Stage 1 (Isolation
          Forest) flags flows whose anomaly score exceeds the threshold; Stage 2 (XGBoost) assigns an
          attack category. Model files are read from the backend&apos;s <code>models/</code> folder; with no
          model loaded the IDS only captures and counts traffic.
        </p>
        {user?.role === 'admin' && (
          <button
            type="button"
            className={styles.reloadButton}
            onClick={() => void handleReload()}
            disabled={reloading}
          >
            <RefreshCw size={14} aria-hidden="true" />
            {reloading ? 'Loading models…' : 'Load / reload models'}
          </button>
        )}
        {data.lastRefreshedAt && (
          <p className={styles.refreshedAt}>
            Last refreshed: {formatDate(data.lastRefreshedAt)}
          </p>
        )}
      </SettingsSection>

      {data.isolationForest ? (
        <IsolationForestCard info={data.isolationForest} />
      ) : (
        <div className={styles.stageCard}>
          <div className={styles.stageHeader}>
            <h3 className={styles.stageTitle}>Stage 1 — Isolation Forest</h3>
          </div>
          <p className={styles.metricsUnavailable}>Not available</p>
        </div>
      )}

      {data.xgboost ? (
        <XGBoostCard info={data.xgboost} />
      ) : (
        <div className={styles.stageCard}>
          <div className={styles.stageHeader}>
            <h3 className={styles.stageTitle}>Stage 2 — XGBoost</h3>
          </div>
          <p className={styles.metricsUnavailable}>Not available</p>
        </div>
      )}
    </div>
  );
}
