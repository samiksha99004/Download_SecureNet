/**
 * SecureNet — ML Model Information Types
 *
 * Reflects the two-stage detection pipeline:
 *   Stage 1 — Isolation Forest (anomaly detection)
 *   Stage 2 — XGBoost (attack classification)
 */

export type ModelStatus = 'loaded' | 'loading' | 'error' | 'not_loaded';

// ── Stage 1: Isolation Forest ─────────────────────────────────────────────────

export interface IsolationForestInfo {
  status: ModelStatus;
  version: string | null;
  nEstimators: number | null;
  maxSamples: number | null;
  contamination: number | null;
  /** threshold in use now (sensitivity preset or custom) */
  threshold: number | null;
  /** the threshold the model was tested with (null for models that don't record one) */
  testedThreshold: number | null;
  featureCount: number | null;
  featureNames: string[];
  trainedAt: string | null;   // ISO 8601
  metrics: IsolationForestMetrics | null;
}

export interface IsolationForestMetrics {
  rocAuc: number | null;
  precision: number | null;
  recall: number | null;
  f1Score: number | null;
}

// ── Stage 2: XGBoost ─────────────────────────────────────────────────────────

export interface XGBoostInfo {
  status: ModelStatus;
  version: string | null;
  nEstimators: number | null;
  maxDepth: number | null;
  learningRate: number | null;
  featureCount: number | null;
  featureNames: string[];
  supportedAttackClasses: string[];
  trainedAt: string | null;   // ISO 8601
  metrics: XGBoostMetrics | null;
}

export interface XGBoostMetrics {
  /** what the numbers were measured on */
  evaluation: string | null;
  testRows: number | null;
  accuracy: number | null;
  macroF1: number | null;
  weightedF1: number | null;
  perClassMetrics: PerClassMetric[];
}

export interface PerClassMetric {
  className: string;
  precision: number | null;
  recall: number | null;
  f1Score: number | null;
  support: number | null;
}

// ── Combined Model Info ───────────────────────────────────────────────────────

export interface ModelInfo {
  isolationForest: IsolationForestInfo | null;
  xgboost: XGBoostInfo | null;
  lastRefreshedAt: string | null;  // ISO 8601
}

// ── Feature Importance ────────────────────────────────────────────────────────

export interface FeatureImportance {
  featureName: string;
  importanceScore: number;
  rank: number;
}
