/**
 * SecureNet — Model Service
 *
 * Optional detection models: Isolation Forest (stage 1) and/or XGBoost (stage 2).
 */

import { apiClient } from './apiClient';
import type { ModelInfo, FeatureImportance } from '../types/model.types';

/** GET /model/info */
export async function getModelInfo(): Promise<ModelInfo> {
  return apiClient.get<ModelInfo>('/model/info');
}

/** GET /model/feature-importance?stage=1|2&limit=N (stage 1 has none) */
export async function getFeatureImportance(
  stage: 1 | 2,
  limit = 20
): Promise<FeatureImportance[]> {
  return apiClient.get<FeatureImportance[]>(
    `/model/feature-importance?stage=${stage}&limit=${limit}`
  );
}

/** POST /model/reload — load model files from ML_MODELS_DIR (admin only). */
export async function reloadModels(): Promise<ModelInfo> {
  return apiClient.post<ModelInfo>('/model/reload', {});
}
