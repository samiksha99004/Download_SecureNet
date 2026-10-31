/**
 * SecureNet — DetectionTab
 *
 * Settings tab for anomaly detection configuration.
 * Loads current settings from the backend; saves via PUT.
 * Admin only; changes apply to the running IDS immediately.
 */

import { useCallback, useEffect, useState } from 'react';
import { useAsyncData } from '../../hooks/useAsyncData';
import { useToast } from '../common/Toast';
import { getDetectionSettings, updateDetectionSettings } from '../../services/settingsService';
import { getModelInfo } from '../../services/modelService';
import type { DetectionSettings } from '../../types/settings.types';
import { SettingsSection } from './SettingsSection';
import { SettingsField } from './SettingsField';
import { SaveBar } from './SaveBar';
import { LoadingState } from '../common/LoadingState';
import { ErrorState } from '../common/ErrorState';
import styles from './TabShared.module.css';
import { errorMessage } from '../../utils/errors';

type Preset = Exclude<DetectionSettings['sensitivity'], 'custom'>;

/** Without a tested threshold the presets are fixed values of θ. */
const PRESET_THRESHOLDS: Record<Preset, number> = { low: 0.6, medium: 0.5, high: 0.45 };
/** With a model that records its tested threshold, the presets sit around it (same as the backend). */
const PRESET_OFFSETS: Record<Preset, number> = { low: 0.05, medium: 0, high: -0.03 };

function presetThreshold(preset: Preset, tested: number | null): number {
  return tested !== null ? Math.round((tested + PRESET_OFFSETS[preset]) * 1e4) / 1e4 : PRESET_THRESHOLDS[preset];
}

export function DetectionTab() {
  const { showToast } = useToast();
  const { data, isLoading, isError, refetch } = useAsyncData(
    useCallback(() => getDetectionSettings(), [])
  );

  const model = useAsyncData(useCallback(() => getModelInfo(), []));
  const tested = model.data?.isolationForest?.testedThreshold ?? null;
  const inUse = model.data?.isolationForest?.threshold ?? null;

  const [local, setLocal] = useState<DetectionSettings | null>(null);
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    if (data) {
      setLocal(data);
      setIsDirty(false);
    }
  }, [data]);

  function update<K extends keyof DetectionSettings>(key: K, value: DetectionSettings[K]) {
    setLocal((prev) => {
      if (!prev) return prev;
      const next = { ...prev, [key]: value };
      if (key === 'sensitivity' && value !== 'custom') {
        next.anomalyThreshold = presetThreshold(value as Preset, tested);
      }
      if (key === 'anomalyThreshold') next.sensitivity = 'custom';
      return next;
    });
    setIsDirty(true);
  }

  async function handleSave() {
    if (!local) return;
    setIsSaving(true);
    try {
      await updateDetectionSettings(local);
      setIsDirty(false);
      showToast({ message: 'Detection settings saved.', variant: 'success' });
      void refetch();
      void model.refetch();
    } catch (err) {
      showToast({ message: errorMessage(err, 'Could not save.'), variant: 'error' });
    } finally {
      setIsSaving(false);
    }
  }

  function handleDiscard() {
    if (data) {
      setLocal(data);
      setIsDirty(false);
    }
  }

  if (isLoading) return <LoadingState message="Loading detection settings…" />;
  if (isError || !local) {
    return (
      <ErrorState
        title="Settings unavailable"
        message="Detection settings could not be loaded. Please try again."
        onRetry={refetch}
      />
    );
  }

  return (
    <div className={styles.tabContent}>
      <SettingsSection
        title="Anomaly Detection"
        description="Stage 1 — the Isolation Forest anomaly score (0–1) of every finished flow is compared with the threshold θ."
      >
        <SettingsField
          id="det-enabled"
          label="Enable Detection"
          hint="When off, the IDS keeps capturing traffic but does not score it."
          type="toggle"
          checked={local.enabled}
          onChange={(v) => update('enabled', v)}
        />
        <SettingsField
          id="det-sensitivity"
          label="Sensitivity Preset"
          hint={tested !== null
            ? `Follows the loaded model's tested threshold ${tested.toFixed(4)}: Medium = exactly that value, `
              + `Low ${presetThreshold('low', tested).toFixed(4)} (fewer alerts), High ${presetThreshold('high', tested).toFixed(4)}.`
              + (inUse !== null ? ` In use now: ${inUse.toFixed(4)}.` : '')
            : 'Sets the anomaly threshold: Low 0.60 · Medium 0.50 · High 0.45.'}
          type="select"
          value={local.sensitivity}
          onChange={(v) => update('sensitivity', v as DetectionSettings['sensitivity'])}
          options={[
            { value: 'low',    label: 'Low — fewer alerts' },
            { value: 'medium', label: 'Medium — balanced' },
            { value: 'high',   label: 'High — maximum sensitivity' },
            { value: 'custom', label: 'Custom' },
          ]}
        />
        <SettingsField
          id="det-threshold"
          label="Anomaly Threshold"
          hint="Flows whose anomaly score is at or above this value are flagged (0.0 – 1.0). Typing a value switches to Custom."
          type="number"
          value={local.anomalyThreshold}
          onChange={(v) => update('anomalyThreshold', parseFloat(v) || 0)}
          min={0}
          max={1}
          step={0.01}
        />
      </SettingsSection>

      <SettingsSection
        title="Stage 2 — XGBoost Classification"
        description="Control the attack-classification pipeline that runs after stage-1 flags a flow."
      >
        <SettingsField
          id="det-stage2"
          label="Enable XGBoost Stage 2"
          hint="When enabled, flagged flows are classified into attack categories."
          type="toggle"
          checked={local.stage2Enabled}
          onChange={(v) => update('stage2Enabled', v)}
        />
        <SettingsField
          id="det-stage2-confidence"
          label="Stage 2 Confidence Threshold"
          hint="Minimum XGBoost confidence to accept a classification (0.0 – 1.0)."
          type="number"
          value={local.stage2ConfidenceThreshold}
          onChange={(v) => update('stage2ConfidenceThreshold', parseFloat(v) || 0)}
          min={0}
          max={1}
          step={0.01}
          disabled={!local.stage2Enabled}
        />
      </SettingsSection>

      <SaveBar
        isDirty={isDirty}
        isSaving={isSaving}
        onSave={handleSave}
        onDiscard={handleDiscard}
      />
    </div>
  );
}
