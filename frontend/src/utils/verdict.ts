/**
 * SecureNet — verdict wording
 *
 * The model's job is to say whether traffic is normal or abnormal. Which attack it
 * might be is only stage 2's guess, so it is always shown as a "possible attack".
 */

import type { AttackGuess, SecurityEvent } from '../types/security.types';

export const ABNORMAL_TRAFFIC = 'Abnormal traffic detected';
export const NORMAL_TRAFFIC = 'Normal traffic';

const BENIGN = new Set(['benign', 'normal']);

export function percent(p: number, digits = 0): string {
  return `${(p * 100).toFixed(digits)}%`;
}

/** Guesses worth showing (≥ 0.5 %), most likely first. */
export function guessesOf(event: Pick<SecurityEvent, 'attackGuesses'>): AttackGuess[] {
  return [...(event.attackGuesses ?? [])]
    .filter((g) => typeof g.probability === 'number' && g.probability >= 0.005)
    .sort((a, b) => b.probability - a.probability);
}

/** The model's best guess of which attack it might be, e.g. "DDoS (97%)". */
export function possibleAttack(
  event: Pick<SecurityEvent, 'attackType' | 'confidence' | 'attackGuesses'>,
): string {
  if (event.attackType) {
    return event.confidence != null ? `${event.attackType} (${percent(event.confidence)})` : event.attackType;
  }
  const guess = guessesOf(event).find((g) => !BENIGN.has(g.label.toLowerCase()));
  return guess ? `${guess.label} (${percent(guess.probability)}, unsure)` : 'Unknown';
}

/** Name shown for a stage-2 class in the guess table. */
export function guessLabel(label: string): string {
  return BENIGN.has(label.toLowerCase()) ? 'Benign — not an attack' : label;
}

/** Attacks below this chance are not shown (no tiny rows like "SQL Injection 0.3%"). */
export const MIN_SHOWN_CHANCE = 0.05;

export interface AttackChance {
  label: string;
  /** 0–1 */
  chance: number;
}

/** "What kind of attack could it be?" — the chance of each attack type.
 *  From every abnormal flow since the IDS was turned on (share of flows the model guessed as that
 *  attack); when there are none (e.g. right after a restart) from the latest alert's own guesses. */
export function attackChances(
  verdicts: { guesses: { label: string; flows: number; cancelled: boolean }[] } | null | undefined,
  latest: Pick<SecurityEvent, 'attackGuesses'> | null,
): { rows: AttackChance[]; basis: 'traffic' | 'latest' | null; total: number } {
  const attacks = (verdicts?.guesses ?? []).filter((g) => !g.cancelled);
  const total = attacks.reduce((sum, g) => sum + g.flows, 0);
  if (total > 0) {
    const rows = attacks
      .map((g) => ({ label: g.label === 'Unclassified' ? 'Unknown type' : g.label, chance: g.flows / total }))
      .filter((r) => r.chance >= MIN_SHOWN_CHANCE)
      .sort((a, b) => b.chance - a.chance);
    return { rows, basis: 'traffic', total };
  }
  if (latest) {
    const rows = guessesOf(latest)
      .filter((g) => !BENIGN.has(g.label.toLowerCase()) && g.probability >= MIN_SHOWN_CHANCE)
      .map((g) => ({ label: g.label, chance: g.probability }));
    if (rows.length) return { rows, basis: 'latest', total: 1 };
  }
  return { rows: [], basis: null, total: 0 };
}

/** Detection reason in plain words. Older alerts were stored with the model names
 *  ("Isolation Forest score … ; XGBoost: DoS (100%)"); people see the same plain wording as new ones. */
export function plainReason(reason: string | null | undefined): string | null {
  if (!reason) return null;
  return reason
    .replace(/Isolation Forest (?:anomaly )?score ([\d.]+) (?:is at or above|exceeded) (?:the )?threshold ([\d.]+)/i,
      'The traffic looked unusual: score $1 is at or above the alarm level $2')
    .replace(/;\s*XGBoost: Benign \((\d+%)\) - not an attack/i, '. A second check found normal traffic ($1 sure) - not an attack')
    .replace(/;\s*XGBoost: (.+?) \((\d+%)\)/i, '. Most likely attack: $1 ($2 sure)')
    .replace(/XGBoost classified flow as (.+?) \((\d+%)\)/i, 'Matches the pattern of $1 ($2 sure)')
    .replace(/Isolation Forest|XGBoost/gi, 'SecureNet');
}
