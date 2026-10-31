/**
 * SecureNet — AboutCard
 *
 * What the app is, in plain language for everyday users.
 */

import { Shield } from 'lucide-react';
import { Card } from '../common/Card';
import styles from './AboutCard.module.css';

const FEATURES: { title: string; text: string }[] = [
  {
    title: 'Watches your network',
    text: 'While the IDS is ON, SecureNet looks at the traffic on this computer’s network and learns what normal activity looks like.',
  },
  {
    title: 'Spots attacks',
    text: 'Unusual or harmful activity — such as flooding, password guessing or scanning — is flagged and given a severity: High, Medium or Low.',
  },
  {
    title: 'Alerts you instantly',
    text: 'You see an alert on screen (with an optional sound) the moment an attack is detected, and every registered user gets an email with the incident report attached.',
  },
  {
    title: 'Keeps a record',
    text: 'Every incident is saved in History, and a report is created for each day an attack happens, ready to download.',
  },
];

export function AboutCard() {
  return (
    <Card padding="lg">
      <div className={styles.header}>
        <div className={styles.logoMark} aria-hidden="true">
          <Shield size={22} />
        </div>
        <div>
          <h3 className={styles.title}>About SecureNet</h3>
          <p className={styles.subtitle}>Network intrusion detection for your computer and network</p>
        </div>
      </div>

      <div className={styles.body}>
        <p className={styles.description}>
          SecureNet keeps an eye on your network and warns you when something suspicious happens. It
          recognises attacks by how they behave, so it can catch threats it has never seen before — and it
          tells you right away, on screen and by email.
        </p>

        <div className={styles.featureList}>
          {FEATURES.map((f) => (
            <div key={f.title} className={styles.feature}>
              <span className={styles.featureDot} aria-hidden="true" />
              <div>
                <strong>{f.title}:</strong> {f.text}
              </div>
            </div>
          ))}
        </div>
      </div>
    </Card>
  );
}
