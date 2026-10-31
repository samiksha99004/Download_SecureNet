/**
 * SecureNet — GuideCard
 *
 * "How to use SecureNet": the everyday steps, in plain language.
 */

import { Card } from '../common/Card';
import styles from './GuideCard.module.css';

const STEPS: { title: string; text: string }[] = [
  {
    title: 'Sign in safely',
    text: 'Enter your email and password, then the 6-digit code we email you. The code works for 5 minutes; if it does not arrive, press “Resend code” (and check your spam folder).',
  },
  {
    title: 'Turn the IDS on',
    text: 'On the Dashboard, press the ON/OFF button. While it is ON, SecureNet watches your network. If you shut down the computer while it is ON, it turns itself back on when you start the computer and a desktop notice says "SecureNet is on and is monitoring."',
  },
  {
    title: 'Get alerted',
    text: 'When an attack is detected an alert appears on screen, the bell shows it, and you receive an email with the report.',
  },
  {
    title: 'Look into an incident',
    text: 'Open History (or “View incident” on an alert) to see when it happened, where it came from and why it was flagged.',
  },
  {
    title: 'Download reports',
    text: 'Reports lists every day that had attacks. Download that day’s report as .txt or .pdf.',
  },
  {
    title: 'Make it yours',
    text: 'In Settings choose the dark or peach theme and turn notifications or their sound on or off. On Account you can change your name, phone number, email or password (each confirmed with a code sent to your email).',
  },
];

export function GuideCard() {
  return (
    <Card padding="lg">
      <h3 className={styles.title}>How to use SecureNet</h3>
      <ol className={styles.steps}>
        {STEPS.map((step, index) => (
          <li key={step.title} className={styles.step}>
            <span className={styles.number} aria-hidden="true">{index + 1}</span>
            <div>
              <strong className={styles.stepTitle}>{step.title}</strong>
              <p className={styles.stepText}>{step.text}</p>
            </div>
          </li>
        ))}
      </ol>
      <p className={styles.note}>
        Settings such as detection sensitivity and trusted addresses are managed by your SecureNet admin.
      </p>
    </Card>
  );
}
