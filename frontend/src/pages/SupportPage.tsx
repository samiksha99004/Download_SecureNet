/**
 * SecureNet — Support Page
 *
 * What SecureNet is, how to use it, how to contact the SecureNet team
 * (details set by the admin) and a "Send us a message" box that emails the
 * team, plus the app version. Plain language only —
 * no technical details about models or tooling.
 */

import { MainLayout } from '../components/layout/MainLayout';
import { PageHeader } from '../components/common/PageHeader';
import { AboutCard } from '../components/support/AboutCard';
import { GuideCard } from '../components/support/GuideCard';
import { ContactCard } from '../components/support/ContactCard';
import { MessageCard } from '../components/support/MessageCard';
import styles from './SupportPage.module.css';

export function SupportPage() {
  return (
    <MainLayout title="Support">
      <div className={styles.page}>
        <PageHeader title="Support" description="What SecureNet does, how to use it and how to reach us." />

        <div className={styles.grid}>
          <AboutCard />
          <GuideCard />
        </div>

        <div className={styles.grid}>
          <ContactCard />
          <MessageCard />
        </div>

        <p className={styles.version}>SecureNet version {__APP_VERSION__}</p>
      </div>
    </MainLayout>
  );
}
