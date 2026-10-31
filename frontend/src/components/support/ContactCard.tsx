/**
 * SecureNet — ContactCard ("Contact us")
 *
 * Website, phone, email and admin office location, as set by the admin in
 * Settings → System. Empty details are simply not shown.
 */

import type { ReactNode } from 'react';
import { Globe, Mail, MapPin, Phone } from 'lucide-react';
import { Card } from '../common/Card';
import { LoadingState } from '../common/LoadingState';
import { useAsyncData } from '../../hooks/useAsyncData';
import { getContactInfo } from '../../services/supportService';
import styles from './ContactCard.module.css';

interface Row {
  icon: ReactNode;
  label: string;
  value: string;
  href?: string;
}

export function ContactCard() {
  const { data, isLoading, isError } = useAsyncData(getContactInfo);

  const rows: Row[] = [];
  if (data?.website) {
    rows.push({ icon: <Globe size={16} />, label: 'Website', value: data.website.replace(/^https?:\/\//, ''), href: data.website });
  }
  if (data?.phone) {
    rows.push({ icon: <Phone size={16} />, label: 'Phone', value: data.phone, href: `tel:${data.phone.replace(/[^\d+]/g, '')}` });
  }
  if (data?.email) {
    rows.push({ icon: <Mail size={16} />, label: 'Email', value: data.email, href: `mailto:${data.email}` });
  }
  if (data?.address) {
    rows.push({ icon: <MapPin size={16} />, label: 'Admin office', value: data.address });
  }

  return (
    <Card padding="lg">
      <h3 className={styles.title}>Contact us</h3>
      <p className={styles.intro}>Need help or noticed something unusual? Get in touch with the SecureNet team.</p>

      {isLoading && <LoadingState message="Loading contact details…" />}
      {isError && <p className={styles.empty}>Contact details could not be loaded. Please try again later.</p>}
      {data && rows.length === 0 && <p className={styles.empty}>Contact details will be added soon.</p>}

      {rows.length > 0 && (
        <ul className={styles.list}>
          {rows.map((row) => (
            <li key={row.label} className={styles.row}>
              <span className={styles.icon} aria-hidden="true">{row.icon}</span>
              <div className={styles.text}>
                <span className={styles.label}>{row.label}</span>
                {row.href ? (
                  <a
                    className={styles.value}
                    href={row.href}
                    {...(row.label === 'Website' ? { target: '_blank', rel: 'noopener noreferrer' } : {})}
                  >
                    {row.value}
                  </a>
                ) : (
                  <span className={styles.value}>{row.value}</span>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
