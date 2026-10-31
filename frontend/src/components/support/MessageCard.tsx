/**
 * SecureNet — MessageCard ("Send us a message")
 *
 * The signed-in user writes a subject + message; it is emailed to the
 * SecureNet team (the contact email). Replies go straight to the user's
 * own email address, and the user receives a copy.
 */

import { useState, type FormEvent } from 'react';
import { Send } from 'lucide-react';
import { Card } from '../common/Card';
import { useAuth } from '../../contexts/AuthContext';
import { sendSupportMessage } from '../../services/supportService';
import styles from './MessageCard.module.css';

const MAX_MESSAGE = 5000;

export function MessageCard() {
  const { user } = useAuth();
  const [subject, setSubject] = useState('');
  const [message, setMessage] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    if (subject.trim().length < 3) {
      setError('Please enter a subject (at least 3 characters).');
      return;
    }
    if (message.trim().length < 10) {
      setError('Please write a little more (at least 10 characters).');
      return;
    }
    setSending(true);
    try {
      const response = await sendSupportMessage(subject.trim(), message.trim());
      setSent(response.message);
      setSubject('');
      setMessage('');
    } catch (err) {
      setError(err instanceof Error && err.message ? err.message : 'Your message could not be sent. Please try again.');
    } finally {
      setSending(false);
    }
  }

  return (
    <Card padding="lg">
      <h3 className={styles.title}>Send us a message</h3>
      <p className={styles.intro}>
        Questions, problems or feedback? Write to the SecureNet team — we&apos;ll reply to your email.
      </p>

      {sent && (
        <div className={styles.success} role="status">
          {sent}{' '}
          <button type="button" className={styles.link} onClick={() => setSent(null)}>
            Send another message
          </button>
        </div>
      )}

      {!sent && (
        <form onSubmit={handleSubmit} className={styles.form} noValidate>
          <div className={styles.from}>
            <span className={styles.fromLabel}>From</span>
            <span className={styles.fromValue}>
              {user?.fullName}
            </span>
          </div>

          <label className={styles.label} htmlFor="support-subject">Subject</label>
          <input
            id="support-subject"
            className={styles.input}
            type="text"
            value={subject}
            maxLength={150}
            onChange={(e) => { setSubject(e.target.value); setError(null); }}
            placeholder="What is it about?"
            disabled={sending}
          />

          <label className={styles.label} htmlFor="support-message">Message</label>
          <textarea
            id="support-message"
            className={styles.textarea}
            value={message}
            maxLength={MAX_MESSAGE}
            rows={6}
            onChange={(e) => { setMessage(e.target.value); setError(null); }}
            placeholder="Write your message here…"
            disabled={sending}
          />
          <div className={styles.counter}>{message.length} / {MAX_MESSAGE}</div>

          {error && <p className={styles.error} role="alert">{error}</p>}

          <button type="submit" className={styles.send} disabled={sending}>
            <Send size={15} aria-hidden="true" />
            {sending ? 'Sending…' : 'Send message'}
          </button>
        </form>
      )}
    </Card>
  );
}
