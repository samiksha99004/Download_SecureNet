/**
 * SecureNet — AddWhitelistEntryModal
 *
 * Modal form for adding a new whitelist entry.
 * Validates IPv4 / CIDR for ip and cidr types.
 * Validates non-empty for port and protocol types.
 */

import { useEffect, useRef, useState } from 'react';
import { X } from 'lucide-react';
import type { WhitelistEntryType, CreateWhitelistEntryRequest } from '../../types/settings.types';
import { isValidIpAddress } from '../../utils/validation';
import styles from './AddWhitelistEntryModal.module.css';

interface AddWhitelistEntryModalProps {
  isOpen: boolean;
  isSaving: boolean;
  onConfirm: (req: CreateWhitelistEntryRequest) => void;
  onCancel: () => void;
}

const TYPE_OPTIONS: { value: WhitelistEntryType; label: string; hint: string }[] = [
  { value: 'ip',       label: 'IP Address',   hint: 'e.g. 192.168.1.100' },
  { value: 'cidr',     label: 'CIDR Range',   hint: 'e.g. 10.0.0.0/8' },
  { value: 'port',     label: 'Port',         hint: 'e.g. 443' },
  { value: 'protocol', label: 'Protocol',     hint: 'e.g. ICMP' },
];

export function AddWhitelistEntryModal({
  isOpen,
  isSaving,
  onConfirm,
  onCancel,
}: AddWhitelistEntryModalProps) {
  const [type, setType] = useState<WhitelistEntryType>('ip');
  const [value, setValue] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState<string | null>(null);
  const firstInputRef = useRef<HTMLSelectElement>(null);

  useEffect(() => {
    if (isOpen) {
      setType('ip');
      setValue('');
      setDescription('');
      setError(null);
      setTimeout(() => firstInputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onCancel();
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [isOpen, onCancel]);

  function validate(): boolean {
    const trimmed = value.trim();
    if (!trimmed) {
      setError('Value is required.');
      return false;
    }
    if (type === 'ip' || type === 'cidr') {
      if (!isValidIpAddress(trimmed)) {
        setError('Enter a valid IPv4 address or CIDR range (e.g. 192.168.1.0/24).');
        return false;
      }
    }
    if (type === 'port') {
      const port = parseInt(trimmed, 10);
      if (isNaN(port) || port < 1 || port > 65535) {
        setError('Enter a valid port number (1 – 65535).');
        return false;
      }
    }
    setError(null);
    return true;
  }

  function handleSubmit() {
    if (!validate()) return;
    onConfirm({
      type,
      value: value.trim(),
      description: description.trim() || undefined,
    });
  }

  if (!isOpen) return null;

  const currentHint = TYPE_OPTIONS.find((o) => o.value === type)?.hint ?? '';

  return (
    <div
      className={styles.overlay}
      onClick={(e) => { if (e.target === e.currentTarget) onCancel(); }}
      role="presentation"
    >
      <div
        className={styles.modal}
        role="dialog"
        aria-modal="true"
        aria-labelledby="wl-modal-title"
      >
        {/* Header */}
        <div className={styles.header}>
          <h2 id="wl-modal-title" className={styles.title}>Add Whitelist Entry</h2>
          <button className={styles.closeBtn} onClick={onCancel} aria-label="Close">
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className={styles.body}>
          {/* Type */}
          <div className={styles.fieldGroup}>
            <label htmlFor="wl-type" className={styles.label}>Entry Type</label>
            <select
              ref={firstInputRef}
              id="wl-type"
              className={styles.select}
              value={type}
              onChange={(e) => {
                setType(e.target.value as WhitelistEntryType);
                setValue('');
                setError(null);
              }}
            >
              {TYPE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>

          {/* Value */}
          <div className={styles.fieldGroup}>
            <label htmlFor="wl-value" className={styles.label}>Value</label>
            <input
              id="wl-value"
              type="text"
              className={styles.input}
              value={value}
              onChange={(e) => { setValue(e.target.value); setError(null); }}
              placeholder={currentHint}
              autoComplete="off"
            />
            {error
              ? <p className={styles.error}>{error}</p>
              : <p className={styles.hint}>{currentHint}</p>
            }
          </div>

          {/* Description */}
          <div className={styles.fieldGroup}>
            <label htmlFor="wl-desc" className={styles.label}>
              Description <span className={styles.optional}>(optional)</span>
            </label>
            <input
              id="wl-desc"
              type="text"
              className={styles.input}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="e.g. Internal scanner, monitoring host…"
            />
          </div>
        </div>

        {/* Footer */}
        <div className={styles.footer}>
          <button className={styles.cancelBtn} onClick={onCancel} disabled={isSaving}>
            Cancel
          </button>
          <button
            className={styles.addBtn}
            onClick={handleSubmit}
            disabled={isSaving}
            aria-busy={isSaving}
          >
            {isSaving ? 'Adding…' : 'Add Entry'}
          </button>
        </div>
      </div>
    </div>
  );
}
