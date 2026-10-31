/**
 * SecureNet — ConnectionIndicator
 *
 * Shows the WebSocket live feed connection status in the TopBar.
 * Reads from the wsService singleton without triggering a connection —
 * the Dashboard page manages the actual connection.
 */

import { useEffect, useState } from 'react';
import { wsService } from '../../services/websocketService';
import type { WebSocketStatus } from '../../types/websocket.types';
import { cn } from '../../utils/cn';
import styles from './ConnectionIndicator.module.css';

const STATUS_CONFIG: Record<
  WebSocketStatus,
  { label: string; dotClass: string; visible: boolean }
> = {
  idle:         { label: 'Monitoring idle',         dotClass: 'dotIdle',         visible: false },
  connecting:   { label: 'Connecting…',             dotClass: 'dotConnecting',   visible: true  },
  connected:    { label: 'Live',                    dotClass: 'dotConnected',    visible: true  },
  disconnected: { label: 'Disconnected',            dotClass: 'dotDisconnected', visible: true  },
  reconnecting: { label: 'Reconnecting…',           dotClass: 'dotConnecting',   visible: true  },
  error:        { label: 'Connection error',        dotClass: 'dotError',        visible: true  },
};

export function ConnectionIndicator() {
  const [status, setStatus] = useState<WebSocketStatus>(wsService.getStatus());

  useEffect(() => {
    const unsub = wsService.onStatusChange(setStatus);
    return unsub;
  }, []);

  const config = STATUS_CONFIG[status];
  if (!config.visible) return null;

  return (
    <div
      className={styles.indicator}
      title={config.label}
      aria-label={`Monitor connection: ${config.label}`}
      role="status"
    >
      <span
        className={cn(styles.dot, styles[config.dotClass])}
        aria-hidden="true"
      />
      <span className={styles.label}>{config.label}</span>
    </div>
  );
}
