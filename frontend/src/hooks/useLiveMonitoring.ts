/**
 * SecureNet — Live Monitoring Hooks
 *
 * useLiveMonitoring()   – WebSocket status + rolling chart of anomaly scores
 * useWebSocketMessage() – subscribe a component to one message type
 *
 * The backend streams a `live_score` for every scored flow (throttled) and
 * an `alert` for every stored security event. No data is ever fabricated.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { wsService } from '../services/websocketService';
import type {
  LiveScorePayload,
  WebSocketMessage,
  WebSocketMessageType,
  WebSocketStatus,
} from '../types/websocket.types';
import type { LiveChartPoint } from '../types/security.types';

const MAX_CHART_POINTS = 120;

interface LiveMonitoringState {
  status: WebSocketStatus;
  chartData: LiveChartPoint[];
  lastScore: number | null;
  lastSeverity: string | null;
}

export function useLiveMonitoring() {
  const [state, setState] = useState<LiveMonitoringState>({
    status: wsService.getStatus(),
    chartData: [],
    lastScore: null,
    lastSeverity: null,
  });

  useEffect(() => {
    const unsubStatus = wsService.onStatusChange((status) => {
      setState((prev) => ({ ...prev, status }));
    });

    const unsubScore = wsService.on<LiveScorePayload>(
      'live_score',
      (message: WebSocketMessage<LiveScorePayload>) => {
        const { anomalyScore, severity, isAlert } = message.payload;
        const time = new Date(message.timestamp).toLocaleTimeString('en-GB');
        setState((prev) => ({
          ...prev,
          chartData: [
            ...prev.chartData,
            {
              time,
              score: anomalyScore,
              severity: severity as LiveChartPoint['severity'],
              isAlert: Boolean(isAlert),
            },
          ].slice(-MAX_CHART_POINTS),
          lastScore: anomalyScore,
          lastSeverity: severity,
        }));
      }
    );

    wsService.connect();

    return () => {
      unsubStatus();
      unsubScore();
    };
  }, []);

  const disconnect = useCallback(() => wsService.disconnect(), []);
  const reconnect = useCallback(() => wsService.reconnect(), []);

  return {
    ...state,
    disconnect,
    reconnect,
    isConnected: state.status === 'connected',
    isConnecting: state.status === 'connecting' || state.status === 'reconnecting',
  };
}

/** Run `handler` for every WebSocket message of `type` while mounted. */
export function useWebSocketMessage<T>(
  type: WebSocketMessageType,
  handler: (message: WebSocketMessage<T>) => void
): void {
  const handlerRef = useRef(handler);
  useEffect(() => {
    handlerRef.current = handler;
  }, [handler]);

  useEffect(() => {
    const unsubscribe = wsService.on<T>(type, (message) => handlerRef.current(message));
    wsService.connect();
    return unsubscribe;
  }, [type]);
}
