/**
 * SecureNet — Application Entry Point
 */

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

// Global styles must be imported before App
import './styles/globals.css';

import App from './App';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import { applyTheme, getTheme } from './utils/theme';

applyTheme(getTheme());

// Started successfully: allow index.html's one automatic retry again next time
try {
  sessionStorage.removeItem('sn_boot_retry');
} catch {
  // storage blocked
}

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Root element #root not found in index.html');
}

createRoot(rootElement).render(
  <StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </StrictMode>
);
