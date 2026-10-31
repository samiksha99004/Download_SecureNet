import { readFileSync } from 'node:fs';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// App version shown on the Support page (single source: package.json)
const { version } = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf-8')) as { version: string };

// The dashboard must not be framed by another site (clickjacking), sniffed or leak its
// address. Vite already refuses unknown Host names (DNS rebinding) and foreign CORS origins.
const SECURITY_HEADERS = {
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
};

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: 'localhost',          // this computer only — never the local network
    headers: SECURITY_HEADERS,
  },
  preview: {
    host: 'localhost',
    headers: SECURITY_HEADERS,
  },
  define: {
    __APP_VERSION__: JSON.stringify(version),
  },
  build: {
    // Raise chunk size warning threshold — Recharts + lucide-react are large
    // but expected for this application. Consider code splitting in production.
    chunkSizeWarningLimit: 800,
  },
});
