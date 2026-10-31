/**
 * SecureNet — 404 Not Found Page
 */

import { Link } from 'react-router-dom';

export function NotFoundPage() {
  return (
    <main
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100dvh',
        padding: '2rem',
        fontFamily: 'var(--font-body)',
        textAlign: 'center',
        gap: '1rem',
      }}
    >
      <h1 style={{ fontFamily: 'var(--font-heading)', fontSize: '3rem', color: 'var(--color-text)' }}>
        404
      </h1>
      <p style={{ color: 'var(--color-text-muted)' }}>
        The page you are looking for does not exist.
      </p>
      <Link
        to="/dashboard"
        style={{
          padding: '0.5rem 1.25rem',
          background: 'var(--color-peach-dark)',
          color: 'var(--color-on-accent)',
          borderRadius: 'var(--radius-md)',
          fontWeight: 500,
          textDecoration: 'none',
        }}
      >
        Go to Dashboard
      </Link>
    </main>
  );
}
