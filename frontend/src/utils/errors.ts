/**
 * SecureNet — error helpers
 */

/** Human-readable message for any thrown value (API errors carry the server's message). */
export function errorMessage(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback;
}
