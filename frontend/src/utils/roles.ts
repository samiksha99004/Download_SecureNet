/**
 * SecureNet — Roles
 *
 * Two roles: the Admin (configures the IDS) and SecureNet Users (monitor,
 * turn the IDS on/off, get alerts and reports). Accounts stored with the old
 * "analyst" / "viewer" roles are SecureNet Users.
 */

import type { UserRole } from '../types/auth.types';

export function isAdminRole(role: UserRole | undefined | null): boolean {
  return role === 'admin';
}

export function roleLabel(role: UserRole | undefined | null): string {
  return isAdminRole(role) ? 'Admin' : 'SecureNet User';
}
