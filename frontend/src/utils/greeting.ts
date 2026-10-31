/**
 * SecureNet — time-of-day greeting ("Good morning, Asha").
 * Morning 05:00–11:59, afternoon 12:00–16:59, evening 17:00–04:59 (local time).
 * useGreeting() re-checks every minute, so the greeting changes on its own.
 */

import { useEffect, useState } from 'react';

export function greetingFor(date: Date): string {
  const hour = date.getHours();
  if (hour >= 5 && hour < 12) return 'Good morning';
  if (hour >= 12 && hour < 17) return 'Good afternoon';
  return 'Good evening';
}

export function useGreeting(): string {
  const [greeting, setGreeting] = useState(() => greetingFor(new Date()));
  useEffect(() => {
    const timer = setInterval(() => setGreeting(greetingFor(new Date())), 60_000);
    return () => clearInterval(timer);
  }, []);
  return greeting;
}
