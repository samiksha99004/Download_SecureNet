/**
 * SecureNet — browser alert channels (desktop notifications + alert sound)
 */

export type DesktopPermission = NotificationPermission | 'unsupported';

export function desktopPermission(): DesktopPermission {
  return typeof Notification === 'undefined' ? 'unsupported' : Notification.permission;
}

/** Ask for desktop-notification permission (call from a click handler). */
export async function requestDesktopNotifications(): Promise<DesktopPermission> {
  if (typeof Notification === 'undefined') return 'unsupported';
  if (Notification.permission === 'default') {
    try {
      return await Notification.requestPermission();
    } catch {
      return Notification.permission;
    }
  }
  return Notification.permission;
}

/** Show an OS notification; clicking it focuses the app and runs `onClick`. */
export function showDesktopNotification(title: string, body: string, tag: string, onClick?: () => void): void {
  if (desktopPermission() !== 'granted') return;
  try {
    const notification = new Notification(title, { body, tag, icon: '/favicon.svg', requireInteraction: false });
    notification.onclick = () => {
      window.focus();
      onClick?.();
      notification.close();
    };
  } catch {
    // Some browsers only allow notifications from a service worker
  }
}

let audioContext: AudioContext | null = null;

/** Short two-tone alert sound (Web Audio — no audio file needed). */
export function playAlertSound(severity: string): void {
  try {
    const Ctor = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!Ctor) return;
    audioContext ??= new Ctor();
    if (audioContext.state === 'suspended') void audioContext.resume();
    const ctx = audioContext;
    const tones = severity === 'high' ? [880, 660, 880] : [740, 560];
    tones.forEach((freq, i) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      const start = ctx.currentTime + i * 0.16;
      osc.type = 'sine';
      osc.frequency.value = freq;
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(0.18, start + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.14);
      osc.connect(gain).connect(ctx.destination);
      osc.start(start);
      osc.stop(start + 0.15);
    });
  } catch {
    // Audio blocked until the user interacts with the page — ignore
  }
}
