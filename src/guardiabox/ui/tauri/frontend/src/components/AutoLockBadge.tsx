/**
 * Live countdown to auto-lock, rendered in the dashboard header.
 *
 * Audit B P1-3 / E P0-5 finding: `useAutoLock` ticked at 1 Hz but no
 * UI surfaced the remaining time, so the user got logged out without
 * warning -- 1Password / Bitwarden display "Auto-lock dans MM:SS"
 * persistently. This component reads `expiresAtMsAtom` directly,
 * recomputes `remainingMs` at 1 Hz via `setInterval`, and switches
 * to amber + an `aria-live` warning when `remaining < 60_000`.
 *
 * Sliding TTL on the server (audit B P1-4): every authenticated
 * request resets the server-side TTL; the frontend slide is
 * deferred to ε-15 (out of Phase α scope). For now the badge shows
 * the conservative client-side countdown -- on activity it updates
 * once the next response carries a refreshed expiresAtMs.
 */

import { cn } from "@/lib/utils";
import { expiresAtMsAtom } from "@/stores/lock";
import { useAtomValue } from "jotai";
import { TimerReset } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

const WARN_THRESHOLD_MS = 60_000;

function formatRemaining(ms: number): string {
  if (ms <= 0) {
    return "00:00";
  }
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

export function AutoLockBadge(): React.ReactElement | null {
  const { t } = useTranslation();
  const expiresAtMs = useAtomValue(expiresAtMsAtom);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (expiresAtMs === null) {
      return;
    }
    const interval = window.setInterval(() => {
      setNow(Date.now());
    }, 1_000);
    return () => window.clearInterval(interval);
  }, [expiresAtMs]);

  if (expiresAtMs === null) {
    return null;
  }

  const remainingMs = Math.max(0, expiresAtMs - now);
  const isWarning = remainingMs > 0 && remainingMs <= WARN_THRESHOLD_MS;

  return (
    <div
      className={cn(
        "flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-mono tabular-nums transition-colors",
        isWarning
          ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
          : "border-input bg-card/60 text-muted-foreground",
      )}
      aria-label={t("dashboard.auto_lock_aria", { time: formatRemaining(remainingMs) })}
      role="timer"
      aria-live={isWarning ? "polite" : "off"}
    >
      <TimerReset className="h-3.5 w-3.5" aria-hidden />
      <span>{formatRemaining(remainingMs)}</span>
    </div>
  );
}
