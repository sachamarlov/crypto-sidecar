/**
 * Auto-lock countdown -- watches `expiresAtMsAtom` and, when the
 * session expires, resets the lock atoms and (best-effort) calls
 * `/api/v1/vault/lock` to drop the server-side state.
 *
 * The hook deliberately runs at 1 Hz (cheap; no observable jitter
 * for the user). A finer cadence would just re-render the
 * countdown faster without changing the lock behaviour.
 */

import { post } from "@/api/client";
import { expiresAtMsAtom, sessionIdAtom } from "@/stores/lock";
import { useAtom } from "jotai";
import { useEffect } from "react";

export function useAutoLock(): void {
  const [expiresAt, setExpiresAt] = useAtom(expiresAtMsAtom);
  const [sessionId, setSessionId] = useAtom(sessionIdAtom);

  useEffect(() => {
    if (expiresAt === null || sessionId === null) {
      return;
    }
    const interval = window.setInterval(() => {
      if (Date.now() >= expiresAt) {
        // Best-effort server-side lock; we drop the local state
        // regardless so the AuthGuard reroutes immediately.
        void post("/api/v1/vault/lock", { session_id: sessionId }).catch(() => {
          /* swallow -- the session is already gone client-side */
        });
        setSessionId(null);
        setExpiresAt(null);
      }
    }, 1_000);
    return () => window.clearInterval(interval);
  }, [expiresAt, sessionId, setExpiresAt, setSessionId]);
}
