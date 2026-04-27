/**
 * Lock state -- Jotai atoms (ADR-0016 sec B).
 *
 * Each consumer subscribes to the precise atom they read; auto-lock
 * countdown UI only re-renders when `expiresAtMsAtom` changes,
 * AuthGuard only re-renders when `isUnlockedAtom` changes.
 *
 * The `sessionId` is the only piece of identity the frontend keeps
 * after unlock. It travels in `X-GuardiaBox-Session` on every
 * authenticated request. On lock or expiry, atoms reset to null and
 * the AuthGuard reroutes to `/lock`.
 */

import { atom } from "jotai";

/** Active session id -- null when the vault is locked. */
export const sessionIdAtom = atom<string | null>(null);

/** Epoch milliseconds when the session expires (sliding TTL on the server). */
export const expiresAtMsAtom = atom<number | null>(null);

/** Convenience derived atom: true iff a session is open AND not expired. */
export const isUnlockedAtom = atom((get) => {
  const sid = get(sessionIdAtom);
  const exp = get(expiresAtMsAtom);
  if (sid === null || exp === null) {
    return false;
  }
  return Date.now() < exp;
});

/** Active user id (after `/users/{id}/unlock` -- per-user vault key). */
export const activeUserIdAtom = atom<string | null>(null);
