/**
 * AuthGuard -- gates the dashboard tree behind a valid vault session.
 *
 * If the lock atoms say the session is closed or expired, the guard
 * redirects to `/lock`. Used as the parent component of every
 * `/dashboard/*` route.
 */

import { isUnlockedAtom } from "@/stores/lock";
import { Navigate } from "@tanstack/react-router";
import { useAtomValue } from "jotai";
import type { ReactNode } from "react";

interface AuthGuardProps {
  children: ReactNode;
}

export function AuthGuard({ children }: AuthGuardProps): ReactNode {
  const unlocked = useAtomValue(isUnlockedAtom);
  if (!unlocked) {
    return <Navigate to="/lock" />;
  }
  return <>{children}</>;
}
