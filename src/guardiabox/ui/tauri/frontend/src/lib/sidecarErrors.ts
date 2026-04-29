/**
 * Centralised toast dispatcher for sidecar errors.
 *
 * Replaces the 12 ad-hoc `toast.error(t("errors.network"))` blanket
 * branches that audit B P0-2 flagged as the root cause of opaque
 * "Failed to fetch" UX. Every route now delegates to this helper, so
 * adding a new error category is a single-file change.
 *
 * Branching matrix:
 *
 * | Error class                 | Sub-discriminator       | Toast key                    |
 * | --------------------------- | ----------------------- | ---------------------------- |
 * | SidecarUnreachableError     | stage=handshake         | errors.sidecar.handshake     |
 * | SidecarUnreachableError     | stage=fetch             | errors.sidecar.fetch         |
 * | SidecarUnreachableError     | stage=timeout           | errors.sidecar.timeout       |
 * | SidecarHttpError            | status=401              | errors.session_expired       |
 * | SidecarHttpError            | status=429              | errors.rate_limited          |
 * | SidecarHttpError            | status >= 500           | errors.sidecar_server        |
 * | SidecarHttpError            | other 4xx (default)     | err.detail (server-provided) |
 * | other Error / unknown       | --                      | errors.unknown               |
 */

import { SidecarHttpError, SidecarUnreachableError } from "@/api/errors";
import type { TFunction } from "i18next";
import { toast } from "sonner";

/** Show a typed toast for any sidecar/network error. */
export function toastSidecarError(err: unknown, t: TFunction): void {
  if (err instanceof SidecarUnreachableError) {
    toast.error(t(`errors.sidecar.${err.stage}`));
    return;
  }
  if (err instanceof SidecarHttpError) {
    if (err.status === 401) {
      toast.error(t("errors.session_expired"));
      return;
    }
    if (err.status === 429) {
      toast.error(t("errors.rate_limited"));
      return;
    }
    if (err.status >= 500) {
      toast.error(t("errors.sidecar_server"));
      return;
    }
    // Non-anti-oracle 4xx: surface server detail verbatim. Routes
    // that need a status-based override (e.g. decrypt 422 anti-
    // oracle, share 422 verification, users 409 duplicate) handle
    // those branches themselves before falling through to here.
    toast.error(err.detail);
    return;
  }
  toast.error(t("errors.unknown"));
}
