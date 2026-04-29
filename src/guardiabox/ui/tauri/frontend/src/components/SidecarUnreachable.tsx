/**
 * Lock-screen variant displayed when the sidecar handshake fails or
 * the loopback HTTP probe (`/readyz`) cannot reach the process.
 *
 * Audit B P0-2 finding: previously every such failure surfaced as
 * `errors.network` toast with no diagnostic. This screen explicitly
 * tells the user *what* went wrong (handshake / fetch) and *what*
 * to do (relaunch / check AV / read the debug log path) so the
 * reviewer is never left guessing.
 *
 * The component does not auto-retry to avoid burning rate-limit
 * budget on a sidecar that is genuinely down; the user clicks
 * "Retry" or relaunches.
 */

import { SidecarUnreachableError } from "@/api/errors";
import { cn } from "@/lib/utils";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { useTranslation } from "react-i18next";

interface SidecarUnreachableProps {
  error: unknown;
  onRetry?: () => void;
}

export function SidecarUnreachable({
  error,
  onRetry,
}: SidecarUnreachableProps): React.ReactElement {
  const { t } = useTranslation();

  const stage = error instanceof SidecarUnreachableError ? error.stage : "fetch";
  const messageKey = `errors.sidecar.${stage}` as const;
  const hintKey = `errors.sidecar.${stage}_hint` as const;

  return (
    <div className="flex w-full max-w-md flex-col items-center gap-4 text-center" role="alert">
      <div className="rounded-full bg-destructive/10 p-4 ring-1 ring-destructive/40">
        <AlertTriangle className="h-8 w-8 text-destructive" aria-hidden />
      </div>
      <h2 className="font-semibold text-lg">{t("lock.sidecar_unreachable_title")}</h2>
      <p className="text-balance text-muted-foreground text-sm">{t(messageKey)}</p>
      <p className="text-balance text-muted-foreground/70 text-xs">{t(hintKey)}</p>
      {onRetry !== undefined ? (
        <button
          type="button"
          onClick={onRetry}
          className={cn(
            "mt-2 flex items-center gap-2 rounded-md border border-input bg-card px-4 py-2 font-medium text-sm",
            "hover:bg-accent",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
          )}
        >
          <RefreshCw className="h-3.5 w-3.5" aria-hidden />
          {t("common.retry")}
        </button>
      ) : null}
    </div>
  );
}
