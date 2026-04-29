/**
 * Custom title-bar window controls (close / minimize / maximize).
 *
 * tauri.conf.json sets `decorations: false` + `transparent: true` to
 * render a frameless aurora-glass surface; the trade-off is that
 * macOS / Windows native title-bar buttons disappear and the user
 * cannot move, resize, or close the window without an Alt+F4 / right-
 * click on the taskbar. This component plus the parent's
 * `data-tauri-drag-region` on the title strip restore the expected
 * behaviour.
 *
 * The Tauri `core:window:allow-{close,minimize,maximize,unminimize,
 * unmaximize}` capabilities are already declared in
 * `capabilities/default.json` (audit-resharpened, no `core:window:default`
 * blanket per CLAUDE.md S11).
 */

import { cn } from "@/lib/utils";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Maximize2, Minus, X } from "lucide-react";
import { useTranslation } from "react-i18next";

export function WindowControls(): React.ReactElement {
  const { t } = useTranslation();

  const onMinimize = async (): Promise<void> => {
    await getCurrentWindow().minimize();
  };

  const onToggleMaximize = async (): Promise<void> => {
    await getCurrentWindow().toggleMaximize();
  };

  const onClose = async (): Promise<void> => {
    await getCurrentWindow().close();
  };

  return (
    <div className="flex items-center gap-1" role="group" aria-label={t("window.controls_label")}>
      <button
        type="button"
        onClick={() => void onMinimize()}
        className={cn(
          "flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground transition-colors",
          "hover:bg-accent hover:text-foreground",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        )}
        aria-label={t("window.minimize")}
        title={t("window.minimize")}
      >
        <Minus className="h-3.5 w-3.5" aria-hidden />
      </button>
      <button
        type="button"
        onClick={() => void onToggleMaximize()}
        className={cn(
          "flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground transition-colors",
          "hover:bg-accent hover:text-foreground",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        )}
        aria-label={t("window.maximize")}
        title={t("window.maximize")}
      >
        <Maximize2 className="h-3.5 w-3.5" aria-hidden />
      </button>
      <button
        type="button"
        onClick={() => void onClose()}
        className={cn(
          "flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground transition-colors",
          "hover:bg-destructive hover:text-destructive-foreground",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-destructive",
        )}
        aria-label={t("window.close")}
        title={t("window.close")}
      >
        <X className="h-3.5 w-3.5" aria-hidden />
      </button>
    </div>
  );
}
