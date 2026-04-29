/**
 * Reusable destructive-action confirmation dialog.
 *
 * Replaces ``window.confirm`` (audit B P1-7 / δ-3) which broke the
 * dark theme, used native OS dialogs unsuitable for translation,
 * and lacked accessibility semantics. Backed by Radix
 * ``@radix-ui/react-alert-dialog`` -- the appropriate primitive
 * for "this will destroy data" confirmation flows (role
 * "alertdialog", focus trap, Escape closes).
 */

import { cn } from "@/lib/utils";
import * as AlertDialog from "@radix-ui/react-alert-dialog";
import { type ReactElement, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

interface ConfirmDestructiveProps {
  /** Trigger element (typically the destructive button). */
  trigger: ReactNode;
  title: string;
  description: string;
  confirmLabel: string;
  onConfirm: () => void;
  /** Optional cancel label override; defaults to common.cancel. */
  cancelLabel?: string;
}

export function ConfirmDestructive({
  trigger,
  title,
  description,
  confirmLabel,
  onConfirm,
  cancelLabel,
}: ConfirmDestructiveProps): ReactElement {
  const { t } = useTranslation();
  return (
    <AlertDialog.Root>
      <AlertDialog.Trigger asChild>{trigger}</AlertDialog.Trigger>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="fixed inset-0 z-50 bg-background/60 backdrop-blur-sm data-[state=open]:animate-in data-[state=closed]:animate-out" />
        <AlertDialog.Content
          className={cn(
            "fixed left-[50%] top-[50%] z-50 grid w-full max-w-md translate-x-[-50%] translate-y-[-50%] gap-4 border border-border bg-card p-6 shadow-lg",
            "rounded-xl data-[state=open]:animate-in data-[state=closed]:animate-out",
          )}
        >
          <AlertDialog.Title className="font-semibold text-lg">{title}</AlertDialog.Title>
          <AlertDialog.Description className="text-muted-foreground text-sm">
            {description}
          </AlertDialog.Description>
          <div className="flex justify-end gap-2 pt-2">
            <AlertDialog.Cancel
              className="rounded-md border border-input bg-background px-4 py-2 text-sm hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              {cancelLabel ?? t("common.cancel")}
            </AlertDialog.Cancel>
            <AlertDialog.Action
              onClick={onConfirm}
              className="rounded-md bg-destructive px-4 py-2 font-medium text-destructive-foreground text-sm hover:bg-destructive/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-destructive"
            >
              {confirmLabel}
            </AlertDialog.Action>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}
