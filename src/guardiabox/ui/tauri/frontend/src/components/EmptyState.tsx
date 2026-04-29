/**
 * Generic empty-state card for "you have nothing here yet" surfaces.
 *
 * Audit B P1-8 / E P0-8 / δ-7: share / accept / users routes used
 * to render a disabled ``<select><option>--</option></select>``
 * when there were no other users to pick. The form was unusable
 * with no guidance on what to do next. EmptyState renders an icon +
 * description + a CTA link so the dead-end becomes actionable.
 */

import { cn } from "@/lib/utils";
import { Link } from "@tanstack/react-router";
import { type ReactElement, type ReactNode } from "react";

interface EmptyStateProps {
  icon: ReactNode;
  title: string;
  description: string;
  actionLabel?: string;
  actionTo?: string;
  className?: string;
}

export function EmptyState({
  icon,
  title,
  description,
  actionLabel,
  actionTo,
  className,
}: EmptyStateProps): ReactElement {
  return (
    <div
      className={cn(
        "flex flex-col items-center gap-3 rounded-md border border-dashed border-border bg-card/40 p-6 text-center",
        className,
      )}
    >
      <div className="rounded-full bg-muted p-3 text-muted-foreground">{icon}</div>
      <h3 className="font-medium text-sm">{title}</h3>
      <p className="max-w-sm text-balance text-muted-foreground text-xs">{description}</p>
      {actionLabel !== undefined && actionTo !== undefined ? (
        <Link
          to={actionTo}
          className="rounded-md border border-primary/40 bg-primary/10 px-3 py-1.5 text-primary text-xs hover:bg-primary/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          {actionLabel}
        </Link>
      ) : null}
    </div>
  );
}
