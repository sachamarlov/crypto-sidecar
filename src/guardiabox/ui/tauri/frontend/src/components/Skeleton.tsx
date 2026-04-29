/**
 * Skeleton loading placeholder.
 *
 * Audit E P1-6 / ε-10: replaces flat "Chargement…" <p> tags with
 * a shimmer pattern so the user has a visual sense of the layout
 * while data lands. shadcn/ui-style: a single primitive composed
 * into rows / cards / circles by callers.
 */

import { cn } from "@/lib/utils";
import { type ReactElement } from "react";

interface SkeletonProps {
  className?: string;
}

export function Skeleton({ className }: SkeletonProps): ReactElement {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-muted", className)}
      aria-hidden="true"
    />
  );
}

export function SkeletonRow(): ReactElement {
  return (
    <div className="flex items-center gap-3 p-2">
      <Skeleton className="h-9 w-9 rounded-full" />
      <div className="flex flex-1 flex-col gap-1.5">
        <Skeleton className="h-3 w-2/3" />
        <Skeleton className="h-2.5 w-1/2" />
      </div>
    </div>
  );
}
