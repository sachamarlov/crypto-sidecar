/**
 * Reusable password input with a live zxcvbn-style strength bar.
 *
 * * `password=true` Input -- no echo on disk-state.
 * * Live strength evaluation on every keystroke (client-only;
 *   `assert_strong` on the server is the authoritative gate).
 * * 20-character coloured bar matching the TUI behaviour.
 * * `aria-describedby` ties the strength label to the input for SR.
 */

import { evaluatePassword, strengthColor } from "@/lib/password";
import { cn } from "@/lib/utils";
import { useId } from "react";
import { useTranslation } from "react-i18next";

interface PasswordFieldProps {
  value: string;
  onChange: (next: string) => void;
  placeholder?: string;
  showStrength?: boolean;
  autoFocus?: boolean;
  ariaLabel?: string;
  className?: string;
  disabled?: boolean;
}

const BAR_STEPS = 20;

export function PasswordField({
  value,
  onChange,
  placeholder,
  showStrength = true,
  autoFocus = false,
  ariaLabel,
  className,
  disabled = false,
}: PasswordFieldProps): React.ReactElement {
  const { t } = useTranslation();
  const inputId = useId();
  const helperId = useId();

  const evaluation = evaluatePassword(value);
  const filled = value.length === 0 ? 0 : Math.max(1, Math.round((evaluation.score / 4) * BAR_STEPS));
  const empty = BAR_STEPS - filled;
  const colour = strengthColor(evaluation.score);

  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <input
        id={inputId}
        type="password"
        autoComplete="current-password"
        autoFocus={autoFocus}
        disabled={disabled}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder ?? t("password.placeholder")}
        aria-label={ariaLabel ?? t("password.aria_label")}
        aria-describedby={showStrength ? helperId : undefined}
        className={cn(
          "h-10 w-full rounded-md border border-input bg-background px-3 text-sm shadow-sm",
          "placeholder:text-muted-foreground",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
          "disabled:cursor-not-allowed disabled:opacity-50",
        )}
      />
      {showStrength ? (
        <div
          id={helperId}
          className="flex items-center gap-2 text-xs"
          role="status"
          aria-live="polite"
        >
          <span aria-hidden className="font-mono tracking-tight" style={{ color: colour }}>
            {"█".repeat(filled)}
            <span className="text-muted-foreground/40">{"░".repeat(empty)}</span>
          </span>
          <span className="text-muted-foreground">
            {value.length === 0 ? t("password.hint_empty") : evaluation.label}
          </span>
        </div>
      ) : null}
    </div>
  );
}
