/**
 * Language toggle (FR / EN).
 *
 * Audit B P2-3 / ε-40: extract the duplicated EN/FR button from
 * lock.tsx + dashboard.tsx. Single source of truth so adding
 * a third language only edits one place.
 */

import { cn } from "@/lib/utils";
import { useLanguageStore } from "@/stores/language";
import { type ReactElement } from "react";
import { useTranslation } from "react-i18next";

interface LanguageToggleProps {
  /** Optional class merged with the default styling. */
  className?: string;
}

export function LanguageToggle({ className }: LanguageToggleProps): ReactElement {
  const { t } = useTranslation();
  const language = useLanguageStore((s) => s.language);
  const setLanguage = useLanguageStore((s) => s.setLanguage);

  return (
    <button
      type="button"
      onClick={() => setLanguage(language === "fr" ? "en" : "fr")}
      className={cn(
        "rounded-md border border-input px-2 py-0.5 text-muted-foreground text-xs",
        "hover:bg-accent hover:text-foreground",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        className,
      )}
      aria-label={t("common.language")}
      title={language === "fr" ? "Switch to English" : "Basculer en français"}
    >
      {language === "fr" ? "EN" : "FR"}
    </button>
  );
}
