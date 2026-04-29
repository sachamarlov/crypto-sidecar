/**
 * Light / dark / system theme toggle.
 *
 * Audit E P0-3 / ε-14: index.css ships a complete light token set
 * but main.tsx hard-coded ``defaultTheme="dark"`` and
 * tauri.conf.json hard-coded ``"theme": "Dark"``. The light tokens
 * were dead CSS. This toggle wires the cycle dark -> light -> system
 * via next-themes. The Tauri shell theme is independent (controlled
 * by tauri.conf.json) -- removing the hardcoded "Dark" there is a
 * separate change since it requires a Tauri rebuild.
 */

import { cn } from "@/lib/utils";
import { Monitor, Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";
import { type ReactElement } from "react";
import { useTranslation } from "react-i18next";

export function ThemeToggle(): ReactElement {
  const { t } = useTranslation();
  const { theme, setTheme } = useTheme();

  const cycle = (): void => {
    if (theme === "dark") setTheme("light");
    else if (theme === "light") setTheme("system");
    else setTheme("dark");
  };

  const Icon = theme === "dark" ? Moon : theme === "light" ? Sun : Monitor;

  return (
    <button
      type="button"
      onClick={cycle}
      className={cn(
        "flex h-7 w-7 items-center justify-center rounded-md border border-input text-muted-foreground",
        "hover:bg-accent hover:text-foreground",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
      )}
      aria-label={t("common.theme")}
      title={t("common.theme")}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden />
    </button>
  );
}
