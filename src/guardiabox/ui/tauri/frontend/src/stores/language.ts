/**
 * Language store -- Zustand. Bridges to react-i18next on every
 * `setLanguage` call so the global subscription tree updates
 * synchronously.
 */

import i18n from "@/i18n";
import { create } from "zustand";
import { persist } from "zustand/middleware";

export type SupportedLanguage = "fr" | "en";

interface LanguageState {
  language: SupportedLanguage;
  setLanguage: (lang: SupportedLanguage) => void;
}

export const useLanguageStore = create<LanguageState>()(
  persist(
    (set) => ({
      language: (i18n.language as SupportedLanguage) ?? "fr",
      setLanguage: (lang) => {
        void i18n.changeLanguage(lang);
        set({ language: lang });
      },
    }),
    { name: "guardiabox.lang" },
  ),
);
