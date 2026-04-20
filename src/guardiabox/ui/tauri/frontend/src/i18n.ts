import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";

void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: "en",
    supportedLngs: ["en", "fr"],
    interpolation: {
      escapeValue: false,
    },
    resources: {
      en: {
        translation: {
          app: {
            tagline: "Local secure vault. Encrypt, store, and share files without ever trusting a remote server.",
          },
        },
      },
      fr: {
        translation: {
          app: {
            tagline: "Coffre-fort numérique local. Chiffrez, stockez et partagez vos fichiers sans jamais faire confiance à un serveur distant.",
          },
        },
      },
    },
  });

export default i18n;
