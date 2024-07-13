import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

import zh from "./zh";
import en from "./en";
import ru from "./ru";

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: "en",
    interpolation: {
      escapeValue: false,
    },
    resources: {
      en: {
        translation: en,
      },
      zh: {
        translation: zh,
      },
      ru: {
        translation: ru,
      },
    },
  });

export default i18n;
