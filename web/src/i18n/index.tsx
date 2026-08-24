import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { ApiError } from "../api";
import { catalog, LANGS, type Lang, type MsgKey } from "./catalog";

export const LANG_COOKIE = "kp_lang";

type TFunc = (key: MsgKey | string, vars?: Record<string, string | number>) => string;

type I18nValue = {
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: TFunc;
  te: (err: unknown, fallback?: MsgKey) => string;
  locale: string;
  formatDate: (value: string | Date) => string;
};

const I18nContext = createContext<I18nValue | null>(null);

function readCookie(name: string): string {
  const m = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return m ? decodeURIComponent(m[1]) : "";
}

function writeCookie(name: string, value: string) {
  document.cookie = `${name}=${encodeURIComponent(value)}; path=/; max-age=31536000; SameSite=Lax`;
}

export function detectLang(): Lang {
  const fromCookie = readCookie(LANG_COOKIE).toLowerCase();
  if (fromCookie.startsWith("kk")) return "kk";
  if (fromCookie.startsWith("en")) return "en";
  if (fromCookie.startsWith("ru")) return "ru";
  try {
    const stored = localStorage.getItem(LANG_COOKIE);
    if (stored === "en" || stored === "ru" || stored === "kk") return stored;
  } catch {
    /* ignore */
  }
  const nav = (navigator.language || "").toLowerCase();
  if (nav.startsWith("en")) return "en";
  if (nav.startsWith("ru")) return "ru";
  return "kk";
}

export function persistLang(lang: Lang) {
  writeCookie(LANG_COOKIE, lang);
  try {
    localStorage.setItem(LANG_COOKIE, lang);
  } catch {
    /* ignore */
  }
  document.documentElement.lang = lang;
}

function interpolate(s: string, vars?: Record<string, string | number>): string {
  if (!vars) return s;
  return s.replace(/\{(\w+)\}/g, (_, k: string) => (vars[k] != null ? String(vars[k]) : `{${k}}`));
}

export function translate(lang: Lang, key: string, vars?: Record<string, string | number>): string {
  const pair = (catalog as Record<string, { ru: string; en: string; kk: string }>)[key];
  const raw = pair ? pair[lang] : key;
  return interpolate(raw, vars);
}

function errorSlug(msg: string): string {
  return msg
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_|_$/g, "")
    .slice(0, 64);
}

export function translateError(lang: Lang, err: unknown, fallback: MsgKey = "common.error"): string {
  if (err instanceof ApiError) {
    const code = err.code || errorSlug(err.message);
    const keyed = `errors.${code}`;
    if ((catalog as Record<string, unknown>)[keyed]) {
      return translate(lang, keyed);
    }
    if ((catalog as Record<string, unknown>)[`errors.${errorSlug(err.message)}`]) {
      return translate(lang, `errors.${errorSlug(err.message)}`);
    }
    return err.message || translate(lang, fallback);
  }
  if (err instanceof Error && err.message) {
    const keyed = `errors.${errorSlug(err.message)}`;
    if ((catalog as Record<string, unknown>)[keyed]) {
      return translate(lang, keyed);
    }
    return err.message;
  }
  return translate(lang, fallback);
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    const l = detectLang();
    document.documentElement.lang = l;
    return l;
  });

  const setLang = useCallback((next: Lang) => {
    persistLang(next);
    setLangState(next);
  }, []);

  const value = useMemo<I18nValue>(() => {
    const t: TFunc = (key, vars) => translate(lang, key, vars);
    return {
      lang,
      setLang,
      t,
      te: (err, fallback) => translateError(lang, err, fallback),
      locale: lang === "en" ? "en-GB" : lang === "kk" ? "kk-KZ" : "ru-RU",
      formatDate: (value) => {
        const d = value instanceof Date ? value : new Date(value);
        const loc = lang === "en" ? "en-GB" : lang === "kk" ? "kk-KZ" : "ru-RU";
        return d.toLocaleString(loc);
      },
    };
  }, [lang, setLang]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nValue {
  const ctx = useContext(I18nContext);
  if (!ctx) {
    throw new Error("useI18n requires I18nProvider");
  }
  return ctx;
}

export function LangSwitch(_props?: { compact?: boolean }) {
  const { lang, setLang, t } = useI18n();
  return (
    <div className="lang-switch" role="group" aria-label={t("common.language")}>
      {LANGS.map((item) => (
        <button
          key={item.id}
          type="button"
          className={lang === item.id ? "active" : ""}
          aria-pressed={lang === item.id}
          onClick={() => setLang(item.id)}
        >
          {item.label}
        </button>
      ))}
    </div>
  );
}

export function notifyTitle(t: TFunc, kind: string, fallback: string): string {
  const key = `notify.kind.${kind}`;
  const translated = t(key);
  return translated === key ? fallback : translated;
}
