/**
 * Лёгкая i18n без зависимостей: плоские словари ru/en, t(key, params), хук useT().
 * Русский — язык по умолчанию и запасной вариант; если ключа нет нигде, возвращается сам ключ.
 */
import { useSyncExternalStore } from 'react'
import { ru } from './ru'
import { en } from './en'

export type Lang = 'ru' | 'en'
export const LANGS: Lang[] = ['ru', 'en']
export type Params = Record<string, string | number>

const dictionaries: Record<Lang, Record<string, string>> = { ru, en }
const STORAGE_KEY = 'ui.lang'

function readStored(): Lang {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v === 'ru' || v === 'en') return v
  } catch {
    /* Без localStorage остаётся язык по умолчанию. */
  }
  return 'ru'
}

let current: Lang = readStored()
const listeners = new Set<() => void>()

function applyDocumentLang() {
  if (typeof document !== 'undefined') document.documentElement.lang = current
}
applyDocumentLang()

export function getLang(): Lang {
  return current
}

export function setLang(lang: Lang) {
  if (lang === current) return
  current = lang
  try {
    localStorage.setItem(STORAGE_KEY, lang)
  } catch {
    /* Язык действует до перезагрузки. */
  }
  applyDocumentLang()
  listeners.forEach((l) => l())
}

export function interpolate(text: string, params?: Params): string {
  if (!params) return text
  return text.replace(/\{(\w+)\}/g, (m, name: string) => (name in params ? String(params[name]) : m))
}

export function translate(lang: Lang, key: string, params?: Params): string {
  return interpolate(dictionaries[lang][key] ?? ru[key] ?? key, params)
}

/** Перевод на текущий язык; безопасно вызывать вне компонентов (при смене языка дерево перерисовывается). */
export function t(key: string, params?: Params): string {
  return translate(current, key, params)
}

/**
 * Текст, который по умолчанию приходит с сервера (на русском): на русском возвращается он сам,
 * на английском — перевод из словаря, если он есть, иначе оригинал.
 */
export function tOr(key: string, fallback: string): string {
  return current === 'ru' ? fallback : (dictionaries[current][key] ?? fallback)
}

/** BCP-47 локаль для дат и чисел. */
export function locale(): string {
  return current === 'en' ? 'en-US' : 'ru-RU'
}

function subscribe(cb: () => void) {
  listeners.add(cb)
  return () => {
    listeners.delete(cb)
  }
}

export function useLang(): Lang {
  return useSyncExternalStore(subscribe, getLang, getLang)
}

export function useT() {
  const lang = useLang()
  return { t, lang, setLang }
}
