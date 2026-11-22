import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getLang, interpolate, setLang, t, translate } from './index'
import { ru } from './ru'
import { en } from './en'

// Окружение тестов — node: подставляем минимальные document и localStorage.
const store = new Map<string, string>()
const html = { lang: 'ru' }
beforeEach(() => {
  store.clear()
  vi.stubGlobal('localStorage', {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
  })
  vi.stubGlobal('document', { documentElement: html })
})
afterEach(() => setLang('ru'))

describe('i18n', () => {
  it('по умолчанию русский', () => {
    expect(getLang()).toBe('ru')
    expect(t('nav.overview')).toBe('Обзор')
  })
  it('переключает язык, обновляет html lang и сохраняет выбор', () => {
    setLang('en')
    expect(t('nav.overview')).toBe('Overview')
    expect(html.lang).toBe('en')
    expect(localStorage.getItem('ui.lang')).toBe('en')
  })
  it('если ключа нет в en — берёт русский, если нигде нет — сам ключ', () => {
    expect(translate('en', 'only.in.ru.test')).toBe('only.in.ru.test')
    ru['test.ruOnly'] = 'только по-русски'
    expect(translate('en', 'test.ruOnly')).toBe('только по-русски')
    delete ru['test.ruOnly']
  })
  it('подставляет параметры и оставляет неизвестные', () => {
    expect(interpolate('{n} этапов, {x}', { n: 3 })).toBe('3 этапов, {x}')
  })
  it('словари ru и en содержат одинаковые ключи', () => {
    expect(Object.keys(en).sort()).toEqual(Object.keys(ru).sort())
  })
  it('в обоих словарях одинаковые плейсхолдеры', () => {
    const ph = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort().join()
    for (const k of Object.keys(ru)) expect(ph(en[k] ?? ''), k).toBe(ph(ru[k]!))
  })
})
