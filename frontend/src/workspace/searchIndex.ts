/**
 * Каталог функций программы для поиска (Ctrl K): по любому слову из названия, описания или синонимов
 * человек попадает туда, где функция живёт. Пути — реальные маршруты Shell и App.
 * Названия и подсказки переводятся (RU/EN); ключевые слова всегда содержат оба языка,
 * поэтому поиск работает независимо от выбранного языка интерфейса.
 */
import type { NodeDefinition } from '../api/types'
import { t } from '../i18n'
import { defTitle } from '../i18n/nodes'

export type SearchKind = 'feature' | 'section' | 'node' | 'project' | 'workflow' | 'finding' | 'run'

export interface SearchItem {
  id?: string
  name: string
  kind: SearchKind
  path: string
  hint?: string
  /** Синонимы и слова, по которым функцию ищут, но которых нет в названии. */
  keywords?: string
  /** Если задан — выбор переключает проект, а не переходит по пути. */
  projectId?: string
}

/** Контекст для функций, которые ведут в последний запуск. */
export interface SearchContext {
  latestRunId?: string
  firstWorkflowId?: string
}

type Where = 'editor' | 'report' | 'run' | string
interface Def {
  id: string
  kind: SearchKind
  path: Where
  /** Русские и английские синонимы. */
  kw: string
}

const DEFS: Def[] = [
  { id: 'overview', kind: 'section', path: '/', kw: 'главная дашборд dashboard сводка индекс безопасности уровень динамика home summary score trend' },
  { id: 'projects', kind: 'section', path: '/projects', kw: 'репозитории список проектов выбрать проект переключить repositories list switch project' },
  { id: 'addProject', kind: 'feature', path: '/projects?new=1', kw: 'новый проект подключить репозиторий гит git github ссылка привязать new connect repository link' },
  { id: 'builder', kind: 'section', path: 'editor', kw: 'редактор редактирование граф графы workflow воркфлоу схема ноды узлы блоки связи соединить drag drop перетащить editor edit graph nodes blocks connect scenario constructor' },
  { id: 'newWorkflow', kind: 'feature', path: '/workflows/new', kw: 'создать сценарий новый граф workflow с нуля create new scenario graph from scratch' },
  { id: 'ai', kind: 'feature', path: '/workflows/new?generate=1', kw: 'сгенерировать генерация ии ai llm нейросеть текст описание промпт собрать автоматически generate prompt text describe build automatically' },
  { id: 'validate', kind: 'feature', path: 'editor', kw: 'валидация ошибки графа проверка связей validation errors ports check connections' },
  { id: 'run', kind: 'feature', path: '/', kw: 'старт запуск сканировать скан проверить репозиторий run start scan launch check repository' },
  { id: 'workflows', kind: 'section', path: '/scenarios', kw: 'список сценариев workflows воркфлоу мои сценарии list my scenarios' },
  { id: 'templates', kind: 'section', path: '/templates', kw: 'шаблоны templates готовые скопировать копировать библиотека library ready-made copy' },
  { id: 'publish', kind: 'feature', path: '/templates', kw: 'публикация поделиться сохранить как шаблон publish share save as template' },
  { id: 'routes', kind: 'section', path: '/routes', kw: 'маршруты эндпоинты endpoints api доступ роли spring security permitall права routes access roles permissions' },
  { id: 'runs', kind: 'section', path: '/history', kw: 'история журнал прошлые проверки runs лог history log past checks' },
  { id: 'lastRun', kind: 'feature', path: 'run', kw: 'текущий запуск мониторинг выполнение этапы статус ноды данные current run monitoring progress stages status nodes data' },
  { id: 'findings', kind: 'section', path: '/findings', kw: 'уязвимости проблемы риски findings секреты зависимости sast sca vulnerabilities issues risks secrets dependencies' },
  { id: 'reports', kind: 'section', path: '/reports', kw: 'отчет report итоги reports results' },
  { id: 'download', kind: 'feature', path: 'report', kw: 'экспорт выгрузить скачать html markdown md json sarif sbom cyclonedx файл отчета export download file report pdf' },
  { id: 'aiExplain', kind: 'feature', path: 'report', kw: 'ии ai llm объяснение рекомендации исправить как исправить нейросеть сводка explanation recommendations fix how to fix summary' },
  { id: 'applied', kind: 'feature', path: 'report', kw: 'правила алгоритмы покрытие анализаторы rules coverage analyzers algorithms what was checked' },
  { id: 'dismissed', kind: 'feature', path: 'report', kw: 'ложные срабатывания безопасные места ловушки отклонено секреты в тестах false positives safe spots dismissed secrets in tests' },
  { id: 'integrations', kind: 'section', path: '/integrations', kw: 'ci cd пайплайн pipeline github actions gitlab вебхук webhook интеграция блокировка сборки integration build gate' },
  { id: 'ciConfig', kind: 'feature', path: '/ci', kw: 'yaml github actions gitlab ci конфиг сгенерировать конфигурацию config generate configuration' },
  { id: 'llm', kind: 'feature', path: '/settings', kw: 'нейросеть модель ключ api openai ollama локальная llm ии ai провайдер model key local provider settings' },
  { id: 'allowed', kind: 'feature', path: '/settings', kw: 'whitelist allowed repos доступ репозиторий добавить ссылку access repository add link allowlist' },
  { id: 'telegramSettings', kind: 'feature', path: '/settings#telegram', kw: 'настроить телеграм бот токен подключение telegram bot configure settings connection token recipient' },
  { id: 'telegram', kind: 'feature', path: 'editor', kw: 'телеграм telegram бот оповещение уведомить сообщение bot alert message' },
  { id: 'email', kind: 'feature', path: 'editor', kw: 'почта email smtp письмо mail e-mail letter' },
  { id: 'schedule', kind: 'feature', path: 'editor', kw: 'расписание cron крон каждый день ежедневно по времени триггер schedule daily timer trigger' },
  { id: 'zip', kind: 'feature', path: 'editor', kw: 'zip архив загрузить файл upload без гита archive no git' },
]

export function featureItems(ctx: SearchContext): SearchItem[] {
  const where: Record<string, string> = {
    editor: ctx.firstWorkflowId ? '/workflows/' + ctx.firstWorkflowId : '/workflows/new',
    report: ctx.latestRunId ? '/runs/' + ctx.latestRunId + '/report' : '/reports',
    run: ctx.latestRunId ? '/runs/' + ctx.latestRunId : '/history',
  }
  return DEFS.map((d) => ({
    id: d.id,
    name: t('sf.' + d.id + '.n'),
    kind: d.kind,
    path: where[d.path] ?? d.path,
    hint: t('sf.' + d.id + '.h'),
    keywords: d.kw,
  }))
}

const CATEGORY_KEY: Record<string, string> = {
  TRIGGER: 'cat.TRIGGER', SOURCE: 'cat.SOURCE', ANALYZER: 'cat.ANALYZER', LOGIC: 'cat.LOGIC', AI: 'cat.AI', OUTPUT: 'cat.OUTPUT',
}

/** Каждая нода каталога — отдельный результат: найти по названию или типу и открыть конструктор. */
export function nodeItems(nodes: NodeDefinition[], editorPath: string): SearchItem[] {
  return nodes.map((n) => ({
    name: defTitle(n),
    kind: 'node',
    path: editorPath,
    hint: [CATEGORY_KEY[n.category] ? t(CATEGORY_KEY[n.category]!) : n.category, n.description].filter(Boolean).join(' · '),
    // Русское название сервера и английское из словаря клиента ищутся независимо от языка интерфейса.
    keywords: n.type.replace(/[._-]/g, ' ') + ' ' + n.title,
  }))
}

export function normalize(text: string): string {
  return text.toLowerCase().replace(/ё/g, 'е')
}

/** Грубая основа слова: окончания отбрасываются, чтобы «графов», «графа» и «граф» (и graphs/graph) совпадали. */
function stem(word: string): string {
  return word.length > 4 ? word.slice(0, Math.max(4, word.length - 3)) : word
}

const SCORE_BY_KIND: Record<SearchKind, number> = {
  feature: 3, section: 3, node: 2, project: 2, workflow: 2, finding: 1, run: 0,
}

/** Каждое слово запроса должно найтись (по основе) в названии, описании или синонимах. Название весит больше. */
export function search(items: SearchItem[], query: string, limit = 12): SearchItem[] {
  const tokens = normalize(query).split(/[^\p{L}\p{N}]+/u).filter(Boolean).map(stem)
  if (!tokens.length) return []
  const scored: { item: SearchItem; score: number }[] = []
  for (const item of items) {
    const name = normalize(item.name).split(/[^\p{L}\p{N}]+/u)
    const rest = normalize([item.hint, item.keywords, item.kind].join(' ')).split(/[^\p{L}\p{N}]+/u)
    let score = SCORE_BY_KIND[item.kind]
    let all = true
    for (const t of tokens) {
      if (name.some((w) => w.startsWith(t))) score += 10
      else if (rest.some((w) => w.startsWith(t))) score += 4
      else { all = false; break }
    }
    if (all) scored.push({ item, score })
  }
  return scored.sort((a, b) => b.score - a.score).slice(0, limit).map((s) => s.item)
}
