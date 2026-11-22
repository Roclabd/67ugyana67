/**
 * Ответ ноды output.route-map (C8) → модель экрана RouteMap.
 * Ничего не досчитывается сверх данных сервера, кроме трёх выводов, правила которых видны здесь:
 *  - номер правила — порядок его строки в файле конфигурации безопасности (порядок authorizeHttpRequests);
 *  - «затенено» — последующее подходящее правило строже сработавшего; общий anyRequest() не считается:
 *    это запасное правило для всего остального, а не более строгое правило для этого пути;
 *  - находки маршрута — находки (или места их доказательства) в файле обработчика от его строки
 *    до следующего маршрута того же файла, не дальше 15 строк.
 */
import type {
  Finding,
  RouteAccess,
  RouteArtifactRule,
  RouteEntry,
  RouteMap,
  RouteMapArtifact,
  SecurityRuleInfo,
  UnresolvedItem,
} from '../../api/types'

const STRICTNESS: Record<RouteAccess, number> = { PUBLIC: 0, AUTHENTICATED: 1, ROLE: 2, DENY: 3, UNKNOWN: -1 }

function accessOf(access: string): RouteAccess {
  if (access === 'permitAll') return 'PUBLIC'
  if (access === 'authenticated' || access === 'fullyAuthenticated' || access === 'rememberMe') return 'AUTHENTICATED'
  if (/^has(Any)?(Role|Authority)$/.test(access) || access === 'access') return 'ROLE'
  if (access === 'denyAll') return 'DENY'
  return 'UNKNOWN'
}

const ruleKey = (r: RouteArtifactRule) => `${r.file}:${r.line}`

export function isRouteMapArtifact(value: unknown): value is RouteMapArtifact {
  return typeof value === 'object' && value !== null && (value as { kind?: unknown }).kind === 'route-map' &&
    Array.isArray((value as { routes?: unknown }).routes)
}

export function fromArtifact(artifact: RouteMapArtifact, findings: Finding[] = []): RouteMap {
  // Все правила, которые встретились в ответе, по месту в коде — в порядке объявления.
  const byKey = new Map<string, RouteArtifactRule>()
  for (const row of artifact.routes) for (const r of [row.rule, ...row.subsequentRules]) if (r) byKey.set(ruleKey(r), r)
  const ordered = [...byKey.values()].sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line)
  const order = new Map(ordered.map((r, i) => [ruleKey(r), i + 1]))
  const rules: SecurityRuleInfo[] = ordered.map((r) => ({
    order: order.get(ruleKey(r))!,
    method: null,
    patterns: [],
    anyRequest: r.matcher === 'anyRequest',
    access: accessOf(r.access),
    accessText: r.accessText ?? `${r.access}()`,
    location: { path: r.file, line: r.line },
  }))

  // Граница обработчика: до следующего маршрута в том же файле (не дальше 15 строк).
  const startsByFile = new Map<string, number[]>()
  for (const row of artifact.routes) {
    startsByFile.set(row.location.file, [...(startsByFile.get(row.location.file) ?? []), row.location.line].sort((a, b) => a - b))
  }
  const endOf = (file: string, line: number) => {
    const next = (startsByFile.get(file) ?? []).find((l) => l > line)
    return Math.min(next !== undefined ? next - 1 : line + 15, line + 15)
  }

  const unresolved: UnresolvedItem[] = []
  const routes: RouteEntry[] = artifact.routes.map((row) => {
    const path = row.path ?? '(путь не установлен)'
    const matched = row.accessStatus === 'matched' && row.rule ? row.rule : undefined
    const access = matched ? accessOf(matched.access) : 'UNKNOWN'
    if (!matched) unresolved.push({ kind: 'route-access', path: row.location.file, line: row.location.line, reason: `Доступ к ${path} не установлен`, subject: row.function })
    if (row.tableEvidence === 'unresolved') {
      unresolved.push({ kind: 'route-tables', path: row.location.file, line: row.location.line, reason: `Таблицы, которые читает ${path}, не установлены`, subject: row.function })
    }
    const shadowed = matched
      ? row.subsequentRules.filter((r) => r.matcher !== 'anyRequest' && STRICTNESS[accessOf(r.access)] > STRICTNESS[access]).map((r) => order.get(ruleKey(r))!)
      : []
    const from = row.location.line
    const to = endOf(row.location.file, from)
    const inHandler = (p: string, l?: number) => p === row.location.file && l !== undefined && l >= from && l <= to
    const findingIds = findings
      .filter((f) => f.category !== 'SCA' && (inHandler(f.path, f.line) || f.evidence.some((e) => inHandler(e.path, e.line))))
      .map((f) => f.id)
    const name = row.function.split('.').slice(-2).join('.')
    return {
      method: row.method ?? null,
      path,
      handler: name,
      location: { path: row.location.file, line: row.location.line },
      access,
      accessText: matched ? matched.accessText ?? `${matched.access}()` : 'не установлено',
      matchedRule: matched ? order.get(ruleKey(matched)) ?? null : null,
      shadowedRules: shadowed,
      methodSecurity: row.methodGuards.map((g) => g.name),
      tables: row.tables.map((t) => ({ name: t.name, ownerColumns: t.ownerColumns })),
      tablesResolved: row.tableEvidence !== 'unresolved',
      findingIds,
    }
  })
  return { routes, rules, unresolved }
}
