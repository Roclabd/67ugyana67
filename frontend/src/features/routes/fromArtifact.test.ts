import { describe, expect, it } from 'vitest'
import type { Finding, RouteArtifactRow, RouteArtifactRule, RouteMapArtifact } from '../../api/types'
import serverResponse from '../../api/fixtures/route-map.json'
import { fromArtifact, isRouteMapArtifact } from './fromArtifact'

/** Снятый ответ сервера (output.route-map на учебном проекте Service Desk). */
const fixture = serverResponse as RouteMapArtifact

const SEC = 'src/main/kotlin/lab/servicedesk/config/RepairSecurity.kt'
const LOOKUP = 'src/main/kotlin/lab/servicedesk/repair/RepairLookupController.kt'
const TICKETS = 'src/main/kotlin/lab/servicedesk/repair/RepairTicketController.kt'
const PICKUP = 'src/main/kotlin/lab/servicedesk/pickup/PickupExportController.kt'

const rule = (access: string, line: number, matcher = 'requestMatchers', file = SEC): RouteArtifactRule => ({ access, matcher, file, line })

function row(over: Partial<RouteArtifactRow> = {}): RouteArtifactRow {
  return {
    function: 'lab.app.DemoController.handle',
    accessStatus: 'matched',
    method: 'GET',
    path: '/api/demo',
    location: { file: 'src/Demo.kt', line: 10 },
    rule: rule('authenticated', 5),
    subsequentRules: [],
    methodGuards: [],
    tables: [],
    tableEvidence: 'located',
    ...over,
  }
}

const artifact = (...routes: RouteArtifactRow[]): RouteMapArtifact => ({ kind: 'route-map', status: 'COMPLETE', routes })

function finding(over: Partial<Finding>): Finding {
  return { id: 'F', fingerprint: 'fp', category: 'SAST', path: 'src/Demo.kt', line: 1, severity: 'HIGH', rule: 'r', evidence: [], ...over }
}

const byPath = (map: ReturnType<typeof fromArtifact>, path: string) => {
  const r = map.routes.find((x) => x.path === path)
  if (!r) throw new Error(`нет маршрута ${path}`)
  return r
}

describe('isRouteMapArtifact', () => {
  it('узнаёт ответ сервера', () => {
    expect(isRouteMapArtifact(serverResponse)).toBe(true)
    expect(isRouteMapArtifact({ kind: 'route-map', routes: [] })).toBe(true)
  })

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['строка', 'route-map'],
    ['массив', []],
    ['без routes', { kind: 'route-map' }],
    ['routes не массив', { kind: 'route-map', routes: {} }],
    ['другой kind', { kind: 'report', routes: [] }],
  ])('отвергает: %s', (_name, value) => {
    expect(isRouteMapArtifact(value)).toBe(false)
  })
})

describe('fromArtifact на ответе сервера', () => {
  const map = fromArtifact(fixture)

  it('сохраняет все маршруты в порядке ответа', () => {
    expect(map.routes.map((r) => r.path)).toEqual(fixture.routes.map((r) => r.path))
  })

  it('нумерует правила по порядку строк конфигурации, без повторов', () => {
    expect(map.rules.map((r) => [r.order, r.location.line, r.access, r.anyRequest])).toEqual([
      [1, 17, 'PUBLIC', false],
      [2, 18, 'PUBLIC', false],
      [3, 19, 'ROLE', false],
      [4, 20, 'AUTHENTICATED', false],
      [5, 21, 'DENY', true],
    ])
    expect(map.rules.every((r) => r.location.path === SEC && r.method === null && r.patterns.length === 0)).toBe(true)
    expect(map.rules[4].accessText).toBe('denyAll()')
  })

  it('открытый экспорт: permitAll, а строгий hasRole ниже затенён', () => {
    const r = byPath(map, '/api/pickup/export')
    expect(r).toMatchObject({
      method: 'GET',
      handler: 'PickupExportController.export',
      location: { path: PICKUP, line: 9 },
      access: 'PUBLIC',
      accessText: 'permitAll()',
      matchedRule: 2,
      shadowedRules: [3],
      tablesResolved: false,
    })
  })

  it('anyRequest() не считается затеняющим правилом', () => {
    const r = byPath(map, '/api/catalog/services')
    expect(r.access).toBe('PUBLIC')
    expect(r.matchedRule).toBe(1)
    expect(r.shadowedRules).toEqual([])
  })

  it('таблицы с колонками владельцев переносятся как есть', () => {
    const r = byPath(map, '/api/customer/search/code')
    expect(r.access).toBe('AUTHENTICATED')
    expect(r.matchedRule).toBe(4)
    expect(r.tables).toEqual([{ name: 'repair_ticket', ownerColumns: ['customer_id'] }])
    expect(r.tablesResolved).toBe(true)
  })

  it('«таблицы не установлены» попадает в unresolved, а не превращается в ноль', () => {
    const tables = map.unresolved.filter((u) => u.kind === 'route-tables')
    expect(tables.map((u) => u.subject).sort()).toEqual(
      fixture.routes.filter((r) => r.tableEvidence === 'unresolved').map((r) => r.function).sort(),
    )
    expect(tables).toHaveLength(4)
    expect(map.unresolved.some((u) => u.kind === 'route-access')).toBe(false)
    const tickets = tables.find((u) => u.subject === 'lab.servicedesk.repair.RepairTicketController.getTicket')
    expect(tickets).toMatchObject({ path: TICKETS, line: 13 })
    expect(tickets?.reason).toContain('/api/customer/tickets/{ticketId}')
  })

  it('без находок у маршрутов нет findingIds', () => {
    expect(map.routes.every((r) => r.findingIds.length === 0)).toBe(true)
  })
})

describe('fromArtifact: находки маршрута', () => {
  // В RepairLookupController два маршрута: frame на строке 12, code на строке 16.
  const ids = (findings: Finding[], path: string) => byPath(fromArtifact(fixture, findings), path).findingIds

  it('граница обработчика — строка перед следующим маршрутом того же файла', () => {
    const findings = [
      finding({ id: 'at-12', path: LOOKUP, line: 12 }),
      finding({ id: 'at-15', path: LOOKUP, line: 15 }),
      finding({ id: 'at-16', path: LOOKUP, line: 16 }),
    ]
    expect(ids(findings, '/api/customer/search/frame')).toEqual(['at-12', 'at-15'])
    expect(ids(findings, '/api/customer/search/code')).toEqual(['at-16'])
  })

  it('последний маршрут файла — не дальше 15 строк', () => {
    const findings = [finding({ id: 'at-31', path: LOOKUP, line: 31 }), finding({ id: 'at-32', path: LOOKUP, line: 32 })]
    expect(ids(findings, '/api/customer/search/code')).toEqual(['at-31'])
  })

  it('строки до обработчика и другой файл не считаются', () => {
    const findings = [finding({ id: 'before', path: LOOKUP, line: 11 }), finding({ id: 'other-file', path: TICKETS, line: 14 })]
    expect(ids(findings, '/api/customer/search/frame')).toEqual([])
    expect(ids(findings, '/api/customer/tickets/{ticketId}')).toEqual(['other-file'])
  })

  it('находка засчитывается по месту доказательства', () => {
    const f = finding({ id: 'via-evidence', path: 'src/main/kotlin/lab/servicedesk/repair/RepairTicketReader.kt', line: 40, evidence: [{ path: TICKETS, line: 14 }] })
    expect(ids([f], '/api/customer/tickets/{ticketId}')).toEqual(['via-evidence'])
  })

  it('SCA и находки без строки к маршрутам не привязываются', () => {
    const findings = [
      finding({ id: 'sca', category: 'SCA', path: PICKUP, line: 10 }),
      finding({ id: 'no-line', path: PICKUP, line: undefined }),
      finding({ id: 'secret', category: 'SECRET', path: PICKUP, line: 10 }),
    ]
    expect(ids(findings, '/api/pickup/export')).toEqual(['secret'])
  })
})

describe('fromArtifact: синтетические случаи', () => {
  it('пустой ответ — пустая карта', () => {
    expect(fromArtifact(artifact())).toEqual({ routes: [], rules: [], unresolved: [] })
  })

  it.each([
    ['permitAll', 'PUBLIC'],
    ['authenticated', 'AUTHENTICATED'],
    ['fullyAuthenticated', 'AUTHENTICATED'],
    ['rememberMe', 'AUTHENTICATED'],
    ['hasRole', 'ROLE'],
    ['hasAnyRole', 'ROLE'],
    ['hasAuthority', 'ROLE'],
    ['hasAnyAuthority', 'ROLE'],
    ['access', 'ROLE'],
    ['denyAll', 'DENY'],
    ['anonymous', 'UNKNOWN'],
    ['hasRoleX', 'UNKNOWN'],
  ])('доступ %s → %s', (access, expected) => {
    const map = fromArtifact(artifact(row({ rule: rule(access, 5) })))
    expect(map.routes[0].access).toBe(expected)
    expect(map.rules[0].access).toBe(expected)
    expect(map.routes[0].accessText).toBe(`${access}()`)
  })

  it('доступ не установлен — UNKNOWN, без номера правила и с записью в unresolved', () => {
    const map = fromArtifact(artifact(row({ accessStatus: 'unresolved', subsequentRules: [rule('denyAll', 9)] })))
    expect(map.routes[0]).toMatchObject({ access: 'UNKNOWN', accessText: 'не установлено', matchedRule: null, shadowedRules: [] })
    expect(map.unresolved).toEqual([
      { kind: 'route-access', path: 'src/Demo.kt', line: 10, reason: 'Доступ к /api/demo не установлен', subject: 'lab.app.DemoController.handle' },
    ])
  })

  it('matched без правила тоже считается неустановленным', () => {
    const map = fromArtifact(artifact(row({ rule: undefined })))
    expect(map.routes[0].access).toBe('UNKNOWN')
    expect(map.routes[0].matchedRule).toBeNull()
    expect(map.unresolved.map((u) => u.kind)).toEqual(['route-access'])
  })

  it('нет пути и метода — явная заглушка и любой метод', () => {
    const map = fromArtifact(artifact(row({ path: undefined, method: undefined, accessStatus: 'unresolved' })))
    expect(map.routes[0].path).toBe('(путь не установлен)')
    expect(map.routes[0].method).toBeNull()
    expect(map.unresolved[0].reason).toBe('Доступ к (путь не установлен) не установлен')
  })

  it('затеняет только более строгие правила, кроме anyRequest', () => {
    const map = fromArtifact(artifact(row({
      rule: rule('authenticated', 5),
      subsequentRules: [rule('permitAll', 6), rule('fullyAuthenticated', 7), rule('hasRole', 8), rule('denyAll', 9), rule('denyAll', 10, 'anyRequest')],
    })))
    // Номера: 5→1, 6→2, 7→3, 8→4, 9→5, 10→6.
    expect(map.routes[0].matchedRule).toBe(1)
    expect(map.routes[0].shadowedRules).toEqual([4, 5])
  })

  it('правило с неизвестным выражением строже ничего не делает', () => {
    const map = fromArtifact(artifact(row({ rule: rule('permitAll', 5), subsequentRules: [rule('custom', 6)] })))
    expect(map.routes[0].shadowedRules).toEqual([])
  })

  it('правила из разных файлов: порядок по файлу, затем по строке; одно место — одно правило', () => {
    const map = fromArtifact(artifact(
      row({ rule: rule('permitAll', 30, 'requestMatchers', 'b/Sec.kt') }),
      row({ location: { file: 'src/Demo.kt', line: 40 }, rule: rule('authenticated', 50, 'requestMatchers', 'a/Sec.kt'), subsequentRules: [rule('permitAll', 30, 'requestMatchers', 'b/Sec.kt')] }),
    ))
    expect(map.rules.map((r) => `${r.order} ${r.location.path}:${r.location.line}`)).toEqual(['1 a/Sec.kt:50', '2 b/Sec.kt:30'])
    expect(map.routes.map((r) => r.matchedRule)).toEqual([2, 1])
  })

  it('обработчик — последние два сегмента имени, защита метода — по именам', () => {
    const map = fromArtifact(artifact(row({
      function: 'lab.app.admin.AdminController.purge',
      methodGuards: [{ name: 'PreAuthorize', file: 'src/Demo.kt', line: 9 }, { name: 'Secured', file: 'src/Demo.kt', line: 8 }],
      tables: [{ name: 'audit', ownerColumns: [], schemaKnown: false }],
    })))
    expect(map.routes[0].handler).toBe('AdminController.purge')
    expect(map.routes[0].methodSecurity).toEqual(['PreAuthorize', 'Secured'])
    expect(map.routes[0].tables).toEqual([{ name: 'audit', ownerColumns: [] }])
    expect(map.routes[0].tablesResolved).toBe(true)
    expect(map.unresolved).toEqual([])
  })

  it('не меняет входные данные', () => {
    const input = artifact(row({ subsequentRules: [rule('denyAll', 9)] }), row({ location: { file: 'src/Demo.kt', line: 3 } }))
    const copy = structuredClone(input)
    fromArtifact(input, [finding({ path: 'src/Demo.kt', line: 4 })])
    expect(input).toEqual(copy)
  })
})

describe('fromArtifact: выражение доступа из артефакта', () => {
  it('accessText из C8 (с аргументом роли) важнее имени метода; без него — как раньше', () => {
    const withText = structuredClone(fixture) as RouteMapArtifact
    for (const row of withText.routes) {
      for (const r of [row.rule, ...row.subsequentRules]) if (r && r.access === 'hasRole') r.accessText = 'hasRole("MECHANIC")'
    }
    const map = fromArtifact(withText)
    expect(map.rules.map((r) => r.accessText)).toContain('hasRole("MECHANIC")')
    expect(fromArtifact(fixture).rules.map((r) => r.accessText)).toContain('hasRole()')
  })
})
