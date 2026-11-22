/**
 * Карта маршрутов (киллер-фича 3, поверхность атаки): все эндпоинты с уровнем доступа, сработавшим правилом
 * Spring Security, затенёнными правилами и данными, которые маршрут трогает. Данные — ответ ноды output.route-map (C8) через адаптер fromArtifact.
 * Подсветка строк — подсказка для глаза по данным сервера; находки определяют только анализаторы (они в колонке «Находки»).
 */
import type { Finding, RouteAccess, RouteEntry, RouteMap, SecurityRuleInfo } from '../../api/types'
import { Card } from '../../ui'
import { formatLocation } from '../../ui/format'
import { findingLabel } from '../findings'
import { t } from '../../i18n'

const ACCESS_LABEL: Record<RouteAccess, string> = {
  get PUBLIC() { return t('route.access.PUBLIC') },
  get AUTHENTICATED() { return t('route.access.AUTHENTICATED') },
  get ROLE() { return t('route.access.ROLE') },
  get DENY() { return t('route.access.DENY') },
  get UNKNOWN() { return t('route.access.UNKNOWN') },
}

const ACCESS_BADGE: Record<RouteAccess, string> = {
  PUBLIC: 'badge--HIGH',
  AUTHENTICATED: 'badge--neutral',
  ROLE: 'badge--SUCCESS',
  DENY: 'badge--neutral',
  UNKNOWN: 'badge--PARTIAL',
}

/**
 * Подсказки по фактам маршрута: risk — установленный факт, из-за которого строку стоит рассмотреть
 * (подсвечивается и считается); unknown — чего не удалось установить (видно, но не считается риском).
 */
function routeHints(r: RouteEntry, rules: Map<number, SecurityRuleInfo>): { risk: string[]; unknown: string[] } {
  const hints: string[] = []
  const unknown: string[] = []
  for (const n of r.shadowedRules) {
    const rule = rules.get(n)
    hints.push(t('route.shadows', { n }) + (rule ? ' ' + rule.accessText : ''))
  }
  // Колонки известны — называем те, что отдаются; неизвестны — достаточно, что у таблицы есть владелец.
  const owners = r.tables.flatMap((t) =>
    (t.columns ? t.columns.filter((c) => t.ownerColumns.includes(c)) : t.ownerColumns).map((c) => `${t.name}.${c}`))
  if (r.access === 'PUBLIC' && owners.length) hints.push(t('route.noLogin', { o: owners.join(', ') }))
  const ownedTable = r.tables.some((t) => t.ownerColumns.length > 0)
  if (ownedTable && r.principal === false && r.params?.some((p) => p.source === 'PATH')) hints.push(t('route.idPath'))
  if (r.access === 'PUBLIC' && r.tablesResolved === false) unknown.push(t('route.unknownData'))
  if (r.access === 'UNKNOWN') unknown.push(t('route.unknownAccess'))
  return { risk: hints, unknown }
}

export function RouteMapView({ map, findings = [] }: { map: RouteMap; findings?: Finding[] }) {
  const ownerCol = t('route.ownerCol')
  const ownerWord = t('route.owner')
  const rules = new Map(map.rules.map((r) => [r.order, r]))
  const byId = new Map(findings.map((f) => [f.id, f]))
  const risky = map.routes.filter((r) => routeHints(r, rules).risk.length > 0 || r.findingIds.length > 0).length
  return (
    <Card title={t('route.title', { n: map.routes.length, r: risky })}>
      <div className="stack">
        <div className="table-scroll">
          <table className="table routes">
            <thead>
              <tr>
                <th>{t('route.thRoute')}</th>
                <th>{t('route.thAccess')}</th>
                <th>{t('route.thHandler')}</th>
                <th>{t('route.thData')}</th>
                <th>{t('route.thFindings')}</th>
              </tr>
            </thead>
            <tbody>
              {map.routes.map((r, i) => {
                const { risk: hints, unknown } = routeHints(r, rules)
                return (
                  <tr key={i} className={hints.length || r.findingIds.length ? 'routes__row--risk' : undefined}>
                    <td className="mono">
                      <strong>{r.method ?? 'ANY'}</strong> {r.path}
                      {r.params && r.params.length > 0 && (
                        <div className="muted">{r.params.map((p) => `${p.name}: ${p.source.toLowerCase()}`).join(', ')}</div>
                      )}
                    </td>
                    <td>
                      <span className={`badge ${ACCESS_BADGE[r.access]}`}>{ACCESS_LABEL[r.access]}</span>
                      <div className="mono muted">
                        {r.matchedRule ? `#${r.matchedRule} ` : ''}{r.accessText}
                      </div>
                      {r.methodSecurity.map((m, k) => <div key={k} className="mono muted">{m}</div>)}
                      {r.principal && <div className="muted">{t('route.principal')}</div>}
                    </td>
                    <td className="mono">
                      {r.handler}
                      <div className="muted">{formatLocation(r.location.path, r.location.line, r.location.endLine)}</div>
                    </td>
                    <td className="mono">
                      {r.tablesResolved === false && <span className="muted">{t('route.notDetermined')}</span>}
                      {r.tablesResolved !== false && r.tables.length === 0 && <span className="muted">—</span>}
                      {r.tables.map((t) => (
                        <div key={t.name}>
                          {t.name}(
                          {(t.columns ?? t.ownerColumns).map((c, k) => (
                            <span key={c}>
                              {k > 0 && ', '}
                              {t.ownerColumns.includes(c) ? <strong title={ownerCol}>{c}</strong> : c}
                            </span>
                          ))}
                          {!t.columns && t.ownerColumns.length > 0 && <span className="muted"> — {ownerWord}</span>}
                          )
                        </div>
                      ))}
                    </td>
                    <td>
                      {r.findingIds.map((id) => {
                        const f = byId.get(id)
                        return <div key={id}><span className="badge badge--FAILED">{f ? findingLabel(f) : id}</span></div>
                      })}
                      {hints.map((h, k) => <div key={k} className="routes__hint">{h}</div>)}
                      {unknown.map((h, k) => <div key={`u${k}`} className="muted">{h}</div>)}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        <details>
          <summary>{t('route.rules', { n: map.rules.length })}</summary>
          <ol className="routes__rules">
            {map.rules.map((r) => (
              <li key={r.order} className="mono">
                {r.anyRequest ? 'anyRequest()' : `${r.method ?? 'ANY'} ${r.patterns.join(', ')}`} → {r.accessText}
                <span className="muted"> · {formatLocation(r.location.path, r.location.line)}</span>
              </li>
            ))}
          </ol>
        </details>

        {map.unresolved.length > 0 && (
          <div className="alert alert--warn">
            <div className="alert__title">{t('route.unresolved', { n: map.unresolved.length })}</div>
            <ul className="coverage-list">
              {map.unresolved.map((u, i) => <li key={i}>{formatLocation(u.path, u.line)} — {u.reason}</li>)}
            </ul>
          </div>
        )}
      </div>
    </Card>
  )
}
