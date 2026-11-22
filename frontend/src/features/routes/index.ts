/** Карта маршрутов (D7). Источник — нода output.route-map (C8), порт report; экран работает с моделью RouteMap. */
import type { Finding, RouteMap, Run } from '../../api/types'
import { fromArtifact, isRouteMapArtifact } from './fromArtifact'

export { RouteMapView } from './RouteMapView'
export { fromArtifact, isRouteMapArtifact } from './fromArtifact'

/** Карта маршрутов запуска: первый выход ноды с ответом C8; null — такой ноды в сценарии нет. */
export function runRoutes(run: Run, findings: Finding[] = []): RouteMap | null {
  for (const n of run.nodeRuns) {
    const out = n.output as Record<string, unknown> | undefined
    for (const value of Object.values(out ?? {})) if (isRouteMapArtifact(value)) return fromArtifact(value, findings)
  }
  return null
}
