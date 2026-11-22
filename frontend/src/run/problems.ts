/**
 * «Где сломалось»: проблемные этапы запуска в порядке графа. Чистые функции — без React и стора.
 */
import type { AnalyzerCoverage, NodeStatus, SkipCause } from '../api/types'
import { t } from '../i18n'

/** Минимум от NodeRun/LiveNode, нужный для разбора. */
export interface ProblemNodeRun {
  status: NodeStatus
  error?: string
  coverage?: AnalyzerCoverage
  skipCause?: SkipCause
  failureContextNodeIds?: string[]
}

export interface ProblemStep {
  nodeId: string
  title: string
  status: 'FAILED' | 'PARTIAL' | 'SKIPPED'
  reason: string
  primary: boolean
  causeIds: string[]
}

/** Порядок нод по графу (топологический, при равенстве — как в исходном списке). Циклы дописываются в конец. */
export function graphOrder(nodeIds: string[], edges: { from: string; to: string }[]): string[] {
  const known = new Set(nodeIds)
  const indeg = new Map(nodeIds.map((id) => [id, 0]))
  const out = new Map<string, string[]>(nodeIds.map((id) => [id, []]))
  for (const e of edges) {
    if (!known.has(e.from) || !known.has(e.to) || e.from === e.to) continue
    out.get(e.from)!.push(e.to)
    indeg.set(e.to, indeg.get(e.to)! + 1)
  }
  const result: string[] = []
  const done = new Set<string>()
  while (result.length < nodeIds.length) {
    const next = nodeIds.find((id) => !done.has(id) && indeg.get(id) === 0)
    if (next === undefined) {
      for (const id of nodeIds) if (!done.has(id)) result.push(id)
      break
    }
    done.add(next)
    result.push(next)
    for (const t of out.get(next)!) indeg.set(t, indeg.get(t)! - 1)
  }
  return result
}

/** Короткая причина неполноты PARTIAL-ноды: текст ошибки, иначе по покрытию анализатора. */
export function partialReason(node: ProblemNodeRun, ai = false): string {
  // Объяснения AI необязательны: их неполнота не делает анализ неполным.
  if (ai) return node.error ? t('prob.aiPartialErr', { e: node.error }) : t('prob.aiPartial')
  if (node.error) return node.error
  const c = node.coverage
  if (c) {
    const first = c.unresolved[0]?.reason ?? c.filesSkipped[0]?.reason
    const n = c.unresolved.length + c.filesSkipped.length
    if (first) return t('prob.partialWhy', { first }) + (n > 1 ? t('prob.andMore', { n: n - 1 }) : '')
  }
  return t('prob.incomplete')
}

export function isPrimaryFailure(node: ProblemNodeRun): boolean {
  return node.status === 'FAILED' && !node.failureContextNodeIds?.length
}

export function nodeReason(node: ProblemNodeRun, ai = false): string | null {
  if (node.status === 'FAILED') return node.error || t('prob.execFail')
  if (node.status === 'PARTIAL') return partialReason(node, ai)
  if (node.status === 'SKIPPED') {
    switch (node.skipCause?.reason) {
      case 'UPSTREAM_FAILURE': return t('prob.upstream')
      case 'RUN_STOPPED': return t('prob.stopped')
      case 'INACTIVE_BRANCH': return t('prob.inactive')
      case 'MISSING_INPUT': return t('prob.noInput')
    }
  }
  return null
}

export function blockedEdgeIds(nodes: Record<string, ProblemNodeRun>): Set<string> {
  return new Set(Object.values(nodes).flatMap((node) =>
    node.status === 'SKIPPED' && node.skipCause?.reason === 'UPSTREAM_FAILURE' ? node.skipCause.edgeIds : [],
  ))
}

/** Проблемы в порядке графа. Обычный пропуск и пропуск без установленной причины нейтральны. */
export function findProblems(
  order: { id: string; title: string; ai?: boolean; delivery?: boolean }[],
  nodes: Record<string, ProblemNodeRun>,
): ProblemStep[] {
  const known = new Set(order.map((item) => item.id))
  const items: typeof order = [
    ...order,
    ...Object.keys(nodes).filter((id) => !known.has(id)).map((id) => ({ id, title: id })),
  ]
  const problems: ProblemStep[] = []
  for (const { id, title, ai, delivery } of items) {
    const node = nodes[id]
    if (!node) continue
    const { status, skipCause, failureContextNodeIds } = node
    const blocked = skipCause?.reason === 'UPSTREAM_FAILURE' || skipCause?.reason === 'RUN_STOPPED'
    if (status !== 'FAILED' && status !== 'PARTIAL' && !(status === 'SKIPPED' && blocked)) continue
    const reason = nodeReason(node, ai)
    if (reason) problems.push({
      nodeId: id, title, status, reason,
      primary: !delivery && isPrimaryFailure(node),
      causeIds: status === 'SKIPPED' ? skipCause?.nodeIds ?? [] : failureContextNodeIds ?? [],
    })
  }
  return problems.sort((a, b) => Number(b.primary) - Number(a.primary))
}
