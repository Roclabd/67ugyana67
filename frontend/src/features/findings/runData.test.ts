import { describe, expect, it } from 'vitest'
import type { Finding, FindingAi, NodeRun, Report, ReportAi, Run } from '../../api/types'
import { runAi, runFindings } from './index'

function finding(id: string, over: Partial<Finding> = {}): Finding {
  return { id, fingerprint: `fp-${id}`, category: 'SAST', path: 'src/A.kt', line: 1, severity: 'HIGH', rule: 'r', evidence: [], ...over }
}

const ai = (explanation: string): FindingAi => ({ status: 'OK', explanation })

function node(nodeId: string, output?: unknown): NodeRun {
  return { nodeId, status: 'SUCCESS', output, logs: [] }
}

function report(findings: Finding[], reportAi?: ReportAi): Report {
  return { runId: 'r1', inputHash: 'h', rulesVersion: 'sast-1', coverage: { status: 'COMPLETE', byAnalyzer: {} }, findings, ai: reportAi }
}

function run(rep: Report | null, nodeRuns: NodeRun[] = []): Run {
  return {
    runId: 'r1', workflowId: 'w1', workflowVersion: 1, status: 'SUCCESS', coverageStatus: 'COMPLETE',
    counts: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }, startedAt: '2026-11-21T00:00:00Z', finishedAt: '2026-11-21T00:01:00Z',
    nodeRuns, report: rep,
  }
}

describe('runFindings', () => {
  it('без отчёта — пусто', () => {
    expect(runFindings(run(null, [node('ai', { findings: [finding('a', { ai: ai('x') })] })]))).toEqual([])
  })

  it('если у всех находок отчёта уже есть ai — возвращает их без изменений', () => {
    const findings = [finding('a', { ai: ai('из отчёта') })]
    const r = run(report(findings), [node('ai', { findings: [finding('a', { ai: ai('из ноды') })] })])
    expect(runFindings(r)).toBe(findings)
  })

  it('подмешивает ai из выхода ноды по отпечатку; набор и порядок — из отчёта', () => {
    const r = run(report([finding('b'), finding('a'), finding('c')]), [
      node('n1', { findings: [finding('a')] }), // анализатор: ai нет
      node('n5', { findings: [finding('a', { ai: ai('A') }), finding('b', { ai: ai('B') }), finding('extra', { ai: ai('лишняя') })] }),
    ])
    const out = runFindings(r)
    expect(out.map((f) => f.id)).toEqual(['b', 'a', 'c'])
    expect(out.map((f) => f.ai?.explanation)).toEqual(['B', 'A', undefined])
  })

  it('ai из отчёта приоритетнее ai из ноды', () => {
    const r = run(report([finding('a', { ai: ai('отчёт') }), finding('b')]), [
      node('n5', { findings: [finding('a', { ai: ai('нода') }), finding('b', { ai: ai('нода B') })] }),
    ])
    expect(runFindings(r).map((f) => f.ai?.explanation)).toEqual(['отчёт', 'нода B'])
  })

  it('сопоставляет по fingerprint, а не по id', () => {
    const r = run(report([finding('a', { fingerprint: 'same' })]), [
      node('n5', { findings: [finding('a', { fingerprint: 'other', ai: ai('чужая') }), finding('z', { fingerprint: 'same', ai: ai('своя') })] }),
    ])
    expect(runFindings(r)[0].ai?.explanation).toBe('своя')
  })

  it('пропускает ноды без выхода и с выходом не той формы', () => {
    const r = run(report([finding('a')]), [
      node('n0'),
      node('n1', null),
      node('n2', 'text'),
      node('n3', { findings: 'not-an-array' }),
      node('n4', { findings: [{ ...finding('a', { ai: ai('без отпечатка') }), fingerprint: '' }] }),
      node('n5', { findings: [finding('a', { ai: ai('ok') })] }),
    ])
    expect(runFindings(r)[0].ai?.explanation).toBe('ok')
  })

  it('не меняет находки отчёта', () => {
    const original = finding('a')
    const r = run(report([original]), [node('n5', { findings: [finding('a', { ai: ai('A') })] })])
    const out = runFindings(r)
    expect(out[0]).not.toBe(original)
    expect(original.ai).toBeUndefined()
  })

  it('без пары находка остаётся без ai', () => {
    const r = run(report([finding('a')]), [node('n5', { findings: [] })])
    expect(runFindings(r)[0].ai).toBeUndefined()
  })
})

describe('runAi', () => {
  const nodeAi: ReportAi = { status: 'OK', model: 'm', summary: 'из ноды', validator: { responses: 3, schemaFailures: 0, rejectedFindingRefs: 0, rejectedCves: 0 } }
  const explanationNode = (a: unknown) => node('n5', { explanation: { text: 'Текст', ai: a, usefulness: {} } })

  it('без отчёта и без ноды — null', () => {
    expect(runAi(run(null))).toBeNull()
    expect(runAi(run(report([])))).toBeNull()
  })

  it('отчёт с summary побеждает выход ноды', () => {
    const fromReport: ReportAi = { status: 'OK', summary: 'из отчёта' }
    expect(runAi(run(report([], fromReport), [explanationNode(nodeAi)]))).toBe(fromReport)
  })

  it('отчёт со счётчиками валидатора (без summary) тоже побеждает', () => {
    const fromReport: ReportAi = { status: 'PARTIAL', validator: { responses: 1, schemaFailures: 1, rejectedFindingRefs: 0, rejectedCves: 0 } }
    expect(runAi(run(report([], fromReport), [explanationNode(nodeAi)]))).toBe(fromReport)
  })

  it('отчёт только со статусом — берётся раздел ai из explanation ноды ai.explain', () => {
    expect(runAi(run(report([], { status: 'NOT_RECEIVED' }), [node('n1', { findings: [] }), explanationNode(nodeAi)]))).toBe(nodeAi)
  })

  it('без раздела ai в отчёте — тоже из ноды', () => {
    expect(runAi(run(report([]), [explanationNode(nodeAi)]))).toBe(nodeAi)
    expect(runAi(run(null, [explanationNode(nodeAi)]))).toBe(nodeAi)
  })

  it('объяснение без ai или без статуса пропускается, берётся следующее', () => {
    const r = run(report([]), [node('n0'), node('n1', { explanation: { text: 'x' } }), explanationNode({ summary: 'без статуса' }), node('n6', { explanation: { ai: nodeAi } })])
    expect(runAi(r)).toBe(nodeAi)
  })

  it('нет подходящей ноды — остаётся раздел отчёта со статусом', () => {
    const fromReport: ReportAi = { status: 'NOT_RECEIVED', reason: 'LLM не настроена' }
    expect(runAi(run(report([], fromReport), [node('n1', { findings: [] })]))).toBe(fromReport)
  })
})
