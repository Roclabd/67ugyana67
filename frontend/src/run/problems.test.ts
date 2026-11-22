import { describe, expect, it } from 'vitest'
import { blockedEdgeIds, findProblems, graphOrder, type ProblemNodeRun } from './problems'

const order = [
  { id: 'n1', title: 'Репозиторий' },
  { id: 'n2', title: 'SAST' },
  { id: 'n3', title: 'Отчёт' },
]

describe('graphOrder', () => {
  it('сортирует топологически, при равенстве — по исходному порядку', () => {
    expect(graphOrder(['c', 'b', 'a'], [{ from: 'a', to: 'b' }, { from: 'b', to: 'c' }])).toEqual(['a', 'b', 'c'])
    expect(graphOrder(['x', 'y'], [])).toEqual(['x', 'y'])
  })
  it('цикл не зацикливает', () => {
    expect(graphOrder(['a', 'b'], [{ from: 'a', to: 'b' }, { from: 'b', to: 'a' }])).toHaveLength(2)
  })
})

describe('findProblems', () => {
  it('выделяет первичный сбой и подтверждённую зависимость даже до завершения запуска', () => {
    const snapshot: Record<string, ProblemNodeRun> = {
      n1: { status: 'FAILED', error: 'Архив не найден' },
      n2: { status: 'SKIPPED', skipCause: { reason: 'UPSTREAM_FAILURE', nodeIds: ['n1'], edgeIds: ['e1'] } },
      n3: { status: 'RUNNING' },
    }
    const problems = findProblems(order, snapshot)
    expect(problems.map(({ nodeId, primary, causeIds }) => ({ nodeId, primary, causeIds }))).toEqual([
      { nodeId: 'n1', primary: true, causeIds: [] },
      { nodeId: 'n2', primary: false, causeIds: ['n1'] },
    ])
    expect([...blockedEdgeIds(snapshot)]).toEqual(['e1'])
  })

  it('обычный пропуск и старый SKIPPED без причины не выделяются', () => {
    expect(findProblems(order, {
      n1: { status: 'FAILED' },
      n2: { status: 'SKIPPED', skipCause: { reason: 'INACTIVE_BRANCH', nodeIds: [], edgeIds: [] } },
      n3: { status: 'SKIPPED' },
    }).map((problem) => problem.nodeId)).toEqual(['n1'])
  })

  it('показывает обе независимые причины и отделяет сбой уведомления', () => {
    const problems = findProblems(order, {
      n1: { status: 'FAILED' },
      n2: { status: 'FAILED' },
      n3: { status: 'FAILED', failureContextNodeIds: ['n1', 'n2'] },
    })
    expect(problems.map((problem) => problem.primary)).toEqual([true, true, false])
    expect(problems[2].causeIds).toEqual(['n1', 'n2'])
  })

  it('общая остановка видна без подсветки неподтверждённых связей', () => {
    const nodes = {
      n1: { status: 'FAILED' as const },
      n2: { status: 'SKIPPED' as const, skipCause: { reason: 'RUN_STOPPED' as const, nodeIds: ['n1'], edgeIds: [] } },
    }
    expect(findProblems(order, nodes)[1].reason).toBe('Выполнение остановлено')
    expect(blockedEdgeIds(nodes).size).toBe(0)
  })

  it('PARTIAL анализатора берёт причину из покрытия', () => {
    const coverage = {
      status: 'PARTIAL' as const,
      filesAnalyzed: 3,
      filesSkipped: [{ path: 'a.bin', reason: 'бинарный файл' }],
      rulesApplied: [],
      unresolved: [],
      dismissed: [],
    }
    const res = findProblems(order, { n1: { status: 'SUCCESS' }, n2: { status: 'PARTIAL', coverage } })
    expect(res).toMatchObject([{ nodeId: 'n2', title: 'SAST', status: 'PARTIAL', reason: 'анализ неполный: бинарный файл', primary: false }])
  })

  it('всё успешно — пусто', () => {
    expect(findProblems(order, { n1: { status: 'SUCCESS' }, n2: { status: 'SUCCESS' } })).toEqual([])
  })

  it('AI PARTIAL говорит про объяснения, а не про неполный анализ', () => {
    const problems = findProblems(
      [...order, { id: 'ai', title: 'AI', ai: true }],
      { n1: { status: 'SUCCESS' }, ai: { status: 'PARTIAL' } },
    )
    expect(problems).toHaveLength(1)
    expect(problems[0].reason).toBe('Объяснения AI неполные')
  })
})
