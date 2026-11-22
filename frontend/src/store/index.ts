/**
 * Общее состояние приложения (zustand). 
 * Здесь только то, что нужно нескольким экранам: каталог нод и живое состояние текущего запуска.
 * Данные отдельных экранов грузятся через useApi в самом экране.
 */
import { create } from 'zustand'
import { api, subscribeRunEvents } from '../api/client'
import { errorMessage } from '../api/errors'
import type { NodeDefinition, NodeRun, NodeStatus, Run, RunEvent, RunStatus } from '../api/types'

// ───────────── Каталог нод ─────────────

interface CatalogState {
  nodes: NodeDefinition[]
  byType: Record<string, NodeDefinition>
  status: 'idle' | 'loading' | 'ready' | 'error'
  error: string | null
  load: () => Promise<void>
}

export const useCatalog = create<CatalogState>((set, get) => ({
  nodes: [],
  byType: {},
  status: 'idle',
  error: null,
  load: async () => {
    if (get().status === 'loading' || get().status === 'ready') return
    set({ status: 'loading', error: null })
    try {
      const nodes = await api.listNodes()
      set({ nodes, byType: Object.fromEntries(nodes.map((n) => [n.type, n])), status: 'ready' })
    } catch (err) {
      set({ status: 'error', error: errorMessage(err) })
    }
  },
}))

// ───────────── Живой запуск ─────────────

export interface LiveNode extends NodeRun {
  /** Ход выполнения из node.progress, пока нода работает. */
  progress?: { percent: number; note?: string | null }
}

interface LiveRunState {
  runId: string | null
  status: RunStatus | null
  workflowId: string | null
  workflowVersion: number | null
  nodes: Record<string, LiveNode>
  /** Начать следить за запуском. Прошлая подписка закрывается. */
  watch: (runId: string, workflowId: string, workflowVersion: number) => void
  restore: (run: Run) => void
  stop: () => void
}

let unsubscribe: (() => void) | null = null

/**
 * Итог запуска с сервера: статусы, покрытие, данные портов и логи нод.
 * SSE — для живого отображения; окончательное состояние берётся только из GET /runs/{id}.
 */
async function finalState(runId: string): Promise<{ status: RunStatus; nodes: Record<string, LiveNode> } | null> {
  try {
    const run = await api.getRun(runId)
    if (run.status === 'RUNNING') return null
    return { status: run.status, nodes: Object.fromEntries(run.nodeRuns.map((n) => [n.nodeId, n])) }
  } catch {
    return null
  }
}

function patchNode(nodes: Record<string, LiveNode>, nodeId: string, patch: Partial<LiveNode>): Record<string, LiveNode> {
  const prev: LiveNode = nodes[nodeId] ?? { nodeId, status: 'PENDING' as NodeStatus, logs: [] }
  return { ...nodes, [nodeId]: { ...prev, ...patch } }
}

export const useLiveRun = create<LiveRunState>((set, get) => ({
  runId: null,
  status: null,
  workflowId: null,
  workflowVersion: null,
  nodes: {},
  watch: (runId, workflowId, workflowVersion) => {
    unsubscribe?.()
    set({ runId, workflowId, workflowVersion, status: 'RUNNING', nodes: {} })
    const settle = async () => {
      const final = await finalState(runId)
      if (!final || get().runId !== runId) return
      set(final)
      unsubscribe?.()
      unsubscribe = null
    }
    const onEvent = (e: RunEvent) => {
      if (get().runId !== runId) return
      switch (e.type) {
        case 'node.status':
          set((s) => ({
            nodes: patchNode(s.nodes, e.data.nodeId, {
              status: e.data.status,
              ...(e.data.startedAt ? { startedAt: e.data.startedAt } : {}),
              ...(e.data.finishedAt ? { finishedAt: e.data.finishedAt } : {}),
              error: e.data.error ?? undefined,
              coverage: e.data.coverage ?? undefined,
              skipCause: e.data.skipCause ?? undefined,
              failureContextNodeIds: e.data.failureContextNodeIds ?? undefined,
            }),
          }))
          break
        case 'node.io':
          set((s) => ({ nodes: patchNode(s.nodes, e.data.nodeId, { input: e.data.input, output: e.data.output }) }))
          break
        case 'node.progress':
          set((s) => ({
            nodes: patchNode(s.nodes, e.data.nodeId, { progress: { percent: e.data.percent, note: e.data.note } }),
          }))
          break
        case 'log':
          set((s) => ({
            nodes: patchNode(s.nodes, e.data.nodeId, { logs: [...(s.nodes[e.data.nodeId]?.logs ?? []), e.data.message] }),
          }))
          break
        case 'run.status':
          set({ status: e.data.status })
          if (e.data.status !== 'RUNNING') void settle()
          break
      }
    }
    // Обрыв потока: если запуск уже завершён (например, закончился до подписки) — берём итог с сервера.
    unsubscribe = subscribeRunEvents(runId, onEvent, () => void settle())
  },
  restore: (run) => {
    if (run.status === 'RUNNING') {
      if (get().runId !== run.runId) get().watch(run.runId, run.workflowId, run.workflowVersion)
      return
    }
    unsubscribe?.()
    unsubscribe = null
    set({
      runId: run.runId,
      workflowId: run.workflowId,
      workflowVersion: run.workflowVersion,
      status: run.status,
      nodes: Object.fromEntries(run.nodeRuns.map((node) => [node.nodeId, node])),
    })
  },
  stop: () => {
    unsubscribe?.()
    unsubscribe = null
    set({ runId: null, workflowId: null, workflowVersion: null, status: null, nodes: {} })
  },
}))
