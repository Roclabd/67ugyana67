/**
 * Преобразование Workflow (формат API) ↔ узлы и связи React Flow, проверка совместимости портов.
 * Проверка на фронте — подсказка пользователю; окончательно граф проверяет GraphValidator на сервере.
 */
import type { LiveNode } from '../store'
import type { Edge, Node } from '@xyflow/react'
import type { NodeDefinition, PortType, Workflow, WorkflowDraft, WorkflowNode } from '../api/types'

export type FlowNodeData = {
  nodeType: string
  params: Record<string, unknown>
  continueOnError?: boolean
}

export type FlowNode = Node<FlowNodeData & {
  live?: LiveNode
  invalidPorts?: string[]
}, 'step'>

export function toFlow(wf: WorkflowDraft): { nodes: FlowNode[]; edges: Edge[] } {
  return {
    nodes: wf.nodes.map((n) => ({
      id: n.id,
      type: 'step',
      position: n.position,
      data: { nodeType: n.type, params: n.params, continueOnError: n.continueOnError },
    })),
    edges: wf.edges.map((e) => ({
      id: e.id,
      source: e.from.node,
      sourceHandle: e.from.port,
      target: e.to.node,
      targetHandle: e.to.port,
    })),
  }
}

export function fromFlow(base: { id?: string; name: string; version?: number }, nodes: FlowNode[], edges: Edge[]): WorkflowDraft {
  return {
    ...(base.id ? { id: base.id } : {}),
    ...(base.version ? { version: base.version } : {}),
    name: base.name,
    nodes: nodes.map(
      (n): WorkflowNode => ({
        id: n.id,
        type: n.data.nodeType,
        params: n.data.params,
        position: { x: Math.round(n.position.x), y: Math.round(n.position.y) },
        ...(n.data.continueOnError ? { continueOnError: true } : {}),
      }),
    ),
    edges: edges.map((e) => ({
      id: e.id,
      from: { node: e.source, port: e.sourceHandle ?? '' },
      to: { node: e.target, port: e.targetHandle ?? '' },
    })),
  }
}

export function isSaved(wf: WorkflowDraft): wf is Workflow {
  return typeof wf.id === 'string' && typeof wf.version === 'number'
}

/** ANY совместим со всем, остальные — только с тем же типом (как в GraphValidator). */
export function portsCompatible(out: PortType, inp: PortType): boolean {
  return out === 'ANY' || inp === 'ANY' || out === inp
}

/** У замены должны сохраниться имена и совместимость всех подключённых портов. */
export function keepsNodeConnections(
  nodeId: string,
  replacement: NodeDefinition,
  edges: Edge[],
  portType: (nodeId: string, handle: string | null | undefined, side: 'out' | 'in') => PortType | undefined,
): boolean {
  return edges.every((edge) => {
    if (edge.target === nodeId) {
      const input = replacement.inputs.find((port) => port.name === edge.targetHandle)
      const output = portType(edge.source, edge.sourceHandle, 'out')
      return Boolean(input && output && portsCompatible(output, input.type))
    }
    if (edge.source === nodeId) {
      const output = replacement.outputs.find((port) => port.name === edge.sourceHandle)
      const input = portType(edge.target, edge.targetHandle, 'in')
      return Boolean(output && input && portsCompatible(output.type, input))
    }
    return true
  })
}

/** Параметры по умолчанию из JSON-схемы ноды. */
export function defaultParams(def: NodeDefinition): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, s] of Object.entries(def.paramsSchema.properties ?? {})) {
    if (s.default !== undefined) out[k] = s.default
  }
  return out
}

export function newNodeId(existing: { id: string }[]): string {
  let i = existing.length + 1
  while (existing.some((n) => n.id === `n${i}`)) i++
  return `n${i}`
}

/**
 * Раскладка по слоям графа: слой ноды — длина самого длинного пути до неё от триггеров, слои идут слева направо,
 * внутри слоя порядок по средней высоте предшественников (меньше пересечений). Нужна для черновиков от LLM:
 * модель ставит координаты как попало. Ноды из циклов (их отклонит сервер) остаются в нулевом слое.
 */
export function layeredLayout(
  draft: Pick<WorkflowDraft, 'nodes' | 'edges'>,
  spacing = { x: 250, y: 120 },
): Record<string, { x: number; y: number }> {
  const ids = draft.nodes.map((n) => n.id)
  const known = new Set(ids)
  const preds = new Map<string, string[]>(ids.map((id) => [id, []]))
  for (const e of draft.edges) {
    if (known.has(e.from.node) && known.has(e.to.node) && e.from.node !== e.to.node) preds.get(e.to.node)!.push(e.from.node)
  }
  const layer = new Map<string, number>()
  const visiting = new Set<string>()
  const depth = (id: string): number => {
    const cached = layer.get(id)
    if (cached !== undefined) return cached
    if (visiting.has(id)) return 0
    visiting.add(id)
    const d = Math.max(-1, ...preds.get(id)!.map(depth)) + 1
    visiting.delete(id)
    layer.set(id, d)
    return d
  }
  ids.forEach(depth)

  const columns: string[][] = []
  for (const id of ids) (columns[layer.get(id)!] ??= []).push(id)
  const y = new Map<string, number>()
  const out: Record<string, { x: number; y: number }> = {}
  columns.forEach((column, index) => {
    const order = column
      .map((id, i) => {
        const ys = preds.get(id)!.map((p) => y.get(p)).filter((v): v is number => v !== undefined)
        return { id, key: ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : i * spacing.y }
      })
      .sort((a, b) => a.key - b.key)
    order.forEach(({ id }, i) => {
      const pos = { x: index * spacing.x, y: (i - (order.length - 1) / 2) * spacing.y }
      y.set(id, pos.y)
      out[id] = pos
    })
  })
  return out
}

/**
 * Удалили ноду из простой цепочки (ровно одна входящая и одна исходящая связь) — соединить соседей напрямую,
 * если типы их портов совместимы и вход соседа свободен. Ветвления и несовместимые порты не трогаем:
 * лучше оставить разрыв, который подсветит проверка графа, чем угадать связь.
 */
export function bridgeEdges(
  deletedIds: string[],
  edges: Edge[],
  portType: (nodeId: string, handle: string | null | undefined, side: 'out' | 'in') => PortType | undefined,
): Edge[] {
  const deleted = new Set(deletedIds)
  const remaining = edges.filter((e) => !deleted.has(e.source) && !deleted.has(e.target))
  const bridges: Edge[] = []
  for (const id of deletedIds) {
    const incoming = edges.filter((e) => e.target === id)
    const outgoing = edges.filter((e) => e.source === id)
    if (incoming.length !== 1 || outgoing.length !== 1) continue
    const [from, to] = [incoming[0], outgoing[0]]
    if (deleted.has(from.source) || deleted.has(to.target) || from.source === to.target) continue
    const out = portType(from.source, from.sourceHandle, 'out')
    const inp = portType(to.target, to.targetHandle, 'in')
    if (!out || !inp || !portsCompatible(out, inp)) continue
    const taken = [...remaining, ...bridges].some((e) => e.target === to.target && e.targetHandle === to.targetHandle)
    if (taken) continue
    bridges.push({
      id: `e-${from.source}-${from.sourceHandle}-${to.target}-${to.targetHandle}`,
      source: from.source, sourceHandle: from.sourceHandle, target: to.target, targetHandle: to.targetHandle,
    })
  }
  return bridges
}

export interface Rect { x: number; y: number; w: number; h: number }

/** Примерный размер ноды на холсте, пока React Flow её не измерил. */
export const NODE_SIZE = { w: 200, h: 130 }

/**
 * Свободное место для новой ноды: справа от опорной (выбранной/последней), иначе в видимой области сверху вниз,
 * не накладываясь на существующие. viewport — видимая область в координатах графа (null — не ограничивать).
 */
export function freeSpot(
  nodes: { position: { x: number; y: number }; width?: number | null; height?: number | null }[],
  viewport: Rect | null,
  anchor: { x: number; y: number; w?: number } | null,
  size = NODE_SIZE,
  gap = 40,
): { x: number; y: number } {
  const boxes = nodes.map((n) => ({ x: n.position.x, y: n.position.y, w: n.width ?? size.w, h: n.height ?? size.h }))
  const free = (p: { x: number; y: number }) =>
    !boxes.some((b) => p.x < b.x + b.w + gap / 2 && p.x + size.w + gap / 2 > b.x && p.y < b.y + b.h + gap / 2 && p.y + size.h + gap / 2 > b.y)
  const visible = (p: { x: number; y: number }) =>
    !viewport || (p.x >= viewport.x && p.y >= viewport.y && p.x + size.w <= viewport.x + viewport.w && p.y + size.h <= viewport.y + viewport.h)
  const stepX = size.w + gap
  const stepY = size.h + gap
  const candidates: { x: number; y: number }[] = []
  // Первая нода — слева по центру по высоте
  if (!anchor && viewport) candidates.push({ x: viewport.x + gap, y: viewport.y + (viewport.h - size.h) / 2 })
  const originX = viewport ? viewport.x + gap : 0
  if (anchor) {
    const bx = anchor.x + (anchor.w ?? size.w) + gap
    // справа в той же строке; не влезло — следующая строка с левого края окна; затем другие места рядом
    candidates.push({ x: bx, y: anchor.y }, { x: originX, y: anchor.y + stepY }, { x: originX, y: anchor.y + 2 * stepY })
    for (const k of [1, -1, 2, -2]) candidates.push({ x: bx, y: anchor.y + k * stepY })
  }
  const originY = viewport ? viewport.y + gap : 0
  const cols = viewport ? Math.max(1, Math.floor((viewport.w - gap) / stepX)) : 6
  const rows = viewport ? Math.max(1, Math.floor((viewport.h - gap) / stepY)) : 6
  for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) candidates.push({ x: originX + c * stepX, y: originY + r * stepY })
  const ok = candidates.find((p) => free(p) && visible(p))
  if (ok) return ok
  const anyFree = candidates.find(free)
  if (anyFree) return anyFree
  const right = boxes.reduce((m, b) => Math.max(m, b.x + b.w), originX)
  return { x: right + gap, y: originY }
}

/**
 * Замена ноды на другой тип с сохранением позиции и связей: порт нового типа берётся с тем же именем,
 * иначе — свободный порт с тем же типом. Связи, которым не нашлось порта, возвращаются в dropped.
 */
export function remapEdgesForReplacement(
  nodeId: string,
  oldDef: NodeDefinition | undefined,
  newDef: NodeDefinition,
  edges: Edge[],
): { edges: Edge[]; dropped: Edge[] } {
  const used = new Set<string>()
  const dropped: Edge[] = []
  const out = edges.flatMap((edge): Edge[] => {
    const isIn = edge.target === nodeId
    const isOut = edge.source === nodeId
    if (!isIn && !isOut) return [edge]
    const handle = isIn ? edge.targetHandle : edge.sourceHandle
    const oldPorts = isIn ? oldDef?.inputs : oldDef?.outputs
    const newPorts = isIn ? newDef.inputs : newDef.outputs
    const oldType = oldPorts?.find((p) => p.name === handle)?.type
    const key = (name: string) => `${isIn ? 'in' : 'out'}:${name}`
    const sameName = newPorts.find((p) => p.name === handle && !used.has(key(p.name)))
    const pick = sameName ?? newPorts.find((p) => oldType !== undefined && p.type === oldType && !used.has(key(p.name)))
    if (!pick) {
      dropped.push(edge)
      return []
    }
    used.add(key(pick.name))
    if (pick.name === handle) return [edge]
    const next = isIn ? { ...edge, targetHandle: pick.name } : { ...edge, sourceHandle: pick.name }
    return [{ ...next, id: `e-${next.source}-${next.sourceHandle}-${next.target}-${next.targetHandle}` }]
  })
  return { edges: out, dropped }
}

export interface PortChoice { nodeId: string; port: string; type: PortType }

/**
 * Куда можно переподключить связь: только совместимые порты (portsCompatible), без занятых другими связями.
 * side 'target' — другой приёмник для того же источника, 'source' — другой источник для того же приёмника.
 */
export function compatiblePorts(
  edge: Edge,
  side: 'target' | 'source',
  nodes: { id: string; data: { nodeType: string } }[],
  edges: Edge[],
  defOf: (nodeType: string) => NodeDefinition | undefined,
  portType: (nodeId: string, handle: string | null | undefined, side: 'out' | 'in') => PortType | undefined,
): PortChoice[] {
  const fixed = side === 'target' ? portType(edge.source, edge.sourceHandle, 'out') : portType(edge.target, edge.targetHandle, 'in')
  if (!fixed) return []
  const result: PortChoice[] = []
  for (const n of nodes) {
    if (n.id === (side === 'target' ? edge.source : edge.target)) continue
    const def = defOf(n.data.nodeType)
    if (!def) continue
    for (const p of side === 'target' ? def.inputs : def.outputs) {
      const compatible = side === 'target' ? portsCompatible(fixed, p.type) : portsCompatible(p.type, fixed)
      if (!compatible) continue
      if (side === 'target') {
        const taken = edges.some((e) => e.id !== edge.id && e.target === n.id && e.targetHandle === p.name)
        if (taken || (n.id === edge.target && p.name === edge.targetHandle)) continue
      } else if (n.id === edge.source && p.name === edge.sourceHandle) continue
      result.push({ nodeId: n.id, port: p.name, type: p.type })
    }
  }
  return result
}
