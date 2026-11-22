import { describe, expect, it } from 'vitest'
import type { NodeDefinition, PortType, WorkflowDraft } from '../api/types'
import { bridgeEdges, compatiblePorts, defaultParams, freeSpot, fromFlow, isSaved, keepsNodeConnections, layeredLayout, newNodeId, portsCompatible, remapEdgesForReplacement, toFlow } from './graph'

const edge = (id: string, from: string, to: string, fromPort = 'out', toPort = 'in') =>
  ({ id, from: { node: from, port: fromPort }, to: { node: to, port: toPort } })
const node = (id: string, type = 't', position = { x: 0, y: 0 }) => ({ id, type, params: {}, position })

describe('portsCompatible', () => {
  it('ANY совместим с любым типом, остальные — только с тем же (как GraphValidator)', () => {
    expect(portsCompatible('ANY', 'FINDINGS')).toBe(true)
    expect(portsCompatible('REPORT', 'ANY')).toBe(true)
    expect(portsCompatible('FINDINGS', 'FINDINGS')).toBe(true)
    expect(portsCompatible('FINDINGS', 'REPORT')).toBe(false)
    expect(portsCompatible('WORKSPACE', 'PROJECT_MODEL')).toBe(false)
  })
})

describe('keepsNodeConnections', () => {
  const { edges } = toFlow({
    name: 'Источники',
    nodes: [],
    edges: [
      edge('1', 'start', 'source', 'out', 'trigger'),
      edge('2', 'source', 'parse', 'workspace', 'workspace'),
      edge('3', 'source', 'report', 'workspace', 'workspace'),
    ],
  })
  const archive: NodeDefinition = {
    type: 'source.archive', title: 'ZIP-архив', category: 'SOURCE',
    inputs: [{ name: 'trigger', type: 'ANY', required: false }],
    outputs: [{ name: 'workspace', type: 'WORKSPACE', required: true }],
    paramsSchema: {}, secretParams: [],
  }
  const portType = (id: string): PortType => id === 'start' ? 'ANY' : 'WORKSPACE'

  it('сохраняет входящую связь и все ветви, если имена и типы портов подходят', () => {
    expect(keepsNodeConnections('source', archive, edges, portType)).toBe(true)
  })

  it('отклоняет замену, если занятого порта больше нет или тип не подходит хотя бы одной связи', () => {
    expect(keepsNodeConnections('source', { ...archive, inputs: [] }, edges, portType)).toBe(false)
    expect(keepsNodeConnections('source', archive, edges, (id) => id === 'report' ? 'REPORT' : portType(id))).toBe(false)
  })
})

describe('toFlow / fromFlow', () => {
  const draft: WorkflowDraft = {
    id: 'wf-1',
    version: 3,
    name: 'Сценарий',
    nodes: [
      { id: 'a', type: 'trigger.manual', params: {}, position: { x: 10.4, y: 20.6 } },
      { id: 'b', type: 'ai.explain', params: { k: 1 }, position: { x: 300, y: 0 }, continueOnError: true },
    ],
    edges: [edge('e1', 'a', 'b', 'trigger', 'findings')],
  }

  it('туда и обратно сохраняет ноды, порты связей и continueOnError, координаты округляются', () => {
    const { nodes, edges } = toFlow(draft)
    const back = fromFlow({ id: draft.id, name: draft.name, version: draft.version }, nodes, edges)
    expect(back.edges).toEqual(draft.edges)
    expect(back.nodes[0].position).toEqual({ x: 10, y: 21 })
    expect(back.nodes[1]).toMatchObject({ id: 'b', type: 'ai.explain', params: { k: 1 }, continueOnError: true })
    expect('continueOnError' in back.nodes[0]).toBe(false)
  })

  it('новый сценарий уходит без id и версии — сервер присвоит сам', () => {
    const { nodes, edges } = toFlow(draft)
    const back = fromFlow({ name: 'Новый' }, nodes, edges)
    expect(back.id).toBeUndefined()
    expect(back.version).toBeUndefined()
    expect(isSaved(back)).toBe(false)
    expect(isSaved(draft)).toBe(true)
  })
})

describe('defaultParams и newNodeId', () => {
  it('берёт только заданные в схеме значения по умолчанию', () => {
    const def = { paramsSchema: { type: 'object', properties: { cron: { type: 'string', default: '0 0 14 * * *' }, zone: { type: 'string' } } } } as unknown as NodeDefinition
    expect(defaultParams(def)).toEqual({ cron: '0 0 14 * * *' })
  })

  it('id новой ноды не совпадает с существующими', () => {
    expect(newNodeId([])).toBe('n1')
    expect(newNodeId([{ id: 'n1' }, { id: 'n3' }])).toBe('n4')
    expect(newNodeId([{ id: 'n2' }, { id: 'n3' }])).toBe('n4')
  })
})

describe('layeredLayout', () => {
  it('цепочка — слева направо по слоям, независимо от координат модели', () => {
    const draft = {
      nodes: [node('report', 't', { x: 5000, y: -900 }), node('start'), node('src', 't', { x: -3000, y: 0 })],
      edges: [edge('1', 'start', 'src'), edge('2', 'src', 'report')],
    }
    const pos = layeredLayout(draft)
    expect(pos.start.x).toBeLessThan(pos.src.x)
    expect(pos.src.x).toBeLessThan(pos.report.x)
    expect(new Set(Object.values(pos).map((p) => p.y))).toEqual(new Set([0]))
  })

  it('ветвление: параллельные анализаторы в одном слое, по вертикали без наложений, слияние — правее всех', () => {
    const draft = {
      nodes: ['model', 'secret', 'sca', 'sast', 'merge'].map((id) => node(id)),
      edges: [edge('1', 'model', 'secret'), edge('2', 'model', 'sca'), edge('3', 'model', 'sast'),
        edge('4', 'secret', 'merge'), edge('5', 'sca', 'merge'), edge('6', 'sast', 'merge')],
    }
    const pos = layeredLayout(draft, { x: 250, y: 120 })
    const xs = new Set(['secret', 'sca', 'sast'].map((id) => pos[id].x))
    expect(xs.size).toBe(1)
    expect(new Set(['secret', 'sca', 'sast'].map((id) => pos[id].y)).size).toBe(3)
    expect(pos.merge.x).toBeGreaterThan(pos.secret.x)
    expect(pos.merge.y).toBe(0)
  })

  it('нода в слое — по самому длинному пути, связи на неизвестные ноды и цикл не ломают раскладку', () => {
    const draft = {
      nodes: ['a', 'b', 'c', 'x', 'y'].map((id) => node(id)),
      edges: [edge('1', 'a', 'b'), edge('2', 'b', 'c'), edge('3', 'a', 'c'), edge('4', 'ghost', 'a'),
        edge('5', 'x', 'y'), edge('6', 'y', 'x')],
    }
    const pos = layeredLayout(draft)
    expect(pos.c.x).toBe(pos.b.x + 250)
    expect(pos.a.x).toBe(0)
    expect(Object.keys(pos).sort()).toEqual(['a', 'b', 'c', 'x', 'y'])
  })
})

describe('bridgeEdges', () => {
  const e = (id: string, source: string, sourceHandle: string, target: string, targetHandle: string) =>
    ({ id, source, sourceHandle, target, targetHandle })
  const types: Record<string, PortType> = {
    'merge:out:findings': 'FINDINGS', 'filter:in:findings': 'FINDINGS', 'filter:out:findings': 'FINDINGS',
    'report:in:findings': 'FINDINGS', 'parse:out:model': 'PROJECT_MODEL', 'sast:in:model': 'PROJECT_MODEL',
    'sast:out:findings': 'FINDINGS', 'merge:in:findings1': 'FINDINGS',
  }
  const portType = (node: string, handle: string | null | undefined, side: 'out' | 'in') => types[`${node}:${side}:${handle}`]

  it('удалили фильтр из цепочки — отчёт соединён с объединением напрямую', () => {
    const edges = [e('1', 'merge', 'findings', 'filter', 'findings'), e('2', 'filter', 'findings', 'report', 'findings')]
    expect(bridgeEdges(['filter'], edges, portType)).toEqual([
      { id: 'e-merge-findings-report-findings', source: 'merge', sourceHandle: 'findings', target: 'report', targetHandle: 'findings' },
    ])
  })

  it('несовместимые порты не соединяются: модель проекта не уходит во вход находок', () => {
    const edges = [e('1', 'parse', 'model', 'sast', 'model'), e('2', 'sast', 'findings', 'merge', 'findings1')]
    expect(bridgeEdges(['sast'], edges, portType)).toEqual([])
  })

  it('ветвление (два выхода) и занятый вход не трогаем', () => {
    const fan = [e('1', 'merge', 'findings', 'filter', 'findings'), e('2', 'filter', 'findings', 'report', 'findings'),
      e('3', 'filter', 'findings', 'other', 'findings')]
    expect(bridgeEdges(['filter'], fan, portType)).toEqual([])
    const busy = [e('1', 'merge', 'findings', 'filter', 'findings'), e('2', 'filter', 'findings', 'report', 'findings'),
      e('4', 'sast', 'findings', 'report', 'findings')]
    expect(bridgeEdges(['filter'], busy, portType)).toEqual([])
  })
})

describe('freeSpot', () => {
  const vp = { x: 0, y: 0, w: 1200, h: 600 }
  const at = (x: number, y: number) => ({ position: { x, y } })
  const overlaps = (a: { x: number; y: number }, b: { x: number; y: number }) => Math.abs(a.x - b.x) < 220 && Math.abs(a.y - b.y) < 130

  it('пустой холст — левый верх видимой области', () => {
    const p = freeSpot([], vp, null)
    expect(p.x).toBeGreaterThanOrEqual(0)
    expect(p.y).toBeGreaterThanOrEqual(0)
  })

  it('справа от опорной ноды, если место свободно и видно', () => {
    const p = freeSpot([at(40, 40)], vp, { x: 40, y: 40 })
    expect(p.x).toBeGreaterThan(40 + 220)
    expect(p.y).toBe(40)
  })

  it('место справа занято — берёт другое, без наложения', () => {
    const nodes = [at(40, 40), at(300, 40)]
    const p = freeSpot(nodes, vp, { x: 40, y: 40 })
    for (const n of nodes) expect(overlaps(p, n.position)).toBe(false)
  })

  it('вылезло бы за правый край — остаётся в видимой области', () => {
    const p = freeSpot([at(900, 40)], vp, { x: 900, y: 40 })
    expect(p.x + 220).toBeLessThanOrEqual(1200)
    expect(overlaps(p, { x: 900, y: 40 })).toBe(false)
  })

  it('видимая область забита — всё равно место без наложения', () => {
    const nodes = Array.from({ length: 12 }, (_, i) => at(40 + (i % 4) * 260, 40 + Math.floor(i / 4) * 170))
    const p = freeSpot(nodes, { x: 0, y: 0, w: 1100, h: 560 }, null)
    for (const n of nodes) expect(overlaps(p, n.position)).toBe(false)
  })
})

describe('замена ноды и список совместимых портов', () => {
  const port = (name: string, type: PortType) => ({ name, type, required: true })
  const def = (type: string, inputs: ReturnType<typeof port>[], outputs: ReturnType<typeof port>[]) =>
    ({ type, title: type, category: 'SOURCE', inputs, outputs, secretParams: [], paramsSchema: { type: 'object' } }) as unknown as NodeDefinition
  const repo = def('source.repo', [port('trigger', 'ANY')], [port('workspace', 'WORKSPACE'), port('revision', 'ANY')])
  const zip = def('source.archive', [port('trigger', 'ANY')], [port('workspace', 'WORKSPACE'), port('revision', 'ANY')])
  const e = (id: string, source: string, sourceHandle: string, target: string, targetHandle: string) => ({ id, source, sourceHandle, target, targetHandle })

  it('Git → ZIP: связи остаются на тех же портах', () => {
    const edges = [e('1', 'start', 'trigger', 'src', 'trigger'), e('2', 'src', 'workspace', 'parse', 'workspace')]
    const res = remapEdgesForReplacement('src', repo, zip, edges)
    expect(res.dropped).toEqual([])
    expect(res.edges).toEqual(edges)
  })

  it('порт переименован — берётся свободный порт того же типа, остальное не трогаем', () => {
    const other = def('source.other', [port('in', 'ANY')], [port('files', 'WORKSPACE')])
    const edges = [e('1', 'start', 'trigger', 'src', 'trigger'), e('2', 'src', 'workspace', 'parse', 'workspace'), e('3', 'a', 'x', 'b', 'y')]
    const res = remapEdgesForReplacement('src', repo, other, edges)
    expect(res.dropped).toEqual([])
    expect(res.edges[0]).toMatchObject({ source: 'start', target: 'src', targetHandle: 'in' })
    expect(res.edges[1]).toMatchObject({ source: 'src', sourceHandle: 'files', target: 'parse', targetHandle: 'workspace' })
    expect(res.edges[2]).toEqual(edges[2])
  })

  it('нет порта нужного типа — связь отбрасывается', () => {
    const bare = def('source.bare', [port('trigger', 'ANY')], [])
    const res = remapEdgesForReplacement('src', repo, bare, [e('2', 'src', 'workspace', 'parse', 'workspace')])
    expect(res.edges).toEqual([])
    expect(res.dropped).toHaveLength(1)
  })

  const parse = def('analyzer.parse', [port('workspace', 'WORKSPACE')], [port('model', 'PROJECT_MODEL')])
  const sast = def('analyzer.sast', [port('model', 'PROJECT_MODEL')], [port('findings', 'FINDINGS')])
  const report = def('output.report', [port('findings', 'FINDINGS')], [])
  const delay = def('logic.delay', [port('value', 'ANY')], [])
  const defs: Record<string, NodeDefinition> = { 'source.repo': repo, 'analyzer.parse': parse, 'analyzer.sast': sast, 'output.report': report, 'logic.delay': delay }
  const nodes = [{ id: 'src', data: { nodeType: 'source.repo' } }, { id: 'parse', data: { nodeType: 'analyzer.parse' } },
    { id: 'sast', data: { nodeType: 'analyzer.sast' } }, { id: 'rep', data: { nodeType: 'output.report' } }, { id: 'dl', data: { nodeType: 'logic.delay' } }]
  const portType = (n: string, h: string | null | undefined, side: 'out' | 'in') => {
    const d = defs[nodes.find((x) => x.id === n)!.data.nodeType]
    return (side === 'out' ? d.outputs : d.inputs).find((p) => p.name === h)?.type
  }
  const list = (edge: ReturnType<typeof e>, side: 'target' | 'source') =>
    compatiblePorts(edge, side, nodes, [edge], (t) => defs[t], portType).map((c) => `${c.nodeId}.${c.port}`)

  it('WORKSPACE-выход: подходит только вход ANY; текущий приёмник и несовместимые не предлагаются', () => {
    expect(list(e('1', 'src', 'workspace', 'parse', 'workspace'), 'target')).toEqual(['dl.value'])
  })

  it('PROJECT_MODEL-выход: не предлагает вход находок отчёта', () => {
    expect(list(e('1', 'parse', 'model', 'sast', 'model'), 'target')).toEqual(['src.trigger', 'dl.value'])
  })

  it('смена источника: вход PROJECT_MODEL принимает только PROJECT_MODEL и ANY', () => {
    expect(list(e('1', 'parse', 'model', 'sast', 'model'), 'source')).toEqual(['src.revision'])
  })

  it('занятый другой связью вход не предлагается', () => {
    const edge = e('1', 'src', 'workspace', 'parse', 'workspace')
    const busy = e('2', 'x', 'out', 'dl', 'value')
    expect(compatiblePorts(edge, 'target', nodes, [edge, busy], (t) => defs[t], portType)).toEqual([])
  })
})
