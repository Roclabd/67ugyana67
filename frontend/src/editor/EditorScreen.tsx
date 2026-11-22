/**
 * Редактор сценария: палитра из GET /api/nodes, холст React Flow, параметры ноды, сохранение,
 * ошибки валидации от сервера, запуск с живыми статусами нод (SSE), сценарий из текста через LLM.
 * Сервер — источник правды: сохранение и запуск проходят GraphValidator, фронт показывает его ответ.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  addEdge,
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesInitialized,
  useNodesState,
  useReactFlow,
  useUpdateNodeInternals,
  type Connection,
  type Edge,
  type IsValidConnection,
  type NodeTypes,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { ApiError, errorMessage } from '../api/errors'
import type { GraphError, NodeCategory, NodeDefinition, WorkflowDraft } from '../api/types'
import { useCatalog, useLiveRun } from '../store'
import { ErrorBox, Loading, StatusBadge } from '../ui'
import { bridgeEdges, compatiblePorts, defaultParams, freeSpot, fromFlow, isSaved, keepsNodeConnections, layeredLayout, newNodeId, NODE_SIZE, portsCompatible, remapEdgesForReplacement, toFlow, type FlowNode } from './graph'
import { ParamsForm } from './ParamsForm'
import { StepNode } from './StepNode'
import { NodeRunPanel } from '../run/NodeRunPanel'
import { ProblemsBanner } from '../run/ProblemsBanner'
import { blockedEdgeIds, graphOrder } from '../run/problems'
import { GeneratePanel } from './GeneratePanel'
import { EdgePanel, ReplaceNode } from './SidePanels'
import { t } from '../i18n'
import { defTitle } from '../i18n/nodes'

const nodeTypes: NodeTypes = { step: StepNode }

function validationKey(draft: WorkflowDraft): string {
  return JSON.stringify({
    name: draft.name,
    nodes: draft.nodes.map(({ id, type, params, continueOnError }) => ({ id, type, params, continueOnError })),
    edges: draft.edges,
  })
}

export interface EditorScreenProps {
  /** undefined — новый сценарий. */
  workflowId?: string
  onSaved: (workflowId: string) => void
  onOpenRun: (runId: string) => void
}

export function EditorScreen(props: EditorScreenProps) {
  return (
    <ReactFlowProvider>
      <Editor {...props} />
    </ReactFlowProvider>
  )
}

function Editor({ workflowId, onSaved, onOpenRun }: EditorScreenProps) {
  const catalog = useCatalog()
  const loadCatalog = useCatalog((s) => s.load)
  const live = useLiveRun()
  const { screenToFlowPosition, fitView, getViewport, setCenter } = useReactFlow()
  const updateNodeInternals = useUpdateNodeInternals()

  const [loadState, setLoadState] = useState<'loading' | 'ready' | string>('loading')
  const [meta, setMeta] = useState<{ id?: string; name: string; version?: number }>({ name: t('sf.newWorkflow.n') })
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null)
  const canvasRef = useRef<HTMLDivElement>(null)
  const sideRef = useRef<HTMLElement>(null)
  /** Связь, конец которой тащат мышью: её собственный вход не считается занятым. */
  const reconnecting = useRef<string | null>(null)
  const lastAdded = useRef<string | null>(null)
  /** Вписывать граф при открытии нужно только если нода уже есть: иначе первая добавленная нода утащила бы холст. */
  const fitOnInit = useRef(false)
  // Вписать граф в окно, когда React Flow измерит новые ноды (раньше — промахивается по размерам).
  const [fitPending, setFitPending] = useState<boolean | string | string[]>(false)
  const nodesInitialized = useNodesInitialized()
  const [graphErrors, setGraphErrors] = useState<GraphError[]>([])
  const [checkedGraph, setCheckedGraph] = useState<string | null>(null)
  const [message, setMessage] = useState<{ kind: 'error' | 'info'; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [dirty, setDirty] = useState(false)
  // ?generate=1 — пришли из поиска «Сценарий из текста»: панель генерации сразу открыта.
  const [searchParams] = useSearchParams()
  const [showGenerate, setShowGenerate] = useState(() => searchParams.get('generate') === '1')

  useEffect(() => {
    void loadCatalog()
  }, [loadCatalog])

  useEffect(() => {
    let alive = true
    if (!workflowId) {
      setMeta({ name: t('sf.newWorkflow.n') })
      setNodes([])
      setEdges([])
      fitOnInit.current = false
      setShowGenerate(searchParams.get('generate') === '1')
      setLoadState('ready')
      return
    }
    setLoadState('loading')
    api.getWorkflow(workflowId).then(
      (wf) => {
        if (!alive) return
        const flow = toFlow(wf)
        setMeta({ id: wf.id, name: wf.name, version: wf.version })
        setNodes(flow.nodes)
        fitOnInit.current = flow.nodes.length > 0
        setEdges(flow.edges)
        setDirty(false)
        setShowGenerate(false)
        setLoadState('ready')
      },
      (err: unknown) => alive && setLoadState(errorMessage(err)),
    )
    return () => {
      alive = false
    }
    // Перезагружаем только при смене сценария.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workflowId, setNodes, setEdges])

  const portType = useCallback(
    (nodeId: string, handle: string | null | undefined, side: 'out' | 'in') => {
      const def = catalog.byType[nodes.find((n) => n.id === nodeId)?.data.nodeType ?? '']
      return (side === 'out' ? def?.outputs : def?.inputs)?.find((p) => p.name === handle)?.type
    },
    [nodes, catalog.byType],
  )

  const isValidConnection: IsValidConnection = useCallback(
    (c) => {
      const out = portType(c.source, c.sourceHandle, 'out')
      const inp = portType(c.target, c.targetHandle, 'in')
      if (!out || !inp || c.source === c.target) return false
      // один вход — одна связь
      if (edges.some((e) => e.id !== reconnecting.current && e.target === c.target && e.targetHandle === c.targetHandle)) return false
      return portsCompatible(out, inp)
    },
    [edges, portType],
  )

  const onConnect = useCallback(
    (c: Connection) => {
      setEdges((es) => addEdge({ ...c, id: `e-${c.source}-${c.sourceHandle}-${c.target}-${c.targetHandle}` }, es))
      setDirty(true)
    },
    [setEdges],
  )

  /** Удалили ноду из простой цепочки — соседи соединяются сами, если порты совместимы. */
  const onNodesDelete = useCallback(
    (deleted: FlowNode[]) => {
      const bridges = bridgeEdges(deleted.map((n) => n.id), edges, portType)
      if (bridges.length) setEdges((es) => [...es, ...bridges])
    },
    [edges, portType, setEdges],
  )

  /** Видимая область холста в координатах графа. */
  function visibleRect() {
    const el = canvasRef.current
    if (!el) return null
    const { x, y, zoom } = getViewport()
    return { x: -x / zoom, y: -y / zoom, w: el.clientWidth / zoom, h: el.clientHeight / zoom }
  }

  function addNode(def: NodeDefinition, position?: { x: number; y: number }) {
    const id = newNodeId(nodes)
    let pos = position
    if (!pos) {
      const anchorNode = nodes.find((n) => n.id === (selectedId ?? lastAdded.current)) ?? null
      const rect = visibleRect()
      const anchor = anchorNode && (!rect || (anchorNode.position.x >= rect.x && anchorNode.position.x <= rect.x + rect.w))
        ? { x: anchorNode.position.x, y: anchorNode.position.y, w: anchorNode.measured?.width ?? NODE_SIZE.w }
        : null
      pos = freeSpot(nodes.map((n) => ({ position: n.position, width: n.measured?.width, height: n.measured?.height })), rect, anchor)
    }
    lastAdded.current = id
    setNodes((ns) => [
      ...ns.map((n) => (n.selected ? { ...n, selected: false } : n)),
      { id, type: 'step', position: pos, selected: true, data: { nodeType: def.type, params: defaultParams(def) } },
    ])
    setSelectedId(id)
    setSelectedEdgeId(null)
    setDirty(true)
  }

  function onDrop(e: React.DragEvent) {
    e.preventDefault()
    const type = e.dataTransfer.getData('application/x-node-type')
    const def = catalog.byType[type]
    if (def) addNode(def, screenToFlowPosition({ x: e.clientX, y: e.clientY }))
  }

  function updateParams(id: string, params: Record<string, unknown>) {
    setNodes((ns) => ns.map((n) => (n.id === id ? { ...n, data: { ...n.data, params } } : n)))
    setDirty(true)
  }

  function updateContinueOnError(id: string, value: boolean) {
    setNodes((ns) => ns.map((n) => (n.id === id ? { ...n, data: { ...n.data, continueOnError: value } } : n)))
    setDirty(true)
  }

  function replaceNode(id: string, def: NodeDefinition) {
    const oldDef = catalog.byType[nodes.find((n) => n.id === id)?.data.nodeType ?? '']
    setEdges((es) => remapEdgesForReplacement(id, oldDef, def, es).edges)
    setNodes((ns) => ns.map((node) => node.id === id ? {
      ...node,
      data: { ...node.data, nodeType: def.type, params: defaultParams(def) },
    } : node))
    updateNodeInternals(id)
    live.stop()
    setGraphErrors([])
    setMessage(null)
    setDirty(true)
  }

  /** Удалить ноду с мостом между соседями (как при Delete на холсте). */
  function deleteNodes(ids: string[]) {
    const bridges = bridgeEdges(ids, edges, portType)
    const gone = new Set(ids)
    setNodes((ns) => ns.filter((n) => !gone.has(n.id)))
    setEdges((es) => [...es.filter((e) => !gone.has(e.source) && !gone.has(e.target)), ...bridges])
    setSelectedId(null)
    setDirty(true)
  }

  function deleteEdge(id: string) {
    setEdges((es) => es.filter((e) => e.id !== id))
    setSelectedEdgeId(null)
    setDirty(true)
  }

  /** Перенести конец связи на другой порт (из списка совместимых или перетаскиванием). */
  function reconnectEdge(oldEdge: Edge, c: Connection) {
    const id = `e-${c.source}-${c.sourceHandle}-${c.target}-${c.targetHandle}`
    setEdges((es) => es.map((e) => (e.id === oldEdge.id
      ? { id, source: c.source, sourceHandle: c.sourceHandle, target: c.target, targetHandle: c.targetHandle }
      : e)))
    setSelectedEdgeId(id)
    setDirty(true)
  }

  function focusNode(id: string) {
    if (!nodes.some((n) => n.id === id)) return
    setSelectedId(id)
    setSelectedEdgeId(null)
    setEdges((items) => items.map((item) => item.selected ? { ...item, selected: false } : item))
    setNodes((ns) => ns.map((n) => Boolean(n.selected) === (n.id === id) ? n : { ...n, selected: n.id === id }))
    setFitPending(id)
  }

  function focusEdge(edge: Edge) {
    setSelectedId(null)
    setSelectedEdgeId(edge.id)
    setEdges((items) => items.map((item) => Boolean(item.selected) === (item.id === edge.id) ? item : { ...item, selected: item.id === edge.id }))
    setNodes((items) => items.map((node) => node.selected ? { ...node, selected: false } : node))
    setFitPending([edge.source, edge.target])
  }

  /** Черновик от LLM — новый несохранённый сценарий. Параметры по умолчанию дополняются из схем нод. */
  function applyGenerated(draft: WorkflowDraft) {
    const wasSaved = Boolean(meta.id)
    const positions = layeredLayout(draft)
    const flow = toFlow({
      ...draft,
      nodes: draft.nodes.map((n) => {
        const def = catalog.byType[n.type]
        return { ...n, position: positions[n.id] ?? n.position, params: { ...(def ? defaultParams(def) : {}), ...n.params } }
      }),
    })
    live.stop()
    setMeta({ name: draft.name || t('ed.fromTextName') })
    setNodes(flow.nodes)
    setEdges(flow.edges)
    setSelectedId(null)
    setGraphErrors([])
    setDirty(true)
    setShowGenerate(false)
    setMessage({
      kind: 'info',
      text: t('ed.draft', { nodes: flow.nodes.length, edges: flow.edges.length, saved: wasSaved ? t('ed.draftNew') : '' }),
    })
    setFitPending(true)
  }

  useEffect(() => {
    if (!fitPending || !nodesInitialized) return
    // К конкретной ноде — с задержкой: панель параметров меняет ширину холста
    const timer = setTimeout(() => {
      setFitPending(false)
      if (typeof fitPending === 'string') {
        void fitView({ nodes: [{ id: fitPending }], padding: 0.4, minZoom: 0.9, maxZoom: 1.1, duration: 300 })
      } else if (Array.isArray(fitPending)) {
        void fitView({ nodes: fitPending.map((id) => ({ id })), padding: 0.22, minZoom: 0.4, maxZoom: 1, duration: 250 })
      } else {
        void fitView({ padding: 0.1, minZoom: 0.75, maxZoom: 1 })
      }
    }, fitPending === true ? 30 : 150)
    return () => clearTimeout(timer)
  }, [fitPending, nodesInitialized, fitView])

  // Выбранная нода не должна прятаться под боковой панелью (она сужает холст); на узком экране панель под холстом — прокручиваем к ней.
  useEffect(() => {
    if (!selectedId && !selectedEdgeId) return
    const timer = setTimeout(() => {
      if (window.matchMedia('(max-width: 720px)').matches) {
        sideRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
        return
      }
      const node = nodes.find((n) => n.id === selectedId)
      const rect = visibleRect()
      if (!node || !rect) return
      const w = node.measured?.width ?? NODE_SIZE.w
      const h = node.measured?.height ?? NODE_SIZE.h
      const hidden = node.position.x < rect.x || node.position.y < rect.y || node.position.x + w > rect.x + rect.w || node.position.y + h > rect.y + rect.h
      if (hidden) void setCenter(node.position.x + w / 2, node.position.y + h / 2, { zoom: Math.max(getViewport().zoom, 0.8), duration: 300 })
    }, 120)
    return () => clearTimeout(timer)
    // только на смену выбора
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, selectedEdgeId])

  function currentDraft(): WorkflowDraft {
    return fromFlow(meta, nodes, edges)
  }

  function showServerError(err: unknown, draft: WorkflowDraft) {
    if (err instanceof ApiError && err.graphErrors.length) {
      setGraphErrors(err.graphErrors)
      setCheckedGraph(validationKey(draft))
    }
    setMessage({ kind: 'error', text: errorMessage(err) })
  }

  async function save() {
    setBusy(true)
    setMessage(null)
    setGraphErrors([])
    setCheckedGraph(null)
    const draft = currentDraft()
    try {
      const saved = isSaved(draft) ? await api.updateWorkflow(draft) : await api.createWorkflow(draft)
      setMeta({ id: saved.id, name: saved.name, version: saved.version })
      setDirty(false)
      setMessage({ kind: 'info', text: t('ed.saved', { v: saved.version }) })
      if (saved.id !== workflowId) onSaved(saved.id)
      return saved
    } catch (err) {
      showServerError(err, draft)
      return null
    } finally {
      setBusy(false)
    }
  }

  async function validate() {
    setBusy(true)
    setMessage(null)
    const draft = currentDraft()
    try {
      const res = await api.validateWorkflow(draft)
      setGraphErrors(res.errors)
      setCheckedGraph(validationKey(draft))
      setMessage(res.errors.length ? { kind: 'error', text: t('ed.graphErrors', { n: res.errors.length }) } : { kind: 'info', text: t('ed.graphOk') })
    } catch (err) {
      showServerError(err, draft)
    } finally {
      setBusy(false)
    }
  }

  async function run() {
    // Запускаем только сохранённую версию: сервер исполняет то, что сохранил и проверил.
    const draft = currentDraft()
    const saved = dirty || !isSaved(draft) ? await save() : draft
    if (!saved) return
    setBusy(true)
    setMessage(null)
    try {
      const { runId } = await api.runWorkflow(saved.id)
      live.watch(runId, saved.id, saved.version)
    } catch (err) {
      showServerError(err, saved)
    } finally {
      setBusy(false)
    }
  }

  const palette = useMemo(() => {
    const groups = new Map<NodeCategory, NodeDefinition[]>()
    for (const n of catalog.nodes) groups.set(n.category, [...(groups.get(n.category) ?? []), n])
    // Порядок как в сценарии: запуск → источник → анализ → логика → AI → отчёт
    const order: string[] = ['TRIGGER', 'SOURCE', 'ANALYZER', 'LOGIC', 'AI', 'OUTPUT']
    return [...groups.entries()].sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0]))
  }, [catalog.nodes])

  const validationStale = checkedGraph !== null && checkedGraph !== validationKey(currentDraft())
  const errors = validationStale ? [] : graphErrors
  const errorNodeIds = new Set(errors.map((e) => e.nodeId))
  const errorEdgeIds = new Set(errors.map((e) => e.edgeId))
  const validationTargets = nodes.filter((node) => errorNodeIds.has(node.id)).map((node) => node.id)
  for (const edge of edges) {
    if (errorEdgeIds.has(edge.id)) validationTargets.push(edge.source, edge.target)
  }
  const activeRun = !dirty && live.workflowId === meta.id && live.workflowVersion === meta.version ? live : null
  const liveNodes = activeRun?.nodes ?? {}
  const blockedEdges = blockedEdgeIds(liveNodes)
  // Порядок нод по графу и названия — для баннера «Где сломалось»
  const problemOrder = graphOrder(nodes.map((n) => n.id), edges.map((e) => ({ from: e.source, to: e.target }))).map((nid) => {
    const n = nodes.find((x) => x.id === nid)!
    return {
      id: nid,
      title: defTitle(catalog.byType[n.data.nodeType], n.data.nodeType),
      ai: catalog.byType[n.data.nodeType]?.category === 'AI',
      delivery: n.data.nodeType.startsWith('notify.'),
    }
  })
  const selected = nodes.find((n) => n.id === selectedId) ?? null
  const selectedDef = selected ? catalog.byType[selected.data.nodeType] : undefined
  const replacements = selected && selectedDef ? catalog.nodes.filter((def) =>
    def.type !== selectedDef.type && def.category === selectedDef.category && keepsNodeConnections(selected.id, def, edges, portType),
  ) : []

  const selectedEdge = edges.find((e) => e.id === selectedEdgeId) ?? null
  const nodeTitle = (nid: string) => {
    const n = nodes.find((x) => x.id === nid)
    return n ? defTitle(catalog.byType[n.data.nodeType], n.data.nodeType) : nid
  }

  if (loadState === 'loading' || catalog.status === 'loading' || catalog.status === 'idle') return <Loading />
  if (loadState !== 'ready') return <div className="page"><ErrorBox error={loadState} /></div>
  if (catalog.status === 'error') return <div className="page"><ErrorBox error={catalog.error ?? t('ed.catalogDown')} /></div>

  return (
    <div className="editor">
      <div className="editor__toolbar">
        <input
          className="input editor__name"
          value={meta.name}
          onChange={(e) => {
            setMeta((m) => ({ ...m, name: e.target.value }))
            setDirty(true)
          }}
        />
        <span className="muted">{meta.version ? `v${meta.version}` : t('ed.notSaved')}{dirty ? ' · ' + t('ed.dirty') : ''}</span>
        <span className="spacer" />
        {activeRun?.runId && (
          // Компактно: статус — ссылка на экран запуска, id — в подсказке. Иначе кнопки шапки переносятся.
          <button className="btn" title={t('ed.runOpen', { id: activeRun.runId })} onClick={() => { if (activeRun.runId) onOpenRun(activeRun.runId) }}>
            <StatusBadge status={activeRun.status} /> {t('run.titleShort')}
          </button>
        )}
        <button className="btn" disabled={busy} onClick={() => setShowGenerate((v) => !v)}>{t('ed.fromText')}</button>
        <button className="btn btn--secondary" disabled={busy} onClick={() => void validate()}>{t('ed.validate')}</button>
        <button className="btn" disabled={busy} onClick={() => void save()}>{t('ed.save')}</button>
        <button className="btn btn--primary btn--run" disabled={busy || (live.workflowId === meta.id && live.status === 'RUNNING')} onClick={() => void run()}>
          {t('ed.run')}
        </button>
      </div>

      {showGenerate && (
        <GeneratePanel
          hasGraph={nodes.length > 0}
          onGenerated={applyGenerated}
          onErrors={(items) => {
            setCheckedGraph(null)
            // Диагностика сгенерированного черновика относится к нему, пока он не применён.
            setGraphErrors(items.map(({ code, message: text }) => ({ code, message: text })))
          }}
          onClose={() => setShowGenerate(false)}
        />
      )}

      {(message || validationStale || errors.length > 0) && (
        <div className="editor__messages">
          {validationStale ? <div className="alert alert--info">{t('ed.stale')}</div>
            : message && <div className={`alert ${message.kind === 'error' ? 'alert--error' : 'alert--info'}`}>{message.text}</div>}
          {validationTargets.length > 0 && (
            <button type="button" className="btn" onClick={() => setFitPending([...new Set(validationTargets)])}>
              {t('ed.showErrors')}
            </button>
          )}
          {errors.length > 0 && (
            <ul className="editor__errors">
              {errors.map((error, i) => {
                const edge = edges.find((item) => item.id === error.edgeId)
                const node = nodes.find((item) => item.id === (error.nodeId ?? edge?.target))
                const title = node && defTitle(catalog.byType[node.data.nodeType], node.data.nodeType)
                return (
                  <li key={i}>
                    {node && <button type="button" className="problems__link" onClick={() => edge ? focusEdge(edge) : focusNode(node.id)}>
                      {edge ? t('ed.edgeTo', { name: title ?? '' }) : t('prob.stage', { name: title ?? '' })}
                    </button>}{node ? ' — ' : ''}{error.message}
                  </li>
                )
              })}
            </ul>
          )}
        </div>
      )}

      {activeRun?.runId && (
        <ProblemsBanner order={problemOrder} nodes={liveNodes} runStatus={activeRun.status}
          onSelect={focusNode}
          onShowAll={(ids) => setFitPending(ids.filter((id) => nodes.some((node) => node.id === id)))} />
      )}

      <div className={`editor__body${selected || selectedEdge ? '' : ' editor__body--wide'}`}>
        <aside className="editor__palette">
          <div className="editor__palette-hint">{t('ed.paletteHint')}</div>
          {palette.map(([cat, defs]) => (
            <div key={cat}>
              <div className="editor__palette-title">{t('pal.' + cat)}</div>
              {defs.map((d) => (
                <div
                  key={d.type}
                  className="editor__palette-item"
                  role="button"
                  tabIndex={0}
                  draggable
                  onDragStart={(e) => e.dataTransfer.setData('application/x-node-type', d.type)}
                  onClick={() => addNode(d)}
                  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); addNode(d) } }}
                  title={t('ed.paletteItem')}
                >
                  {defTitle(d)}
                </div>
              ))}
            </div>
          ))}
        </aside>

        <div className="editor__canvas" ref={canvasRef} onDragOver={(e) => e.preventDefault()} onDrop={onDrop}>
          <ReactFlow
            nodes={nodes.map((n) => {
              const invalidPorts = errors.flatMap((error) => error.nodeId === n.id && error.port ? [error.port] : [])
              return {
                ...n,
                className: errorNodeIds.has(n.id) ? 'step-node--invalid' : n.className,
                data: { ...n.data, live: liveNodes[n.id], invalidPorts },
              }
            })}
            edges={edges.map((e) => ({
              ...e,
              selected: e.id === selectedEdgeId || e.selected,
              className: errorEdgeIds.has(e.id) ? 'edge--invalid' : blockedEdges.has(e.id) ? 'edge--blocked' : e.className,
              animated: liveNodes[e.source]?.status === 'RUNNING',
            }))}
            nodeTypes={nodeTypes}
            onNodesChange={(c) => {
              onNodesChange(c)
              const selection = c.find((change) => change.type === 'select' && change.selected)
              if (selection?.type === 'select') {
                setSelectedId(selection.id)
                setSelectedEdgeId(null)
              }
              if (c.some((x) => x.type !== 'select' && x.type !== 'dimensions')) setDirty(true)
            }}
            onEdgesChange={(c) => {
              onEdgesChange(c)
              if (c.some((x) => x.type === 'remove')) setDirty(true)
            }}
            onConnect={onConnect}
            onNodesDelete={onNodesDelete}
            isValidConnection={isValidConnection}
            onReconnectStart={(_, edge) => { reconnecting.current = edge.id }}
            onReconnect={(oldEdge, c) => reconnectEdge(oldEdge, c)}
            onReconnectEnd={() => { reconnecting.current = null }}
            onNodeClick={(_, n) => { setSelectedId(n.id); setSelectedEdgeId(null) }}
            onEdgeClick={(_, e) => { setSelectedEdgeId(e.id); setSelectedId(null) }}
            onPaneClick={() => { setSelectedId(null); setSelectedEdgeId(null) }}
            fitView={fitOnInit.current}
            defaultViewport={{ x: 0, y: 0, zoom: 0.85 }}
            fitViewOptions={{ padding: 0.1, minZoom: 0.75, maxZoom: 1 }}
            minZoom={0.4}
            deleteKeyCode={['Delete', 'Backspace']}
          >
            <Background />
            <Controls fitViewOptions={{ padding: 0.1, minZoom: 0.75, maxZoom: 1 }} />
            {nodes.length > 0 && <MiniMap pannable zoomable />}
          </ReactFlow>
          {nodes.length === 0 && (
            <div className="editor__empty">
              <div className="editor__empty-card">
                <strong>{t('ed.emptyTitle')}</strong>
                <ol>
                  <li>{t('ed.empty1')}</li>
                  <li>{t('ed.empty2')}</li>
                  <li>{t('ed.empty3')}</li>
                </ol>
                <span className="muted">{t('ed.empty4')}</span>
              </div>
            </div>
          )}
        </div>

        <aside className="editor__side" ref={sideRef}>
          {!selected && !selectedEdge && <p className="muted">{t('ed.selectHint')}</p>}
          {selectedEdge && (
            <EdgePanel
              key={selectedEdge.id}
              edge={selectedEdge}
              sourceTitle={nodeTitle(selectedEdge.source)}
              targetTitle={nodeTitle(selectedEdge.target)}
              nodeTitle={nodeTitle}
              choicesFor={(side) => compatiblePorts(selectedEdge, side, nodes, edges, (t) => catalog.byType[t], portType)}
              onDelete={() => deleteEdge(selectedEdge.id)}
              onReconnect={(side, choice) => reconnectEdge(selectedEdge, side === 'target'
                ? { source: selectedEdge.source, sourceHandle: selectedEdge.sourceHandle ?? null, target: choice.nodeId, targetHandle: choice.port }
                : { source: choice.nodeId, sourceHandle: choice.port, target: selectedEdge.target, targetHandle: selectedEdge.targetHandle ?? null })}
            />
          )}
          {selected && (
            <div className="stack">
              <div>
                <div className="card__title" style={{ margin: 0 }}>{selectedDef ? defTitle(selectedDef) : selected.data.nodeType}</div>
                <div className="muted mono">{selected.id} · {selected.data.nodeType}</div>
              </div>
              <div className="editor__actions">
                <ReplaceNode
                  key={`${selected.id}:${selected.data.nodeType}`}
                  choices={replacements}
                  disabled={busy || live.status === 'RUNNING'}
                  onReplace={(def) => replaceNode(selected.id, def)}
                />
                <button type="button" className="btn btn--danger" disabled={busy || live.status === 'RUNNING'} onClick={() => deleteNodes([selected.id])}>
                  {t('ed.delete')}
                </button>
              </div>
              {selectedDef ? (
                <ParamsForm def={selectedDef} params={selected.data.params} onChange={(p) => updateParams(selected.id, p)} />
              ) : (
                <div className="alert alert--error">{t('ed.unknownType')}</div>
              )}
              <label className="row">
                <input
                  type="checkbox"
                  checked={Boolean(selected.data.continueOnError)}
                  onChange={(e) => updateContinueOnError(selected.id, e.target.checked)}
                />
                {t('ed.continueOnError')}
              </label>
              {liveNodes[selected.id] && <NodeRunPanel node={liveNodes[selected.id]} />}
            </div>
          )}
        </aside>
      </div>
    </div>
  )
}

