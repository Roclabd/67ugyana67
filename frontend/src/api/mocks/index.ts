/**
 * Мок-сервер в браузере: тот же контракт, что docs/API.md. Включается USE_MOCKS в client.ts.
 * Здесь нет логики допуска — только имитация ответов. Решения (pass, публикация, валидность графа)
 * в настоящей системе принимает сервер; моки лишь повторяют форму этих решений.
 */
import type {
  GraphError,
  TelegramSettings,
  TelegramSettingsUpdate,
  Run,
  RunEvent,
  Workflow,
  WorkflowDraft,
  WorkflowSummary,
} from '../types'
import { SECRET_MASK } from '../types'
import { ApiError } from '../errors'
import { nodesFixture } from '../fixtures/nodes'
import {
  ciGithubYamlFixture,
  ciGitlabYamlFixture,
  llmSettingsFixture,
  reportCompleteFixture,
  reportMarkdownFixture,
  reportPartialFixture,
  routeMapArtifactFixture,
  runsFixture,
  templatesFixture,
  workflowsFixture,
} from '../fixtures/data'

const state = {
  repositories: [...new Set(workflowsFixture.flatMap(workflow => workflow.nodes
    .filter(node => node.type === 'source.repo' && typeof node.params.url === 'string')
    .map(node => String(node.params.url))))],
  workflows: structuredClone(workflowsFixture) as Workflow[],
  runs: structuredClone(runsFixture),
  llm: structuredClone(llmSettingsFixture),
  telegram: { token: '', tokenSaved: false, chatId: '', attachments: ['pdf'] } as TelegramSettings,
  runSeq: 3,
  wfSeq: 1,
}

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms))

function fail(status: number, code: string, message: string, details?: unknown): never {
  throw new ApiError(status, { code, message, details })
}

/** Упрощённая проверка графа — та же форма ответа, что у GraphValidator бэка. */
function validate(wf: WorkflowDraft): GraphError[] {
  const errors: GraphError[] = []
  const defs = new Map(nodesFixture.map((n) => [n.type, n]))
  const nodes = new Map(wf.nodes.map((n) => [n.id, n]))
  for (const n of wf.nodes) {
    if (!defs.has(n.type)) errors.push({ nodeId: n.id, code: 'UNKNOWN_NODE', message: `Неизвестный тип ноды: ${n.type}` })
  }
  for (const e of wf.edges) {
    const from = nodes.get(e.from.node)
    const to = nodes.get(e.to.node)
    const outPort = from && defs.get(from.type)?.outputs.find((p) => p.name === e.from.port)
    const inPort = to && defs.get(to.type)?.inputs.find((p) => p.name === e.to.port)
    if (!outPort || !inPort) {
      errors.push({ edgeId: e.id, code: 'UNKNOWN_PORT', message: 'Связь ссылается на несуществующий порт' })
    } else if (outPort.type !== 'ANY' && inPort.type !== 'ANY' && outPort.type !== inPort.type) {
      errors.push({ edgeId: e.id, code: 'PORT_TYPE_MISMATCH', message: `Нельзя соединить ${outPort.type} → ${inPort.type}` })
    }
  }
  for (const n of wf.nodes) {
    const def = defs.get(n.type)
    for (const p of def?.inputs ?? []) {
      if (p.required && !wf.edges.some((e) => e.to.node === n.id && e.to.port === p.name)) {
        errors.push({ nodeId: n.id, code: 'REQUIRED_INPUT', message: `Не подключён обязательный вход «${p.name}»` })
      }
    }
  }
  return errors
}

function summary(wf: Workflow): WorkflowSummary {
  return { id: wf.id, name: wf.name, version: wf.version, updatedAt: '2026-11-21T09:00:00Z' }
}

function getRun(runId: string): Run {
  const s = state.runs.find((r) => r.runId === runId)
  if (!s) fail(404, 'NOT_FOUND', 'Запуск не найден')
  const report =
    s.status === 'RUNNING' || s.status === 'FAILED'
      ? null
      : s.status === 'PARTIAL'
        ? { ...reportPartialFixture, runId }
        : { ...reportCompleteFixture, runId }
  const wf = state.workflows.find((w) => w.id === s.workflowId)
  return {
    ...s,
    workflowVersion: wf?.version ?? 1,
    nodeRuns: (wf?.nodes ?? []).map((n) => {
      const failed = s.status === 'FAILED' || (s.status === 'PARTIAL' && n.type === 'analyzer.sast')
      return failed
        ? { nodeId: n.id, status: 'FAILED' as const, logs: [], error: 'Ошибка разбора PSI: RepairSecurity.kt:12' }
        : n.type === 'output.route-map'
          ? { nodeId: n.id, status: 'SUCCESS' as const, logs: [], output: { report: routeMapArtifactFixture } }
          : { nodeId: n.id, status: 'SUCCESS' as const, logs: [] }
    }),
    report,
  }
}

export async function mockRequest<T>(method: string, path: string, body?: unknown): Promise<T> {
  await delay(250)
  const url = new URL(path, 'http://mock')
  const p = url.pathname
  let m: RegExpMatchArray | null

  if (method === 'GET' && p === '/nodes') return nodesFixture as T
  if (method === 'GET' && p === '/meta') return { publicDemo: false } as T

  // Сценарии
  if (method === 'GET' && p === '/workflows') return state.workflows.map(summary) as T
  if (method === 'POST' && p === '/workflows/validate') return { errors: validate(body as WorkflowDraft) } as T
  if (method === 'POST' && p === '/workflows/generate') {
    const wf = structuredClone(workflowsFixture[1])
    return { workflow: { name: 'Сгенерированный сценарий', nodes: wf.nodes, edges: wf.edges }, errors: [] } as T
  }
  if (method === 'POST' && p === '/workflows') {
    const draft = body as WorkflowDraft
    const errors = validate(draft)
    if (errors.length) fail(422, 'GRAPH_INVALID', 'Граф не прошёл проверку', { errors })
    const wf: Workflow = { ...draft, id: `wf-new-${state.wfSeq++}`, version: 1 }
    state.workflows.push(wf)
    return wf as T
  }
  if ((m = p.match(/^\/workflows\/([^/]+)$/))) {
    const id = decodeURIComponent(m[1])
    const idx = state.workflows.findIndex((w) => w.id === id)
    if (idx < 0) fail(404, 'NOT_FOUND', 'Сценарий не найден')
    if (method === 'GET') return state.workflows[idx] as T
    if (method === 'PUT') {
      const next = body as Workflow
      const errors = validate(next)
      if (errors.length) fail(422, 'GRAPH_INVALID', 'Граф не прошёл проверку', { errors })
      const saved = { ...next, version: state.workflows[idx].version + 1 }
      state.workflows[idx] = saved
      return saved as T
    }
  }
  if ((m = p.match(/^\/workflows\/([^/]+)\/export\.yaml$/))) return `# YAML сценария ${m[1]} (мок)\n` as T
  if (method === 'POST' && (m = p.match(/^\/workflows\/([^/]+)\/run$/))) {
    const wf = state.workflows.find((w) => w.id === decodeURIComponent(m![1]))
    if (!wf) fail(404, 'NOT_FOUND', 'Сценарий не найден')
    const runId = `run-${String(state.runSeq++).padStart(4, '0')}`
    state.runs.unshift({
      runId,
      workflowId: wf.id,
      workflowName: wf.name,
      status: 'RUNNING',
      coverageStatus: null,
      counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      trigger: 'manual',
      startedAt: new Date().toISOString(),
      finishedAt: null,
    })
    return { runId } as T
  }

  // Запуски
  if (method === 'GET' && p === '/runs') {
    const wfId = url.searchParams.get('workflowId')
    return state.runs.filter((r) => !wfId || r.workflowId === wfId).map(r => ({
      ...r,
      repoUrl: state.workflows.find(w => w.id === r.workflowId)?.nodes.find(n => n.type === 'source.repo')?.params.url,
    })) as T
  }
  if (method === 'GET' && (m = p.match(/^\/runs\/([^/]+)$/))) return getRun(decodeURIComponent(m[1])) as T
  if (method === 'GET' && (m = p.match(/^\/runs\/([^/]+)\/report\.md$/))) return reportMarkdownFixture as T
  if (method === 'POST' && p === '/uploads') return { uploadId: 'upl-1' } as T

  // CI
  if (method === 'GET' && (m = p.match(/^\/ci\/workflows\/([^/]+)\/config$/))) {
    const yaml = url.searchParams.get('kind') === 'gitlab' ? ciGitlabYamlFixture : ciGithubYamlFixture
    return yaml.replace('WORKFLOW_ID_HERE', decodeURIComponent(m[1])) as T
  }

  // Шаблоны
  if (method === 'GET' && p === '/templates') {
    return templatesFixture.map(({ workflow: _w, ...s }) => s) as T
  }
  if (method === 'POST' && p === '/templates') {
    const req = body as { workflowId: string; name: string; description: string }
    const wf = state.workflows.find((w) => w.id === req.workflowId)
    if (!wf) fail(404, 'NOT_FOUND', 'Сценарий не найден')
    const errors = validate(wf)
    if (errors.length) fail(422, 'GRAPH_INVALID', 'Шаблон не опубликован: граф не прошёл проверку', { errors })
    return { id: `tpl-${wf.id}`, name: req.name, description: req.description, tags: [], nodeCount: wf.nodes.length, author: 'Вы', workflow: wf } as T
  }
  if ((m = p.match(/^\/templates\/([^/]+)(\/copy)?$/))) {
    const tpl = templatesFixture.find((t) => t.id === decodeURIComponent(m![1]))
    if (!tpl) fail(404, 'NOT_FOUND', 'Шаблон не найден')
    if (method === 'GET' && !m[2]) return tpl as T
    if (method === 'POST' && m[2]) {
      const wf: Workflow = { ...structuredClone(tpl.workflow), id: `wf-new-${state.wfSeq++}`, version: 1, name: `${tpl.name} (копия)` }
      state.workflows.push(wf)
      return wf as T
    }
  }

  // Настройки
  if (p === '/integrations/telegram') {
    if (method === 'PUT') {
      const { token, chatId, attachments } = body as TelegramSettingsUpdate
      const tokenSaved = token === undefined || token === SECRET_MASK ? state.telegram.tokenSaved : Boolean(token)
      state.telegram = { token: tokenSaved ? SECRET_MASK : '', tokenSaved, chatId, attachments }
    }
    return state.telegram as T
  }
  if (p === '/settings/repositories') {
    if (method === 'POST') {
      const { url } = body as { url: string }
      if (!state.repositories.includes(url)) state.repositories.push(url)
    }
    return { repositories: [...state.repositories] } as T
  }
  if (p === '/settings/llm') {
    if (method === 'GET') return state.llm as T
    if (method === 'PUT') {
      const upd = body as { provider: typeof state.llm.provider; baseUrl: string; model: string; apiKey?: string }
      state.llm = { provider: upd.provider, baseUrl: upd.baseUrl, model: upd.model, apiKeySet: state.llm.apiKeySet || !!upd.apiKey }
      return state.llm as T
    }
  }

  fail(404, 'MOCK_NOT_FOUND', `Мок не знает ${method} ${p}`)
}

/**
 * Имитация SSE: проходит ноды сценария в топологическом порядке, шлёт node.status / node.io / log,
 * в конце — run.status. Для demo-ноды analyzer.sast сценарий «Полная проверка» даёт PARTIAL,
 * если включён режим ?partial в адресной строке, — чтобы проверить отображение неполного анализа.
 */
export function mockRunEvents(runId: string, onEvent: (e: RunEvent) => void): () => void {
  const run = state.runs.find((r) => r.runId === runId)
  const wf = run && state.workflows.find((w) => w.id === run.workflowId)
  if (!run || !wf) return () => {}

  const order = topoOrder(wf)
  const timers: ReturnType<typeof setTimeout>[] = []
  const at = (ms: number, fn: () => void) => timers.push(setTimeout(fn, ms))
  const partial = typeof location !== 'undefined' && location.search.includes('partial')
  const report = partial ? reportPartialFixture : reportCompleteFixture

  let t = 100
  for (const n of order) {
    at(t, () => onEvent({ type: 'node.status', data: { nodeId: n.id, status: 'RUNNING', startedAt: new Date().toISOString() } }))
    at(t + 50, () => onEvent({ type: 'log', data: { nodeId: n.id, message: `Старт ${n.type}` } }))
    t += 600
    const status = partial && n.type === 'analyzer.sast' ? 'FAILED' : 'SUCCESS'
    at(t, () => {
      onEvent({ type: 'node.io', data: { nodeId: n.id, input: { from: 'предыдущая нода' }, output: ioFor(n.type, report) } })
      onEvent({ type: 'node.status', data: { nodeId: n.id, status, finishedAt: new Date().toISOString(), ...(status === 'FAILED' ? { error: 'Ошибка разбора PSI: RepairSecurity.kt:12' } : {}) } })
    })
  }
  at(t + 100, () => {
    const final = partial ? 'PARTIAL' : 'SUCCESS'
    run.status = final
    run.coverageStatus = report.coverage.status
    run.finishedAt = new Date().toISOString()
    for (const f of report.findings) run.counts[f.severity]++
    onEvent({ type: 'run.status', data: { status: final } })
  })
  return () => timers.forEach(clearTimeout)
}

function ioFor(type: string, report: typeof reportCompleteFixture): unknown {
  const byCat = (c: string) => report.findings.filter((f) => f.category === c)
  switch (type) {
    case 'source.repo':
      return { workspace: { files: 24, root: 'sample-project' } }
    case 'analyzer.parse':
      return { model: { kotlinFiles: 17, configFiles: 2, dependencies: 9, endpoints: 7 } }
    case 'analyzer.secret':
      return { findings: { count: byCat('SECRET').length, items: byCat('SECRET').map((f) => ({ class: f.class, path: f.path, line: f.line, secret: f.secretMasked })) } }
    case 'analyzer.sca':
      return { findings: { count: byCat('SCA').length } }
    case 'analyzer.sast':
      return { findings: { count: byCat('SAST').length } }
    case 'logic.merge':
    case 'ai.explain':
      return { findings: { count: report.findings.length } }
    case 'output.report':
      return { report: { coverage: report.coverage.status, findings: report.findings.length } }
    default:
      return {}
  }
}

function topoOrder(wf: Workflow) {
  const indeg = new Map(wf.nodes.map((n) => [n.id, 0]))
  for (const e of wf.edges) indeg.set(e.to.node, (indeg.get(e.to.node) ?? 0) + 1)
  const queue = wf.nodes.filter((n) => indeg.get(n.id) === 0)
  const out: Workflow['nodes'] = []
  while (queue.length) {
    const n = queue.shift()!
    out.push(n)
    for (const e of wf.edges.filter((x) => x.from.node === n.id)) {
      indeg.set(e.to.node, indeg.get(e.to.node)! - 1)
      if (indeg.get(e.to.node) === 0) queue.push(wf.nodes.find((x) => x.id === e.to.node)!)
    }
  }
  return out
}
