/**
 * Клиент API. Все запросы фронта к бэку идут только отсюда (ESLint запрещает fetch в остальных файлах).
 * Режим моков: `vite --mode demo` — ответы берутся из src/api/mocks,
 * формы которых сняты с contracts/* и docs/API.md.
 */
import type {
  ApiErrorBody,
  CiKind,
  GenerateResult,
  LlmSettings,
  LlmSettingsUpdate,
  NodeDefinition,
  PublishTemplateRequest,
  Run,
  RunEvent,
  RunRequest,
  RunStarted,
  RunSummary,
  Template,
  TemplateSummary,
  UploadResult,
  ValidationResult,
  Workflow,
  WorkflowDraft,
  WorkflowSummary,
  CompareResult,
  TelegramSettings,
  TelegramSettingsUpdate,
} from './types'
import { ApiError } from './errors'

export { ApiError, errorMessage } from './errors'

type RepositoryRun = RunSummary & { repoUrl?: string | null }

export const USE_MOCKS = import.meta.env.MODE === 'demo'

const BASE = '/api'

type Method = 'GET' | 'POST' | 'PUT' | 'DELETE'

async function request<T>(method: Method, path: string, body?: unknown): Promise<T> {
  if (USE_MOCKS) return (await import('./mocks')).mockRequest<T>(method, path, body)

  let res: Response
  try {
    res = await fetch(BASE + path, {
      method,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    throw new ApiError(0, { code: 'NETWORK', message: 'Сервер недоступен' })
  }
  return parse<T>(res)
}

async function requestText(path: string): Promise<string> {
  if (USE_MOCKS) return (await import('./mocks')).mockRequest<string>('GET', path)
  const res = await fetch(BASE + path)
  if (!res.ok) await parse<never>(res)
  return res.text()
}

async function parse<T>(res: Response): Promise<T> {
  const text = await res.text()
  const json: unknown = text ? safeJson(text) : undefined
  if (!res.ok) {
    // Ответ не в формате API ({code, message}) — например, стандартная страница ошибки Spring: тело не показываем.
    const body = isErrorBody(json) ? json : { code: `HTTP_${res.status}`, message: fallbackMessage(res.status) }
    throw new ApiError(res.status, body)
  }
  return json as T
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

function fallbackMessage(status: number): string {
  if (status === 404) return 'Функция недоступна на этом сервере (404)'
  if (status >= 500) return `Ошибка сервера (${status}), повторите позже`
  return `Сервер отклонил запрос (${status})`
}

function isErrorBody(v: unknown): v is ApiErrorBody {
  return typeof v === 'object' && v !== null && 'message' in v && 'code' in v
}

const q = encodeURIComponent

/** Все методы API. Имена совпадают с разделами docs/API.md. */
export const api = {
  // Каталог нод
  listNodes: () => request<NodeDefinition[]>('GET', '/nodes'),

  // Сценарии
  listWorkflows: () => request<WorkflowSummary[]>('GET', '/workflows'),
  getWorkflow: (id: string) => request<Workflow>('GET', `/workflows/${q(id)}`),
  createWorkflow: (wf: WorkflowDraft) => request<Workflow>('POST', '/workflows', wf),
  updateWorkflow: (wf: Workflow) => request<Workflow>('PUT', `/workflows/${q(wf.id)}`, wf),
  validateWorkflow: (wf: WorkflowDraft) => request<ValidationResult>('POST', '/workflows/validate', wf),
  generateWorkflow: (text: string) => request<GenerateResult>('POST', '/workflows/generate', { text }),
  exportWorkflowYaml: (id: string) => requestText(`/workflows/${q(id)}/export.yaml`),

  // Запуски
  runWorkflow: (id: string, req: RunRequest = {}) => request<RunStarted>('POST', `/workflows/${q(id)}/run`, req),
  listRuns: (workflowId?: string) =>
    request<RepositoryRun[]>('GET', workflowId ? `/runs?workflowId=${q(workflowId)}` : '/runs'),
  getRun: (runId: string) => request<Run>('GET', `/runs/${q(runId)}`),
  compareRuns: (base: string, head: string) =>
    request<CompareResult>('GET', `/runs/compare?base=${q(base)}&head=${q(head)}`),
  /** Ссылки на скачивание отчётов (открывать через <a href download>). */
  reportJsonUrl: (runId: string) => `${BASE}/runs/${q(runId)}/report.json`,
  reportSarifUrl: (runId: string) => `${BASE}/runs/${q(runId)}/report.sarif`,
  reportPdfUrl: (runId: string) => `${BASE}/runs/${q(runId)}/report.pdf`,
  /** SBOM CycloneDX 1.5 по результату SCA. */
  sbomUrl: (runId: string) => `${BASE}/runs/${q(runId)}/sbom.cdx.json`,
  /** Готовый патч находки (unified diff); для секретов содержит исходную строку. */
  patchUrl: (runId: string, findingId: string) => `${BASE}/runs/${q(runId)}/findings/${q(findingId)}/patch`,
  /** Показ патча на экране: значение секрета скрыто. */
  getPatchPreview: (runId: string, findingId: string) =>
    requestText(`/runs/${q(runId)}/findings/${q(findingId)}/patch?masked=true`),
  reportMdUrl: (runId: string) => `${BASE}/runs/${q(runId)}/report.md`,
  getReportMarkdown: (runId: string) => requestText(`/runs/${q(runId)}/report.md`),

  // CI
  getCiConfig: (workflowId: string, kind: CiKind) =>
    requestText(`/ci/workflows/${q(workflowId)}/config?kind=${kind}`),

  // Шаблоны
  listTemplates: () => request<TemplateSummary[]>('GET', '/templates'),
  getTemplate: (id: string) => request<Template>('GET', `/templates/${q(id)}`),
  publishTemplate: (req: PublishTemplateRequest) => request<Template>('POST', '/templates', req),
  copyTemplate: (id: string, body?: { repoUrl?: string; name?: string; uploadId?: string; project?: { kind: 'archive'; name: string } }) =>
    request<Workflow>('POST', `/templates/${q(id)}/copy`, body),

  // Настройки
  getMeta: () => request<{ publicDemo: boolean }>('GET', '/meta'),
  getRepositories: () => request<{ repositories: string[] }>('GET', '/settings/repositories'),
  addRepository: (url: string) =>
    request<{ repositories: string[] }>('POST', '/settings/repositories', { url }),
  getTelegramSettings: () => request<TelegramSettings>('GET', '/integrations/telegram'),
  updateTelegramSettings: (settings: TelegramSettingsUpdate) =>
    request<TelegramSettings>('PUT', '/integrations/telegram', settings),
  testTelegram: (settings: { token?: string; chatId: string; language: 'ru' | 'en' }) =>
    request<{ status: 'sent' }>('POST', '/integrations/telegram/test', settings),
  getLlmSettings: () => request<LlmSettings>('GET', '/settings/llm'),
  updateLlmSettings: (s: LlmSettingsUpdate) => request<LlmSettings>('PUT', '/settings/llm', s),

  // Загрузка архива проекта
  upload: async (file: File): Promise<UploadResult> => {
    if (USE_MOCKS) return (await import('./mocks')).mockRequest<UploadResult>('POST', '/uploads', { name: file.name })
    const form = new FormData()
    form.append('file', file)
    let res: Response
    try {
      res = await fetch(`${BASE}/uploads`, { method: 'POST', body: form })
    } catch {
      throw new ApiError(0, { code: 'NETWORK', message: 'Сервер недоступен' })
    }
    return parse<UploadResult>(res)
  },
}

const RUN_EVENT_TYPES: RunEvent['type'][] = ['node.status', 'node.io', 'node.progress', 'run.status', 'log']

/**
 * Подписка на события запуска (SSE). Возвращает функцию отписки.
 * onError вызывается при обрыве соединения; EventSource сам переподключается.
 */
export function subscribeRunEvents(
  runId: string,
  onEvent: (e: RunEvent) => void,
  onError?: () => void,
): () => void {
  if (USE_MOCKS) {
    let cancelled = false
    let stop: (() => void) | undefined
    void import('./mocks').then(({ mockRunEvents }) => {
      if (!cancelled) stop = mockRunEvents(runId, onEvent)
    }).catch(() => { if (!cancelled) onError?.() })
    return () => {
      cancelled = true
      stop?.()
    }
  }

  const es = new EventSource(`${BASE}/runs/${q(runId)}/events`)
  for (const type of RUN_EVENT_TYPES) {
    es.addEventListener(type, (msg) => {
      try {
        onEvent({ type, data: JSON.parse((msg as MessageEvent<string>).data) } as RunEvent)
      } catch {
        // Битое событие не роняет экран; сервер — источник правды, итог перечитывается через getRun.
      }
    })
  }
  if (onError) es.onerror = onError
  return () => es.close()
}
