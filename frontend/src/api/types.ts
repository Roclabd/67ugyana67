/**
 * Типы ответов API. Единственный источник типов для всего фронта.
 * Соответствуют docs/API.md и contracts/finding.schema.json.
 * Экраны A только импортируют отсюда, своих типов ответов не пишут.
 */

// ───────────── Общие перечисления ─────────────

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export const SEVERITIES: readonly Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export type FindingCategory = 'SECRET' | 'SAST' | 'SCA'

/** Статус ноды в запуске. */
export type NodeStatus = 'PENDING' | 'RUNNING' | 'SUCCESS' | 'PARTIAL' | 'FAILED' | 'SKIPPED'
/** Статус запуска целиком. */
export type RunStatus = 'RUNNING' | 'SUCCESS' | 'PARTIAL' | 'FAILED'
/** Полнота анализа: «находок нет» и «анализ не выполнен» — разные результаты. */
export type CoverageStatus = 'COMPLETE' | 'PARTIAL' | 'FAILED'

export type SeverityCounts = Record<Severity, number>

/** Тело ошибки бэка: 4xx/5xx → {code, message, details?}. */
export interface ApiErrorBody {
  code: string
  message: string
  details?: unknown
}

// ───────────── Каталог нод ─────────────

export type NodeCategory = 'TRIGGER' | 'SOURCE' | 'ANALYZER' | 'LOGIC' | 'AI' | 'OUTPUT'
export type PortType = 'WORKSPACE' | 'PROJECT_MODEL' | 'FINDINGS' | 'REPORT' | 'DECISION' | 'ANY'

export interface PortSpec {
  name: string
  type: PortType
  required: boolean
}

/** Подмножество JSON Schema, по которому строится форма параметров ноды. */
export interface ParamSchema {
  type?: 'object' | 'string' | 'number' | 'integer' | 'boolean' | 'array'
  title?: string
  description?: string
  default?: unknown
  enum?: (string | number)[]
  format?: string
  minimum?: number
  maximum?: number
  maxLength?: number
  properties?: Record<string, ParamSchema>
  required?: string[]
  items?: ParamSchema
}

export interface NodeDefinition {
  type: string
  title: string
  category: NodeCategory
  description?: string
  inputs: PortSpec[]
  outputs: PortSpec[]
  paramsSchema: ParamSchema
  /** Имена параметров, которые шифруются на сервере и приходят маской. */
  secretParams: string[]
}

// ───────────── Сценарии ─────────────

/** Маска секретного параметра. Отправка маски обратно = «не менять». */
export const SECRET_MASK = '••••'

export interface WorkflowNode {
  id: string
  type: string
  params: Record<string, unknown>
  position: { x: number; y: number }
  /** Продолжать сценарий, если нода упала. */
  continueOnError?: boolean
}

export interface PortRef {
  node: string
  port: string
}

export interface WorkflowEdge {
  id: string
  from: PortRef
  to: PortRef
}

export interface Workflow {
  id: string
  name: string
  version: number
  nodes: WorkflowNode[]
  edges: WorkflowEdge[]
  /** ZIP-проект, которому принадлежит сценарий; у проектов-репозиториев не задано. */
  project?: { kind: 'archive'; name: string }
}

export type WorkflowDraft = Omit<Workflow, 'id' | 'version'> & { id?: string; version?: number }

export interface WorkflowSummary {
  id: string
  name: string
  version: number
  updatedAt: string
}

export interface GraphError {
  nodeId?: string
  edgeId?: string
  port?: string
  code: string
  message: string
}

export interface ValidationResult {
  errors: GraphError[]
}

export interface GenerateResult {
  workflow: WorkflowDraft | null
  errors: GraphError[]
}

// ───────────── Находки и отчёт (contracts/finding.schema.json) ─────────────

export interface Location {
  path: string
  line: number
  endLine?: number
  note?: string
}

export type AiFindingStatus = 'OK' | 'NOT_RECEIVED' | 'REJECTED_BY_VALIDATOR'

export interface FindingAi {
  status: AiFindingStatus
  explanation?: string
  impact?: string
  fixSteps?: string[]
  fixExample?: string
  /** SCA: целевая версия из справочника (не из ответа модели). */
  recommendedVersion?: string
  /** Проверки полезности: hasFixExample, fixParses, sameIdentifier, fixPattern, rerunClean, targetSafe, fromFixedVersions. */
  usefulnessChecks?: Record<string, boolean>
  /** Почему объяснения нет или оно отклонено. */
  reason?: string
}

export interface Finding {
  id: string
  fingerprint: string
  category: FindingCategory
  /** SECRET/SAST: код класса (password, sql-injection, …). */
  class?: string
  path: string
  line?: number
  endLine?: number
  severity: Severity
  rule: string
  title?: string
  description?: string
  remediation?: string
  evidence: Location[]
  /** Только SECRET: маска значения. Сырого значения на фронте нет никогда. */
  secretMasked?: string
  /** SCA */
  group?: string
  artifact?: string
  version?: string
  advisoryId?: string
  fixedVersions?: string[]
  ai?: FindingAi
}

export interface SkippedFile {
  path: string
  reason: string
  line?: number
}

export interface UnresolvedItem {
  kind: string
  path: string
  line?: number
  reason: string
  subject?: string
}

export interface DismissedItem {
  rule: string
  path: string
  line?: number
  reason: string
}

export interface AnalyzerCoverage {
  status: CoverageStatus
  filesAnalyzed: number
  filesSkipped: SkippedFile[]
  rulesApplied: string[]
  unresolved: UnresolvedItem[]
  dismissed: DismissedItem[]
}

export interface ReportCoverage {
  /** Худший из статусов анализаторов. */
  status: CoverageStatus
  /** Ключ — id ноды анализатора в графе запуска (например "n4"), см. contracts/report-format.md. */
  byAnalyzer: Record<string, AnalyzerCoverage>
}

export type AiReportStatus = 'OK' | 'PARTIAL' | 'NOT_RECEIVED'

export interface AiValidatorStats {
  responses: number
  schemaFailures: number
  rejectedFindingRefs: number
  rejectedCves: number
  rejectedLocations?: number
  rejectedVersions?: number
  rejectedDisputes?: number
  retries?: number
  cacheHits?: number
}

/** Связанные находки — одна история риска (например, открытый маршрут + IDOR). */
export interface AiGroup {
  title: string
  findingIds: string[]
  story: string
}

export interface ReportAi {
  status: AiReportStatus
  provider?: string
  model?: string
  summary?: string
  /** id находок от самой срочной. */
  priorities?: string[]
  groups?: AiGroup[]
  validator?: AiValidatorStats
  reason?: string
}

export interface Report {
  runId: string
  workflowId?: string
  workflowVersion?: number
  inputHash: string
  rulesVersion: string
  coverage: ReportCoverage
  findings: Finding[]
  ai?: ReportAi
  /** Необязательный версионируемый блок проверки качества кода; в старых отчётах его нет. */
  quality?: unknown
}

// ───────────── Карта маршрутов ─────────────

/** Место в ответе ноды C8 (поле file, не path). */
export interface RouteArtifactLocation {
  file: string
  line: number
}

/** Правило Spring Security в ответе C8: access — имя метода без аргументов (permitAll, hasRole…). */
export interface RouteArtifactRule extends RouteArtifactLocation {
  access: string
  /** Выражение доступа целиком, с аргументами (hasRole("MECHANIC")) — есть в артефактах C8 после 21.11. */
  accessText?: string
  matcher: string
}

export interface RouteArtifactRow {
  /** Полное имя функции-обработчика. */
  function: string
  /** matched — сработавшее правило найдено; иное — доступ не установлен. */
  accessStatus: string
  method?: string
  path?: string
  location: RouteArtifactLocation
  rule?: RouteArtifactRule
  /** Следующие по порядку правила, которые тоже подходят к пути (включая anyRequest). */
  subsequentRules: RouteArtifactRule[]
  methodGuards: (RouteArtifactLocation & { name: string })[]
  tables: { name: string; ownerColumns: string[]; schemaKnown: boolean }[]
  /** unresolved — какие таблицы трогает обработчик, установить не удалось. */
  tableEvidence: 'located' | 'unresolved'
}

/** Ответ ноды output.route-map (C8), порт report. Экран переводит его в RouteMap (features/routes). */
export interface RouteMapArtifact {
  kind: 'route-map'
  status: CoverageStatus
  routes: RouteArtifactRow[]
  markdown?: string
}

// Модель экрана карты маршрутов.

/** Уровень доступа по правилу Spring Security: permitAll / authenticated / hasRole|hasAuthority / denyAll / не вычислено. */
export type RouteAccess = 'PUBLIC' | 'AUTHENTICATED' | 'ROLE' | 'DENY' | 'UNKNOWN'

/** Правило authorizeHttpRequests в порядке объявления (побеждает первое совпавшее). */
export interface SecurityRuleInfo {
  /** Порядок в цепочке, с 1. */
  order: number
  /** null — любой HTTP-метод. */
  method: string | null
  /** Пусто при anyRequest(). */
  patterns: string[]
  anyRequest: boolean
  access: RouteAccess
  /** Как в коде: permitAll(), hasRole("MECHANIC"). */
  accessText: string
  location: Location
}

export interface RouteParam {
  name: string
  source: 'PATH' | 'QUERY' | 'BODY' | 'HEADER' | 'PRINCIPAL'
  type?: string
}

/** Таблица, которую затрагивает обработчик (через свои методы проекта), и её колонки-владельцы. */
export interface RouteTable {
  name: string
  /** Колонки, которые читает или пишет запрос; undefined — не установлены. */
  columns?: string[]
  /** Колонки владельца у таблицы (customer_id, user_id, owner…) — из schema.sql, Flyway, Liquibase, @Entity. */
  ownerColumns: string[]
}

export interface RouteEntry {
  /** null — любой HTTP-метод. */
  method: string | null
  /** Полный путь с префиксом @RequestMapping класса. */
  path: string
  /** Класс.метод обработчика. */
  handler: string
  location: Location
  /** Итоговый доступ — по первому совпавшему правилу. */
  access: RouteAccess
  accessText: string
  /** order первого совпавшего правила; null — ни одно не совпало. */
  matchedRule: number | null
  /** Правила ниже, которые тоже подходят к пути, строже и не действуют — затенены. */
  shadowedRules: number[]
  /** Тексты @PreAuthorize / @Secured / @RolesAllowed у метода и класса. */
  methodSecurity: string[]
  /** Личность пользователя доступна в обработчике; undefined — не установлено. */
  principal?: boolean
  /** Параметры с источником; undefined — не установлены. */
  params?: RouteParam[]
  tables: RouteTable[]
  /** false — какие таблицы трогает обработчик, установить не удалось («неизвестное — не ноль»). */
  tablesResolved?: boolean
  /** id находок (route-authorization, object-authorization, sql-injection…) по этому маршруту. */
  findingIds: string[]
}

export interface RouteMap {
  routes: RouteEntry[]
  rules: SecurityRuleInfo[]
  /** Что не удалось установить: путь не вычислен, правило с неизвестным выражением и т. п. */
  unresolved: UnresolvedItem[]
}

// ───────────── Запуски ─────────────

export type RunSource = { kind: 'upload'; uploadId: string } | { kind: 'repo'; url: string }

export interface RunRequest {
  source?: RunSource
}

export interface RunStarted {
  runId: string
}

export interface DeliveryFailure {
  nodeId: string
  type: string
  error: string
}

export interface RunDelivery {
  status: 'NONE' | 'DELIVERED' | 'PARTIAL' | 'FAILED'
  delivered: string[]
  failed: DeliveryFailure[]
}

export interface RunSummary {
  runId: string
  workflowId: string
  workflowName?: string
  status: RunStatus
  /** null, пока запуск идёт и анализаторы ещё не отчитались. */
  coverageStatus: CoverageStatus | null
  counts: SeverityCounts
  trigger?: string
  repoUrl?: string | null
  /** Загруженный архив запуска: ZIP-проект перезапускается без новой загрузки. */
  uploadId?: string | null
  /** Исход доставки уведомлений; не влияет на status и coverageStatus. */
  delivery?: RunDelivery
  startedAt: string
  finishedAt: string | null
}

export interface SkipCause {
  reason: 'INACTIVE_BRANCH' | 'MISSING_INPUT' | 'UPSTREAM_FAILURE' | 'RUN_STOPPED'
  nodeIds: string[]
  edgeIds: string[]
}

export interface NodeRun {
  nodeId: string
  status: NodeStatus
  input?: unknown
  output?: unknown
  logs: string[]
  durationMs?: number
  error?: string
  startedAt?: string
  finishedAt?: string
  /** Только у анализаторов: что проверено и что нет («неизвестное — не ноль»). */
  coverage?: AnalyzerCoverage
  /** Версия набора правил анализатора — к ней привязан отчёт для CI. */
  rulesVersion?: string
  skipCause?: SkipCause
  failureContextNodeIds?: string[]
}

export interface Run extends RunSummary {
  workflowVersion: number
  nodeRuns: NodeRun[]
  /** null, если запуск не дошёл до отчёта. */
  report: Report | null
}

// События SSE /api/runs/{runId}/events
export interface NodeStatusEvent {
  nodeId: string
  status: NodeStatus
  startedAt?: string
  finishedAt?: string
  error?: string
  coverage?: AnalyzerCoverage
  skipCause?: SkipCause
  failureContextNodeIds?: string[]
}
export interface NodeIoEvent {
  nodeId: string
  input: unknown
  output: unknown
}
export interface RunStatusEvent {
  status: RunStatus
}
export interface LogEvent {
  nodeId: string
  message: string
}
export interface NodeProgressEvent {
  nodeId: string
  percent: number
  note?: string | null
}

export type RunEvent =
  | { type: 'node.status'; data: NodeStatusEvent }
  | { type: 'node.io'; data: NodeIoEvent }
  | { type: 'node.progress'; data: NodeProgressEvent }
  | { type: 'run.status'; data: RunStatusEvent }
  | { type: 'log'; data: LogEvent }

export interface UploadResult {
  uploadId: string
}

// ───────────── CI ─────────────

export type CiKind = 'github' | 'gitlab'

export interface CiRunResult {
  runId: string
  status: RunStatus
  coverageStatus: CoverageStatus | null
  counts: SeverityCounts
  /** Решение сервера. false при critical или при PARTIAL/FAILED (fail-closed). */
  pass: boolean
  reason: string
}

// ───────────── Шаблоны ─────────────

export interface TemplateSummary {
  id: string
  name: string
  description: string
  tags: string[]
  nodeCount: number
  author: string
}

export interface Template extends TemplateSummary {
  workflow: WorkflowDraft
}

export interface PublishTemplateRequest {
  workflowId: string
  name: string
  description: string
}

// ───────────── Настройки ─────────────

export type LlmProvider = 'openai-compatible' | 'groq' | 'openrouter' | 'ollama' | 'vllm'

export interface LlmSettings {
  provider: LlmProvider
  baseUrl: string
  model: string
  /** Ключ сервер не отдаёт — только факт, что он задан. */
  apiKeySet: boolean
}

export interface LlmSettingsUpdate {
  provider: LlmProvider
  baseUrl: string
  model: string
  /** Не передавать, чтобы оставить прежний ключ. */
  apiKey?: string
}

// ───────────── Сравнение запусков ─────────────

export interface CompareSide {
  runId: string
  status: RunStatus
  coverageStatus?: string | null
  kind?: string | null
  repoUrl?: string | null
  commitSha?: string | null
  inputHash?: string | null
  subdir: string
  rulesVersion?: string | null
  workflowId: string
  workflowVersion: number
  startedAt: string
}

export interface CompareResult {
  base: CompareSide
  head: CompareSide
  comparable: boolean
  reasons: string[]
  /** Справочные замечания (например, «другая версия архива»), не блокируют сравнение. */
  notes?: string[]
  fixConfirmed: boolean
  added: Finding[]
  unchanged: Finding[]
  resolved: Finding[]
}

export const TELEGRAM_CHAT_LIST_MAX_LENGTH = 4096
export const TELEGRAM_ATTACHMENTS = ['pdf', 'md', 'html', 'json', 'sarif'] as const
export type TelegramAttachmentFormat = typeof TELEGRAM_ATTACHMENTS[number]

export interface TelegramSettings {
  token: string
  tokenSaved: boolean
  chatId: string
  attachments: TelegramAttachmentFormat[]
}

export interface TelegramSettingsUpdate {
  token?: string
  chatId: string
  attachments: TelegramAttachmentFormat[]
}
