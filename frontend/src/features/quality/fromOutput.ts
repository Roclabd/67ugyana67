import { t } from '../../i18n'
/**
 * Проверка качества кода (нода analyzer.quality) → модель экрана. Блок `quality` версионируется; старые отчёты его не содержат.
 * Незнакомая версия или битые данные не роняют экран: такой блок просто не показывается.
 */
export type QualityKind = 'syntax' | 'type-mismatch' | 'unresolved-reference' | 'functional-defect'
export type QualityStatus = 'OK' | 'ISSUES' | 'PARTIAL' | 'TIMEOUT' | 'NOT_APPLICABLE' | 'ERROR'

export interface QualityDiagnostic {
  kind: QualityKind
  rule: string
  language: string
  path: string
  line: number
  column?: number
  message: string
  confidence: 'PROVEN' | 'LIKELY'
}

export interface QualityBlock {
  version: number
  status: QualityStatus
  message: string
  durationMs?: number
  filesAnalyzed: number
  filesByLanguage: Record<string, number>
  truncated: boolean
  diagnostics: QualityDiagnostic[]
  skipped: { path: string; reason: string }[]
  unsupported: string[]
  summary: { total: number; byKind: Record<string, number> }
}

export const KIND_LABEL: Record<QualityKind, string> = {
  get syntax() { return t('q.kind.syntax') },
  get 'type-mismatch'() { return t('q.kind.type-mismatch') },
  get 'unresolved-reference'() { return t('q.kind.unresolved-reference') },
  get 'functional-defect'() { return t('q.kind.functional-defect') },
}

export const STATUS_LABEL: Record<QualityStatus, string> = {
  get OK() { return t('q.status.OK') },
  get ISSUES() { return t('q.status.ISSUES') },
  get PARTIAL() { return t('q.status.PARTIAL') },
  get TIMEOUT() { return t('q.status.TIMEOUT') },
  get NOT_APPLICABLE() { return t('q.status.NOT_APPLICABLE') },
  get ERROR() { return t('q.status.ERROR') },
}

const STATUSES = Object.keys(STATUS_LABEL)
const KINDS = Object.keys(KIND_LABEL)

export function qualityFromValue(value: unknown): QualityBlock | null {
  if (typeof value !== 'object' || value === null) return null
  const v = value as Record<string, unknown>
  if (v.version !== 1 || typeof v.status !== 'string' || !STATUSES.includes(v.status) || !Array.isArray(v.diagnostics)) return null
  const diagnostics = v.diagnostics.filter((d): d is QualityDiagnostic => {
    const x = d as Partial<QualityDiagnostic> | null
    return !!x && typeof x.path === 'string' && typeof x.line === 'number' && typeof x.message === 'string' && typeof x.kind === 'string' && KINDS.includes(x.kind)
  })
  const summary = (v.summary ?? {}) as { total?: number; byKind?: Record<string, number> }
  return {
    version: 1,
    status: v.status as QualityStatus,
    message: typeof v.message === 'string' ? v.message : '',
    durationMs: typeof v.durationMs === 'number' ? v.durationMs : undefined,
    filesAnalyzed: typeof v.filesAnalyzed === 'number' ? v.filesAnalyzed : 0,
    filesByLanguage: (v.filesByLanguage ?? {}) as Record<string, number>,
    truncated: v.truncated === true,
    diagnostics,
    skipped: Array.isArray(v.skipped) ? (v.skipped as { path: string; reason: string }[]) : [],
    unsupported: Array.isArray(v.unsupported) ? (v.unsupported as string[]) : [],
    summary: { total: summary.total ?? diagnostics.length, byKind: summary.byKind ?? {} },
  }
}

/** Выход ноды: {quality: {...}}. */
export function qualityFromOutput(output: unknown): QualityBlock | null {
  if (typeof output !== 'object' || output === null) return null
  return qualityFromValue((output as { quality?: unknown }).quality)
}
