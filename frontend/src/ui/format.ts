import type { CoverageStatus, NodeStatus, RunStatus, Severity } from '../api/types'
import { t } from '../i18n'

/** 2026-11-21T09:30:00Z → «21.11 12:30» (локальное время). */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** Длительность между двумя ISO-датами: «37 с», «2 мин 5 с». */
export function formatDuration(fromIso: string | null | undefined, toIso: string | null | undefined): string {
  if (!fromIso || !toIso) return '—'
  const s = Math.max(0, Math.round((new Date(toIso).getTime() - new Date(fromIso).getTime()) / 1000))
  return s < 60 ? t('dur.s', { n: s }) : t('dur.ms', { m: Math.floor(s / 60), s: s % 60 })
}

/** Место находки: «path:13» или «path:13–14». */
export function formatLocation(path: string, line?: number, endLine?: number): string {
  if (!line) return path
  return endLine && endLine !== line ? `${path}:${line}–${endLine}` : `${path}:${line}`
}

/** Подписи берутся из i18n в момент обращения, поэтому следуют за выбранным языком. */
export const SEVERITY_LABEL = {
  get CRITICAL() { return t('sev.CRITICAL') },
  get HIGH() { return t('sev.HIGH') },
  get MEDIUM() { return t('sev.MEDIUM') },
  get LOW() { return t('sev.LOW') },
} as Record<Severity, string>

export const STATUS_LABEL = {
  get PENDING() { return t('st.PENDING') },
  get RUNNING() { return t('st.RUNNING') },
  get SUCCESS() { return t('st.SUCCESS') },
  get PARTIAL() { return t('st.PARTIAL') },
  get FAILED() { return t('st.FAILED') },
  get SKIPPED() { return t('st.SKIPPED') },
  get COMPLETE() { return t('st.COMPLETE') },
} as Record<NodeStatus | RunStatus | CoverageStatus, string>
